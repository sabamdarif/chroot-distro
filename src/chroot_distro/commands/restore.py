import contextlib
import os
import shutil
import stat
import sys
import tarfile
import typing

import chroot_distro.helpers.mount_manager as mount_manager
from chroot_distro.commands.help import HELP_COMMANDS
from chroot_distro.constants import CONTAINERS_DIR
from chroot_distro.locking import (
    ContainerLock,
    container_lock_path,
    read_lock_info,
)
from chroot_distro.message import (
    C,
    crit_error,
    log_error,
    log_info,
    msg,
)
from chroot_distro.names import is_valid_name
from chroot_distro.paths import (
    container_dir,
    container_manifest,
    container_rootfs,
)
from chroot_distro.progress import (
    ByteCounter,
    clear_bar,
    draw_bytes_bar,
    progress_active,
)

_MAGIC_COMPRESS = (
    (b'\x1f\x8b',      'gz'),   # gzip
    (b'BZh',           'bz2'),  # bzip2
    (b'\xfd7zXZ\x00',  'xz'),   # xz
    (b'\x5d\x00',      'xz'),   # lzma legacy
)

_LEGACY_PREFIX = "installed-rootfs"


def _detect_compression(header: bytes) -> str:
    """Return the tarfile mode suffix inferred from *header* magic bytes."""
    for magic, mode in _MAGIC_COMPRESS:
        if header.startswith(magic):
            return mode
    return ''


def _clear_existing_rootfs(container_name: str) -> None:
    """Remove the destination rootfs before extracting a new copy."""
    rootfs_dir = container_rootfs(container_name)
    if not os.path.isdir(rootfs_dir):
        return

    # Mount safety check: ensure no active mounts exist under rootfs
    try:
        mount_manager.ensure_no_mounts(rootfs_dir)
    except Exception as e:
        crit_error(f"Failed mount safety check for container '{container_name}': {e}")
        sys.exit(1)

    pfx = f"{C['BLUE']}[{C['GREEN']}*{C['BLUE']}] {C['CYAN']}"
    count = 0
    clear_bar()
    for dp, dns, fns in os.walk(rootfs_dir, topdown=False, followlinks=False):
        for fname in fns:
            with contextlib.suppress(OSError):
                os.unlink(os.path.join(dp, fname))
            count += 1
            if progress_active():
                sys.stderr.write(
                    f"\r{pfx}Removing old rootfs... {count} files{C['RST']}"
                )
                sys.stderr.flush()
        for dname in dns:
            with contextlib.suppress(OSError):
                os.rmdir(os.path.join(dp, dname))
    shutil.rmtree(rootfs_dir, ignore_errors=True)
    clear_bar()


def _remove_existing(dest: str, member: tarfile.TarInfo) -> None:
    """Remove any existing filesystem entry at *dest* before extraction."""
    try:
        if os.path.islink(dest) or os.path.isfile(dest):
            os.remove(dest)
        elif os.path.isdir(dest) and not member.isdir():
            shutil.rmtree(dest)
    except OSError:
        pass


_SKIP = (None, None)


def _dest_path(member_name: str) -> tuple:
    """Map a TAR member name to (container_name, dest_path_in_containers)."""
    name = member_name.lstrip("/")
    if not name or name == ".":
        return _SKIP

    parts = name.split("/")

    if any(p in ("..", ".", "") for p in parts):
        return _SKIP

    if len(parts) == 1 and not name.endswith("/"):
        return _SKIP

    # Legacy format: installed-rootfs/<name>/...  ->  containers/<name>/rootfs/...
    if parts[0] == _LEGACY_PREFIX:
        if len(parts) < 2:
            return _SKIP
        container_name = parts[1]
        if not is_valid_name(container_name):
            return _SKIP
        rest = parts[2:]
        if not rest:
            return (container_name, container_rootfs(container_name))
        return (container_name, os.path.join(container_rootfs(container_name), *rest))

    # New format: <name>/...
    container_name = parts[0]
    if not is_valid_name(container_name):
        return _SKIP

    if len(parts) == 1:
        return (container_name, container_dir(container_name))

    sub = parts[1]
    rest = parts[2:]

    if sub == "manifest.json" and not rest:
        return (container_name, container_manifest(container_name))

    if sub == "rootfs":
        if not rest:
            return (container_name, container_rootfs(container_name))
        return (container_name, os.path.join(container_rootfs(container_name), *rest))

    return (container_name, os.path.join(container_rootfs(container_name), *parts[1:]))


def command_restore(args) -> None:
    """Reinstate one or more containers from a tar backup."""
    archive = getattr(args, "archive", None)
    verbose = getattr(args, "verbose", False)

    if archive:
        if not os.path.exists(archive):
            crit_error(f"file '{archive}' does not exist.")
            sys.exit(1)
        if os.path.isdir(archive):
            crit_error(f"path '{archive}' is a directory.")
            sys.exit(1)
        if not os.access(archive, os.R_OK):
            crit_error(f"file '{archive}' is not readable.")
            sys.exit(1)
    else:
        if sys.stdin.isatty():
            msg()
            crit_error("archive file path is not specified and nothing is being piped via stdin.")
            HELP_COMMANDS["restore"]()
            sys.exit(1)

    os.makedirs(CONTAINERS_DIR, exist_ok=True)

    log_info("Restoring container from the backup...")

    done_size = 0
    total_size = 0
    counter: ByteCounter | None = None
    cleared: set[str] = set()

    def _on_entry(member_size: int, member_name: str) -> None:
        nonlocal done_size
        done_size += member_size
        if verbose:
            log_info(f"Extracting: '{member_name}'")
        if counter is not None and total_size:
            draw_bytes_bar(counter.count, total_size)
        else:
            draw_bytes_bar(done_size, 0, noun="extracted")

    def _check_bare_root(member_name: str) -> bool:
        name = member_name.lstrip('/')
        if not name:
            return False
        parts = name.split('/')
        return len(parts) == 1 and not name.endswith('/')

    raw_fh = None
    pending_locks: dict[str, ContainerLock] = {}
    deferred_dir_modes: list[tuple[str, int]] = []
    try:
        if archive:
            total_size = os.path.getsize(archive)
            raw_fh = open(archive, 'rb')  # noqa: SIM115
            counter = ByteCounter(raw_fh)
            tf_fileobj: typing.Any = counter
            tf_mode = 'r|*'
        else:
            import io
            buf = sys.stdin.buffer
            header = buf.peek(6)[:6] if isinstance(buf, io.BufferedReader) else b''
            comp = _detect_compression(header)
            tf_fileobj = sys.stdin.buffer
            tf_mode = f'r|{comp}'

        with tarfile.open(fileobj=tf_fileobj, mode=tf_mode) as tf:  # type: ignore[call-overload]
            for member in tf:
                if member.isblk() or member.ischr() or member.isfifo():
                    continue

                if _check_bare_root(member.name):
                    clear_bar()
                    log_error("Cannot restore: provided file has invalid structure.")
                    sys.exit(1)

                container_name, dest = _dest_path(member.name)
                if container_name is None:
                    continue

                if container_name not in pending_locks:
                    lock = ContainerLock(
                        container_name, exclusive=True, command="restore"
                    )
                    if not lock.acquire():
                        hint = read_lock_info(container_lock_path(container_name))
                        clear_bar()
                        log_error(f"Cannot restore: container '{container_name}' is busy{hint}.")
                        sys.exit(1)
                    pending_locks[container_name] = lock

                if container_name not in cleared:
                    _clear_existing_rootfs(container_name)
                    cleared.add(container_name)

                _remove_existing(dest, member)

                if member.isdir():
                    os.makedirs(dest, exist_ok=True)
                    mode = stat.S_IMODE(member.mode)
                    if (mode & stat.S_IRWXU) != stat.S_IRWXU:
                        with contextlib.suppress(OSError):
                            os.chmod(dest, mode | stat.S_IRWXU)
                        deferred_dir_modes.append((dest, mode))
                    else:
                        with contextlib.suppress(OSError):
                            os.chmod(dest, mode)

                elif member.issym():
                    parent = os.path.dirname(dest)
                    if parent:
                        os.makedirs(parent, exist_ok=True)
                    os.symlink(member.linkname, dest)

                elif member.islnk():
                    _, link_src = _dest_path(member.linkname)
                    if link_src is None:
                        continue
                    parent = os.path.dirname(dest)
                    if parent:
                        os.makedirs(parent, exist_ok=True)
                    try:
                        shutil.copy2(link_src, dest)
                        if member.mode:
                            with contextlib.suppress(OSError):
                                os.chmod(dest, stat.S_IMODE(member.mode))
                    except OSError:
                        pass

                elif member.isreg():
                    fobj = tf.extractfile(member)
                    if fobj is None:
                        continue
                    parent = os.path.dirname(dest)
                    if parent:
                        os.makedirs(parent, exist_ok=True)
                    try:
                        with open(dest, 'wb') as out:
                            while True:
                                chunk = fobj.read(1 << 17)
                                if not chunk:
                                    break
                                out.write(chunk)
                        with contextlib.suppress(OSError):
                            os.chmod(dest, stat.S_IMODE(member.mode))
                    except OSError:
                        pass
                    finally:
                        fobj.close()
                else:
                    continue

                _on_entry(member.size, member.name)

        for path, mode in reversed(deferred_dir_modes):
            with contextlib.suppress(OSError):
                os.chmod(path, mode)

        clear_bar()
        log_info("Finished restoring the container.")

    except KeyboardInterrupt:
        clear_bar()
        log_error("Aborted by user.")
        sys.exit(1)
    except (EOFError, OSError, tarfile.TarError) as exc:
        clear_bar()
        log_error(f"Failed to restore container: {exc}")
        sys.exit(1)
    finally:
        if raw_fh is not None:
            raw_fh.close()
        for lock in pending_locks.values():
            lock.release()

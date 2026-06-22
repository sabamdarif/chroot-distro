from __future__ import annotations

import contextlib
import logging
import os
import re
import shutil
import subprocess
from typing import TYPE_CHECKING

from chroot_distro.constants import IS_TERMUX, TERMUX_PREFIX
from chroot_distro.exceptions import MountError
from chroot_distro.message import warn

if TYPE_CHECKING:
    from chroot_distro.helpers.namespace import NamespaceHolder

log = logging.getLogger(__name__)


def _resolve_mount() -> str:
    if IS_TERMUX:
        termux_mount = os.path.join(TERMUX_PREFIX, "bin", "mount")
        if os.path.isfile(termux_mount):
            return termux_mount
    resolved = shutil.which("mount")
    if not resolved:
        raise MountError(
            "Required executable 'mount' not found on the system. Please install mount-utils or ensure it is in your PATH."
        )
    return resolved


def _resolve_umount() -> str:
    if IS_TERMUX:
        termux_umount = os.path.join(TERMUX_PREFIX, "bin", "umount")
        if os.path.isfile(termux_umount):
            return termux_umount
    resolved = shutil.which("umount")
    if not resolved:
        raise MountError(
            "Required executable 'umount' not found on the system. Please install mount-utils or ensure it is in your PATH."
        )
    return resolved


def decode_mount_path(path: str) -> str:
    """Decode octal escape sequences (like \\040 for space) in /proc/mounts paths."""
    return re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), path)


def _mounts_under_rootfs_from_lines(lines: list[str], rootfs: str) -> list[str]:
    rootfs_abs = os.path.realpath(rootfs)
    active_mounts: list[str] = []
    for line in lines:
        parts = line.strip().split()
        if len(parts) < 2:
            continue
        mount_point = decode_mount_path(parts[1])
        try:
            mount_point_abs = os.path.realpath(mount_point)
        except OSError:
            continue
        if mount_point_abs == rootfs_abs or mount_point_abs.startswith(rootfs_abs + os.sep):
            active_mounts.append(mount_point_abs)
    active_mounts.sort(key=lambda p: len(p.split(os.sep)), reverse=True)
    return active_mounts


def _read_proc_mounts_lines(holder: NamespaceHolder | None) -> list[str]:
    if holder is not None:
        text = holder.get_proc_mounts()
        return text.splitlines() if text else []
    if not os.path.exists("/proc/mounts"):
        return []
    try:
        with open("/proc/mounts") as f:
            return f.readlines()
    except OSError as e:
        raise MountError(f"Failed to read /proc/mounts: {e}") from e


def get_active_mounts(rootfs: str, holder: NamespaceHolder | None = None) -> list[str]:
    """Parse /proc/mounts and return mount points under rootfs (deepest first)."""
    lines = _read_proc_mounts_lines(holder)
    return _mounts_under_rootfs_from_lines(lines, rootfs)


def is_mounted(target: str, holder: NamespaceHolder | None = None) -> bool:
    """Check if a specific path is currently a mount point."""
    if holder is not None:
        return holder.is_mounted(target)

    target_abs = os.path.realpath(target)
    if not os.path.exists("/proc/mounts"):
        return False

    try:
        with open("/proc/mounts") as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) < 2:
                    continue
                mount_point = decode_mount_path(parts[1])
                if os.path.realpath(mount_point) == target_abs:
                    return True
    except OSError:
        pass
    return False


def _run_mount_cmd(cmd: list[str], holder: NamespaceHolder | None) -> subprocess.CompletedProcess:
    if holder is not None:
        return holder.run(cmd, capture_output=True, text=True)
    return subprocess.run(cmd, capture_output=True, text=True, check=False)


# Mount options accepted in a --bind spec that are not kernel mount(2)
# options and must not be passed to `mount -o`. `z`/`Z` are Docker/Podman
# SELinux relabel hints; a plain chroot has no label context to apply them,
# so they are silently dropped (with a debug note).
_NON_KERNEL_BIND_OPTIONS = frozenset({"z", "Z"})


def _filter_bind_options(options: str) -> str:
    """Return *options* with non-kernel relabel flags (z/Z) removed."""
    kept: list[str] = []
    for raw_opt in options.split(","):
        opt = raw_opt.strip()
        if not opt:
            continue
        if opt in _NON_KERNEL_BIND_OPTIONS:
            log.debug("Ignoring SELinux relabel bind option '%s' (no label context in chroot)", opt)
            continue
        kept.append(opt)
    return ",".join(kept)


def safe_mount(
    source: str,
    target: str,
    holder: NamespaceHolder | None = None,
    recursive: bool = False,
    options: str = "",
) -> None:
    """Safely mount source to target using bind mount.

    Creates target directory or file if they do not exist.

    When *options* is given (e.g. ``"ro"`` or ``"ro,nosuid"``), a second
    ``mount -o remount,bind,<options>`` is issued after the initial bind:
    the kernel ignores per-mount flags like ``ro`` on the first bind, so a
    remount is required to actually apply them (matches util-linux).
    """
    source_abs = os.path.realpath(source)
    if not os.path.exists(source_abs):
        raise MountError(f"Mount source does not exist: {source}")

    source_is_dir = os.path.isdir(source_abs)

    # Never bind a zero-byte regular file: doing so would create (or shadow)
    # an empty target that masks a real library inside the rootfs, which
    # makes ldconfig report "File ... is empty, not checked" on every
    # package install. A genuine library is never zero bytes, so an empty
    # source is always a broken/placeholder bind we must skip.
    if not source_is_dir and os.path.isfile(source_abs):
        try:
            if os.path.getsize(source_abs) == 0:
                log.debug("Skipping bind of zero-byte source %s -> %s", source, target)
                return
        except OSError:
            pass

    # Track whether we create an empty stub target so we can remove it if the
    # bind fails (otherwise the empty stub shadows a real rootfs file).
    created_stub = False
    if source_is_dir:
        os.makedirs(target, exist_ok=True)
    else:
        os.makedirs(os.path.dirname(target), exist_ok=True)
        if not os.path.exists(target):
            open(target, "a").close()
            created_stub = True

    if is_mounted(target, holder=holder):
        return

    try:
        cmd = [_resolve_mount(), "--rbind" if recursive else "--bind", source_abs, target]
        result = _run_mount_cmd(cmd, holder)
        if result.returncode != 0:
            raise subprocess.CalledProcessError(
                result.returncode,
                result.args,
                result.stdout,
                result.stderr,
            )
    except subprocess.CalledProcessError as e:
        if created_stub:
            # Remove the empty stub we created so it does not shadow a real
            # file (e.g. the container's own libGL.so) when the bind fails.
            with contextlib.suppress(OSError):
                os.remove(target)
        stderr = (e.stderr or "").strip() if hasattr(e, "stderr") else ""
        raise MountError(f"Failed to mount {source} to {target}: {stderr}") from e

    kernel_options = _filter_bind_options(options)
    if not kernel_options:
        return

    remount_flags = "remount,bind"
    if recursive:
        remount_flags = "remount,rbind"
    try:
        remount_cmd = [_resolve_mount(), "-o", f"{remount_flags},{kernel_options}", target]
        result = _run_mount_cmd(remount_cmd, holder)
        if result.returncode != 0:
            raise subprocess.CalledProcessError(
                result.returncode,
                result.args,
                result.stdout,
                result.stderr,
            )
    except subprocess.CalledProcessError as e:
        stderr = (e.stderr or "").strip() if hasattr(e, "stderr") else ""
        raise MountError(f"Failed to apply mount options '{kernel_options}' to {target}: {stderr}") from e


def create_dev_nodes(
    rootfs: str,
    nodes,
    holder: NamespaceHolder | None = None,
) -> None:
    """Create minimal character device nodes inside the rootfs ``/dev``.

    *nodes* is an iterable of ``(name, major, minor, mode)`` tuples. Used for
    the fresh tmpfs ``/dev`` mounted under maximum isolation, where the host
    ``/dev`` is intentionally not bind-mounted. mknod is run inside the
    holder's mount namespace (when given) so the nodes land on the new tmpfs;
    failures are non-fatal and logged at debug level. ``/dev/ptmx``,
    ``/dev/console`` and the ``std*`` symlinks are provided by the devpts
    overmount and the login pty wrapper, so they are not created here.
    """
    dev_dir = os.path.join(rootfs, "dev")
    for name, major, minor, mode in nodes:
        guest_path = f"/dev/{name}"
        host_path = os.path.join(dev_dir, name)
        if holder is not None:
            cmd = ["mknod", "-m", format(mode, "o"), guest_path, "c", str(major), str(minor)]
            try:
                result = holder.run(cmd, capture_output=True, text=True)
                if result.returncode != 0:
                    log.debug("mknod %s failed: %s", guest_path, (result.stderr or "").strip())
            except OSError as exc:
                log.debug("mknod %s raised: %s", guest_path, exc)
            continue
        # No holder (no mount namespace): create directly on the host path.
        try:
            if os.path.exists(host_path):
                continue
            os.mknod(host_path, mode | 0o020000, os.makedev(major, minor))  # S_IFCHR
            os.chmod(host_path, mode)
        except OSError as exc:
            log.debug("os.mknod %s failed: %s", host_path, exc)


def make_rslave(target: str, holder: NamespaceHolder | None = None) -> bool:
    """Set recursive slave mount propagation on *target*.

    This ensures that new mounts on the host (e.g. sockets created in
    /run/user/<uid> after the bind mount) propagate into the chroot,
    matching distrobox's ``--volume /run:/run:rslave`` behaviour.

    Returns True on success, False on failure (non-fatal).
    """
    target_abs = os.path.realpath(target)
    if not is_mounted(target_abs, holder=holder):
        return False
    try:
        result = _run_mount_cmd([_resolve_mount(), "--make-rslave", target_abs], holder)
        if result.returncode != 0:
            log.debug(
                "make-rslave failed for %s: %s",
                target_abs,
                (result.stderr or "").strip(),
            )
            return False
    except Exception:
        log.debug("make-rslave exception for %s", target_abs, exc_info=True)
        return False
    log.debug("Set rslave propagation on %s", target_abs)
    return True


# Recursive bind targets (/dev, /run and friends) frequently report
# "target is busy" on logout because nested submounts or short-lived handles
# linger. This is benign: the lazy umount below always succeeds. Suppress the
# alarming warning for these and clean up quietly.
_RECURSIVE_BIND_BASENAMES = frozenset({"dev", "run", "proc", "sys"})


def _is_recursive_bind_target(target: str) -> bool:
    base = os.path.basename(os.path.realpath(target).rstrip(os.sep))
    return base in _RECURSIVE_BIND_BASENAMES


def safe_unmount(target: str, holder: NamespaceHolder | None = None) -> None:
    """Safely unmount a target path.

    Falls back to lazy unmount if normal unmount fails. For recursive bind
    targets the "target is busy" fallback is expected, so it is logged at
    debug level instead of warning the user.
    """
    if not is_mounted(target, holder=holder):
        return

    try:
        result = _run_mount_cmd([_resolve_umount(), target], holder)
        if result.returncode != 0:
            raise subprocess.CalledProcessError(
                result.returncode,
                result.args,
                result.stdout,
                result.stderr,
            )
    except subprocess.CalledProcessError as e:
        stderr = (e.stderr or "").strip() if hasattr(e, "stderr") else ""
        # "not mounted" means the mount is already gone (e.g. it was
        # shadowed by a parent bind mount and became unreachable). Treat
        # it as a successful unmount rather than escalating to lazy/error.
        if "not mounted" in stderr:
            log.debug("umount reports '%s' is not mounted; treating as already unmounted.", target)
            return
        if _is_recursive_bind_target(target):
            log.debug("Standard umount failed for %s (%s); using lazy umount.", target, stderr)
        else:
            warn(f"Standard umount failed for {target} ({stderr}). Trying lazy umount...")
        try:
            result = _run_mount_cmd([_resolve_umount(), "-l", target], holder)
            if result.returncode != 0:
                raise subprocess.CalledProcessError(
                    result.returncode,
                    result.args,
                    result.stdout,
                    result.stderr,
                )
        except subprocess.CalledProcessError as e_lazy:
            lazy_stderr = (e_lazy.stderr or "").strip() if hasattr(e_lazy, "stderr") else ""
            if "not mounted" in lazy_stderr:
                log.debug("Lazy umount reports '%s' is not mounted; treating as already unmounted.", target)
                return
            raise MountError(f"Failed to unmount {target} (lazy umount also failed): {lazy_stderr}") from e_lazy


def unmount_all(rootfs: str, holder: NamespaceHolder | None = None) -> None:
    """Unmount all active mount points nested under rootfs in correct order."""
    mounts = get_active_mounts(rootfs, holder=holder)
    for m in mounts:
        safe_unmount(m, holder=holder)


def ensure_no_mounts(rootfs: str, holder: NamespaceHolder | None = None) -> None:
    """Verify that no mount points exist under rootfs.

    Attempts to clean up if some are found. Raises MountError if any remain.
    """
    mounts = get_active_mounts(rootfs, holder=holder)
    if not mounts:
        return

    warn(f"Active mounts found under rootfs: {mounts}. Attempting automatic unmount...")
    with contextlib.suppress(MountError):
        unmount_all(rootfs, holder=holder)

    remaining = get_active_mounts(rootfs, holder=holder)
    if remaining:
        raise MountError(
            f"Safety check failed: Active mount points remain under {rootfs}: {remaining}. "
            "Refusing to delete or modify files in this directory to prevent host filesystem data loss."
        )


def _fs_supported(fstype: str) -> bool:
    """Return True if the kernel reports support for the given filesystem type."""
    try:
        with open("/proc/filesystems") as f:
            return fstype in f.read()
    except OSError:
        return False


def apply_special_mount(rootfs: str, sm, holder: NamespaceHolder | None = None) -> bool:
    """Execute a single SpecialMount inside rootfs.

    Returns True on success, False on failure (when optional=True).
    Raises RuntimeError on failure when optional=False.
    """
    if sm.check and not _fs_supported(sm.check):
        log.debug(f"Skipping {sm.fstype} mount: '{sm.check}' not in /proc/filesystems")
        return False

    target = os.path.join(rootfs, sm.target.lstrip("/"))

    if sm.mkdir:
        # When a holder is present the target may live on a tmpfs that only
        # exists inside the holder's mount namespace (e.g. the fresh /dev
        # under maximum isolation). Creating it from the parent process would
        # write to the underlying directory the namespace cannot see, so the
        # subsequent mount fails with "mount point does not exist". Create the
        # directory inside the holder's mount namespace instead.
        if holder is not None:
            mk = holder.run(["mkdir", "-p", target], capture_output=True, text=True)
            if mk.returncode != 0:
                msg = f"Failed to create mount target directory {target}: {(mk.stderr or '').strip()}"
                if sm.optional:
                    log.debug(msg)
                    return False
                raise RuntimeError(msg)
        else:
            try:
                os.makedirs(target, exist_ok=True)
            except OSError as e:
                msg = f"Failed to create mount target directory {target}: {e}"
                if sm.optional:
                    log.debug(msg)
                    return False
                raise RuntimeError(msg) from e
    elif not os.path.exists(target):
        # With a holder, existence must also be checked inside its namespace.
        if holder is not None:
            chk = holder.run(["test", "-e", target], capture_output=True, text=True)
            if chk.returncode != 0:
                log.debug(f"Mount target {target} does not exist in holder NS and mkdir=False, skipping")
                return False
        else:
            log.debug(f"Mount target {target} does not exist and mkdir=False, skipping")
            return False

    if is_mounted(target, holder=holder):
        return True

    # Build the list of option strings to try, simplest-last. Android's toybox
    # `mount` and SELinux frequently reject tmpfs option strings (e.g. size=)
    # with a non-zero exit and no stderr, so progressively strip options and,
    # for tmpfs, finally try with none at all.
    option_attempts: list[str] = []
    if sm.options:
        option_attempts.append(sm.options)
        # Drop size= (a common toybox/SELinux reject) but keep mode=.
        reduced = ",".join(o for o in sm.options.split(",") if not o.strip().startswith("size="))
        if reduced and reduced != sm.options:
            option_attempts.append(reduced)
    if sm.fstype == "tmpfs":
        option_attempts.append("")  # last resort: a bare tmpfs
    if not option_attempts:
        option_attempts.append("")

    last_err = ""
    last_code = 0
    last_cmd: list[str] = []
    for opts in option_attempts:
        cmd = [_resolve_mount(), "-t", sm.fstype]
        if opts:
            cmd += ["-o", opts]
        cmd += [sm.source, target]
        last_cmd = cmd
        try:
            if holder is not None:
                result = holder.run(cmd, capture_output=True, text=True, timeout=15)
            else:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=15, check=False)
        except subprocess.TimeoutExpired as exc:
            msg = f"mount timeout for {sm.fstype} at {target}"
            if sm.optional:
                log.debug(msg)
                return False
            raise RuntimeError(msg) from exc

        if result.returncode == 0:
            log.debug("Mounted %s at %s (options=%r)", sm.fstype, sm.target, opts)
            return True
        last_code = result.returncode
        last_err = ((result.stderr or "").strip() or (result.stdout or "").strip())
        log.debug("mount -t %s opts=%r failed (rc=%s): %s", sm.fstype, opts, last_code, last_err)

    detail = last_err or "(no error output)"
    msg = f"mount -t {sm.fstype} at {target} failed (exit {last_code}): {detail}; cmd: {' '.join(last_cmd)}"
    if sm.optional:
        log.debug(msg)
        return False
    raise RuntimeError(msg)

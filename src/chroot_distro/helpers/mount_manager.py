from __future__ import annotations

import contextlib
import errno
import functools
import logging
import os
import re
import stat
from typing import TYPE_CHECKING

from chroot_distro.exceptions import MountError
from chroot_distro.message import warn
from chroot_distro.syscalls._constants import MS_PRIVATE, MS_REC, MS_SLAVE
from chroot_distro.syscalls.mount import bind_mount, mount_filesystem, set_propagation
from chroot_distro.syscalls.umount import native_umount

if TYPE_CHECKING:
    from chroot_distro.helpers.namespace import NamespaceHolder

log = logging.getLogger(__name__)


def decode_mount_path(path: str) -> str:
    """Decode octal escape sequences (like \\040 for space) in /proc/mounts paths."""
    return re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), path)


def _mounts_under_rootfs_from_lines(lines: list[str], rootfs: str) -> list[str]:
    rootfs_abs = os.path.realpath(rootfs)
    # Kernel mount paths are canonical, so cheap prefix checks avoid a
    # realpath per line (Android tables have hundreds of entries).
    prefixes = {os.path.normpath(rootfs), rootfs_abs}
    active_mounts: list[str] = []
    for line in lines:
        parts = line.strip().split()
        if len(parts) < 2:
            continue
        mount_point = decode_mount_path(parts[1])
        if not any(mount_point == p or mount_point.startswith(p + os.sep) for p in prefixes):
            continue
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
    try:
        lines = _read_proc_mounts_lines(holder)
    except MountError as exc:
        log.warning("Failed to check if %s is mounted: %s", target, exc)
        return False

    # Kernel mount paths are canonical; realpath the target once, not per line.
    target_abs = os.path.realpath(target)
    for line in lines:
        parts = line.strip().split()
        if len(parts) < 2:
            continue
        if decode_mount_path(parts[1]) == target_abs:
            return True
    return False


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
    required_child: str = "",
) -> None:
    """Safely mount source to target using bind mount.

    Creates target directory or file if they do not exist.

    When *required_child* is given (e.g. ``"ptmx"`` for the /dev bind), an
    already-mounted target is only trusted if that child entry exists;
    otherwise the bind is stacked on top. This recovers from stale
    MNT_LOCKED mounts (whose origin namespace died) that shadow the target
    but lack what the guest needs and cannot be unmounted.

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
        except OSError as exc:
            log.debug("Failed to get size of mount source %s: %s", source_abs, exc)

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
        # Normally an existing mount is trusted (concurrent sessions share
        # mounts). But a stale mount from a dead namespace can shadow the
        # target while missing what the guest needs — e.g. a leftover
        # MNT_LOCKED tmpfs on /dev without a ptmx node, which umount2
        # cannot remove (EINVAL). When *required_child* is set, probe for
        # it and mount over the stale mount when it is missing.
        if not required_child or holder is not None or os.path.exists(os.path.join(target, required_child)):
            return
        log.debug(
            "Target %s is mounted but missing '%s'; mounting %s over the stale mount",
            target,
            required_child,
            source,
        )

    kernel_options = _filter_bind_options(options)

    if holder is not None:
        # A mount only reaches the guest from inside the holder's mount
        # namespace, so the holder makes it.
        try:
            holder.do_bind_mount(source_abs, target, recursive=recursive, options=kernel_options)
        except (OSError, MountError) as e:
            if created_stub:
                with contextlib.suppress(OSError):
                    os.remove(target)
            raise MountError(f"Failed to mount {source} to {target}: {e}") from e
    else:
        # No holder, so mount(2) straight from this process.
        try:
            bind_mount(source_abs, target, recursive=recursive, options=kernel_options)
        except OSError as e:
            if created_stub:
                with contextlib.suppress(OSError):
                    os.remove(target)
            raise MountError(f"Failed to mount {source} to {target}: {e}") from e


def create_dev_nodes(
    rootfs: str,
    nodes,
    holder: NamespaceHolder | None = None,
    *,
    use_userns: bool = False,
) -> None:
    """Populate the fresh tmpfs ``/dev`` with the minimal device nodes.

    *nodes* is an iterable of ``(name, major, minor, mode)`` tuples. Used for
    the fresh tmpfs ``/dev`` mounted under maximum isolation, where the host
    ``/dev`` is intentionally not bind-mounted. ``/dev/ptmx``, ``/dev/console``
    and the ``std*`` symlinks are provided by the devpts overmount and the login
    pty wrapper, so they are not created here.

    Two strategies:

    * **mknod** (default) creates real device nodes on the new tmpfs. This is
      how a privileged mount namespace without a user namespace works.
    * **bind** (*use_userns*): inside a user namespace the kernel forbids
      ``mknod`` of device nodes (EPERM) even for root, which would leave e.g.
      ``/dev/null`` missing — a later shell redirect then creates a plain file
      in its place, breaking it for non-root users. So when a user namespace is
      active we instead **bind-mount the host's real device node** (``/dev/null``
      etc.) onto a stub in the tmpfs ``/dev``; binding an existing device node
      is permitted in a user namespace.

    Failures are non-fatal and logged at debug level.
    """
    dev_dir = os.path.join(rootfs, "dev")
    for name, major, minor, mode in nodes:
        host_path = os.path.join(dev_dir, name)

        if use_userns:
            # Bind the host's real device node over a stub in the tmpfs /dev.
            # The fresh tmpfs /dev lives inside the holder's mount namespace, so
            # the stub target must be created there (not on the host view of the
            # rootfs) before the bind — otherwise the mount target is missing.
            source = os.path.join("/dev", name)
            if not os.path.exists(source):
                log.debug("Skipping /dev/%s bind: host node %s missing", name, source)
                continue
            if holder is not None:

                def _stub(path: str = host_path) -> None:
                    os.close(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o644))

                if holder.call(_stub) is None:
                    log.debug("Could not create stub %s in the holder's namespaces", host_path)
                    continue
            try:
                safe_mount(source, host_path, holder=holder)
            except MountError as exc:
                log.debug("Bind of device node %s -> %s failed: %s", source, host_path, exc)
            continue

        def _make_node(path: str = host_path, mode: int = mode, major: int = major, minor: int = minor) -> None:
            if os.path.exists(path):
                return
            os.mknod(path, mode | stat.S_IFCHR, os.makedev(major, minor))
            os.chmod(path, mode)

        if holder is not None:
            if holder.call(_make_node) is None:
                log.debug("Could not create device node %s in the holder's namespaces", host_path)
            continue
        # No holder (no mount namespace): create directly on the host path.
        try:
            _make_node()
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

    if holder is not None:
        try:
            holder.do_set_propagation(target_abs, MS_REC | MS_SLAVE)
            log.debug("Set rslave propagation on %s (via holder)", target_abs)
            return True
        except Exception:
            log.debug("make-rslave exception for %s (via holder)", target_abs, exc_info=True)
            return False
    else:
        try:
            set_propagation(target_abs, MS_REC | MS_SLAVE)
        except OSError:
            log.debug("make-rslave failed for %s", target_abs, exc_info=True)
            return False
        log.debug("Set rslave propagation on %s", target_abs)
        return True


# Targets that routinely EBUSY on logout (open ptys/segments, nested
# submounts); the lazy-detach fallback handles them, so log at debug
# instead of warning.
_BUSY_PRONE_BASENAMES = frozenset(
    {"dev", "pts", "shm", "run", "proc", "sys", "apex", "system", "vendor", "odm", "product", "system_ext"}
)


def _is_busy_prone_target(target: str) -> bool:
    base = os.path.basename(os.path.realpath(target).rstrip(os.sep))
    return base in _BUSY_PRONE_BASENAMES


def safe_unmount(target: str, holder: NamespaceHolder | None = None) -> None:
    """Safely unmount a target path.

    Falls back to lazy unmount if normal unmount fails. For recursive bind
    targets the "target is busy" fallback is expected, so it is logged at
    debug level instead of warning the user.
    """
    if holder is not None:
        if not is_mounted(target, holder=holder):
            return
        # Unmount inside the holder's mount namespace. do_umount already retries
        # with a lazy unmount. If even that fails (e.g. a special submount such
        # as sys/firmware/efi/efivars pulled in by a recursive /sys bind under a
        # user namespace), it is non-fatal: the holder's mount namespace is torn
        # down in full when the holder is killed, so nothing leaks.
        try:
            holder.do_umount(target)
        except (MountError, OSError) as e:
            log.debug("Non-fatal: unmount of %s inside namespace failed: %s", target, e)
        return

    # Direct syscall path — no holder.
    try:
        native_umount(target)
    except OSError as e:
        if e.errno in (errno.EINVAL, errno.ENOENT):
            # EINVAL: "not mounted" — already gone. ENOENT: the mount point
            # vanished, e.g. a shared-propagation peer was removed when its
            # sibling was unmounted. Either way there is nothing to unmount.
            log.debug("umount reports '%s' is not mounted; treating as already unmounted.", target)
            return
        err_msg = str(e)
        if _is_busy_prone_target(target):
            log.debug("umount of %s failed (%s); detaching lazily (MNT_DETACH).", target, err_msg)
        else:
            warn(f"Unmounting {target} failed ({err_msg}); detaching lazily (MNT_DETACH) instead.")
        try:
            native_umount(target, lazy=True)
        except OSError as e_lazy:
            if e_lazy.errno in (errno.EINVAL, errno.ENOENT):
                log.debug("Lazy umount reports '%s' is not mounted; treating as already unmounted.", target)
                return
            raise MountError(f"Failed to unmount {target} (lazy umount also failed): {e_lazy}") from e_lazy


def unmount_all(rootfs: str, holder: NamespaceHolder | None = None) -> None:
    """Unmount all active mount points nested under rootfs in correct order."""
    mounts = get_active_mounts(rootfs, holder=holder)
    for m in mounts:
        safe_unmount(m, holder=holder)


def _sweep_matching_mounts(marker: str) -> int:
    """Unmount every mount whose mount point contains *marker*, deepest first.

    Matches raw /proc/self/mounts entries by substring so that aliases of
    the same rootfs under different prefixes (/data/data, /data/user/0,
    /data_mirror/...) and recursive rootfs/.../rootfs phantom paths are all
    caught. EINVAL/ENOENT mean the mount is already gone; anything else
    falls back to a lazy unmount. Returns the number of removed mounts.
    """
    try:
        with open("/proc/self/mounts") as f:
            lines = f.readlines()
    except OSError:
        return 0
    targets: list[str] = []
    for line in lines:
        parts = line.strip().split()
        if len(parts) < 2:
            continue
        mount_point = decode_mount_path(parts[1])
        if marker + "/" in mount_point or mount_point.endswith(marker):
            targets.append(mount_point)
    targets.sort(key=lambda p: len(p.split(os.sep)), reverse=True)
    removed = 0
    for target in targets:
        try:
            native_umount(target)
            removed += 1
        except OSError as e:
            if e.errno in (errno.EINVAL, errno.ENOENT):
                continue
            try:
                native_umount(target, lazy=True)
                removed += 1
            except OSError:
                log.debug("deep-clean: failed to unmount %s", target, exc_info=True)
    return removed


def _pids_with_container_mounts(marker: str) -> list[int]:
    """Return one PID per distinct mount namespace whose table contains *marker*.

    Scans /proc/<pid>/ns/mnt symlinks to deduplicate namespaces, skips the
    caller's own namespace, and pre-filters by reading /proc/<pid>/mounts so
    only namespaces that actually hold container mounts are visited.
    """
    seen: set[str] = set()
    pids: list[int] = []
    try:
        entries = os.listdir("/proc")
    except OSError:
        return pids
    try:
        own_ns = os.readlink("/proc/self/ns/mnt")
    except OSError:
        own_ns = ""
    for entry in entries:
        if not entry.isdigit():
            continue
        pid = int(entry)
        try:
            ns_id = os.readlink(f"/proc/{pid}/ns/mnt")
        except OSError:
            continue
        if ns_id in seen or ns_id == own_ns:
            continue
        seen.add(ns_id)
        try:
            with open(f"/proc/{pid}/mounts") as f:
                if marker not in f.read():
                    continue
        except OSError:
            continue
        pids.append(pid)
    return pids


def deep_clean_container_mounts(container_name: str) -> None:
    """Remove a container's mounts from the init (global) mount namespace.

    Stale mounts created in the global namespace (e.g. by earlier
    ``su --mount-master`` runs) propagate into app namespaces as slave
    copies. Unmounting a slave never removes its master, so they cannot be
    cleaned from a per-session namespace. Entering PID 1's mount namespace
    and unmounting the origin mounts propagates the removal to every slave,
    which also clears the copies visible inside the Termux app namespace.

    The global-namespace sweep runs in a forked child so the caller's own
    mount namespace is never changed. Requires root; every failure is
    non-fatal and merely logged (a reboot then remains the fallback).
    """
    from chroot_distro.syscalls._constants import CLONE_NEWNS
    from chroot_distro.syscalls.nsenter import enter_namespaces

    if os.getuid() != 0:
        return

    marker = f"/chroot-distro/containers/{container_name}/rootfs"

    # Sweep the caller's namespace first: the substring match catches
    # aliases and phantom paths the rootfs-prefix walk in unmount_all
    # cannot see.
    _sweep_matching_mounts(marker)

    # Sweep every other mount namespace that still holds container mounts.
    # The stale origins are not necessarily in init's namespace:
    # `su --mount-master` enters magiskd's namespace (where /data_mirror
    # lives), and the copies propagated into app namespaces are MNT_LOCKED
    # slaves whose umount2 fails with EINVAL locally. Unmounting at the true
    # origin propagates the removal to every slave, locked ones included.
    for pid in _pids_with_container_mounts(marker):
        child = os.fork()
        if child == 0:
            # --- child: enter the target mount namespace and sweep ---
            try:
                enter_namespaces(pid, CLONE_NEWNS)
                _sweep_matching_mounts(marker)
                os._exit(0)
            except BaseException:
                os._exit(1)
        _, status = os.waitpid(child, 0)
        if not (os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0):
            log.debug("deep-clean: sweep failed for mount namespace of pid %d", pid)

    # Final pass in the caller's namespace: origin unmounts above may have
    # already cleared everything via propagation.
    _sweep_matching_mounts(marker)

    try:
        with open("/proc/self/mounts") as f:
            still_present = marker in f.read()
    except OSError:
        still_present = False
    if still_present:
        warn(
            "Some stale container mounts could not be removed from their "
            "origin mount namespace; a device reboot may be required."
        )


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


@functools.lru_cache(maxsize=1)
def _devpts_single_instance() -> bool:
    """Whether the kernel has one global devpts superblock (cached)."""
    from chroot_distro.commands.kernel_config import PROBE_ABSENT, probe_devpts_multi_instance

    return probe_devpts_multi_instance() == PROBE_ABSENT


def _mount_fs_and_options(target: str) -> tuple[str, str]:
    """Return (fstype, options) of the topmost mount at *target*.

    /proc/self/mounts lists mounts in mount order, so the last matching
    entry is the visible top of any stack at that path. Returns ("", "")
    when no entry matches.
    """
    target_abs = os.path.realpath(target)
    fstype = ""
    options = ""
    try:
        with open("/proc/self/mounts") as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) < 4:
                    continue
                mount_point = decode_mount_path(parts[1])
                try:
                    if os.path.realpath(mount_point) == target_abs:
                        fstype = parts[2]
                        options = parts[3]
                except OSError:
                    continue
    except OSError:
        return ("", "")
    return (fstype, options)


def apply_special_mount(rootfs: str, sm, holder: NamespaceHolder | None = None, force_optional: bool = False) -> bool:
    """Execute a single SpecialMount inside rootfs.

    Returns True on success, False on failure (when optional). Raises
    RuntimeError on failure when not optional. *force_optional* lets the
    caller treat an otherwise-required mount as best-effort (used for the
    max-isolation /dev tmpfs, which falls back to the on-disk /dev).
    """
    optional = sm.optional or force_optional
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

            def _mkdir() -> None:
                os.makedirs(target, exist_ok=True)

            if holder.call(_mkdir) is None:
                msg = f"Failed to create mount target directory {target} inside the holder's namespaces"
                if optional:
                    log.debug(msg)
                    return False
                raise RuntimeError(msg)
        else:
            try:
                os.makedirs(target, exist_ok=True)
            except OSError as e:
                msg = f"Failed to create mount target directory {target}: {e}"
                if optional:
                    log.debug(msg)
                    return False
                raise RuntimeError(msg) from e
    elif not os.path.exists(target):
        # With a holder, existence must also be checked inside its namespace.
        if holder is not None:

            def _exists() -> bytes:
                return b"1" if os.path.exists(target) else b""

            if not holder.call(_exists):
                log.debug(f"Mount target {target} does not exist in holder NS and mkdir=False, skipping")
                return False
        else:
            log.debug(f"Mount target {target} does not exist and mkdir=False, skipping")
            return False

    # On single-instance kernels a devpts mount(2) reconfigures the one global
    # superblock, i.e. the host's /dev/pts, until reboot. Bind it instead.
    if sm.fstype == "devpts" and _devpts_single_instance():
        if is_mounted(target, holder=holder):
            return True
        if holder is None:
            try:
                bind_mount("/dev/pts", target)
                return True
            except OSError as e:
                msg = f"binding host /dev/pts on {target} failed: {e}"
                if optional:
                    log.debug(msg)
                    return False
                raise RuntimeError(msg) from e
        # No host /dev/pts to bind inside the namespace; skip rather than
        # fail the login.
        warn("Single-instance devpts kernel: container gets no private /dev/pts.")
        return False

    if is_mounted(target, holder=holder):
        # Trust an existing mount only when it looks like the one we would
        # create. Stale mounts from dead namespaces are MNT_LOCKED (umount2
        # fails with EINVAL) and must be mounted over instead. For devpts,
        # the host instance (and binds of it) carries ptmxmode=000, which
        # breaks pty allocation in the login session; our newinstance devpts
        # uses ptmxmode=0666, so its presence identifies the correct mount.
        if holder is not None:
            return True
        fstype, opts = _mount_fs_and_options(target)
        if sm.fstype == "devpts":
            if "ptmxmode=666" in opts:
                return True
        elif fstype == sm.fstype:
            return True
        # Fall through: stack the correct mount on top of the stale one.
        # Make the covered mount private first, or the new mount propagates
        # a copy onto the host original when they share a peer group.
        with contextlib.suppress(OSError):
            set_propagation(target, MS_PRIVATE)

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
    for opts in option_attempts:
        if holder is not None:
            # Inside a namespace holder, use holder.do_mount_filesystem()
            try:
                holder.do_mount_filesystem(sm.source, target, sm.fstype, options=opts)
                log.debug("Mounted %s at %s (options=%r) via holder", sm.fstype, sm.target, opts)
                return True
            except OSError as e:
                last_err = str(e)
                log.debug("mount(2) of %s opts=%r failed via holder: %s", sm.fstype, opts, last_err)
        else:
            # Direct syscall path.
            try:
                mount_filesystem(sm.source, target, sm.fstype, options=opts)
                log.debug("Mounted %s at %s (options=%r)", sm.fstype, sm.target, opts)
                return True
            except OSError as e:
                # Kernel < 4.7 single-instance devpts: newinstance is a no-op
                # and stacking the lone instance on its own bind EBUSYs; the
                # devpts already at the target is that instance, reuse it.
                if sm.fstype == "devpts" and e.errno == errno.EBUSY and _mount_fs_and_options(target)[0] == "devpts":
                    log.debug(
                        "devpts is single-instance on this kernel; reusing the instance already mounted at %s",
                        target,
                    )
                    return True
                last_err = str(e)
                log.debug("mount(2) of %s opts=%r failed (native): %s", sm.fstype, opts, last_err)

    detail = last_err or "(no error output)"
    msg = f"mounting {sm.fstype} on {target} failed: {detail}"
    if optional:
        log.debug(msg)
        return False
    raise RuntimeError(msg)

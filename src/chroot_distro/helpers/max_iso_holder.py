"""Self-contained maximum-isolation namespace holder.

This module is executed via ``python3 -m chroot_distro.helpers.max_iso_holder``
(or ``python3 <path>``) *inside* the new PID/mount/UTS/IPC namespace created by
``unshare``. Running as PID 1 of that namespace, it:

1. makes the mount tree private (so nothing propagates back to the host),
2. chroots into the container rootfs (so PID 1's root is inside the
   container, closing the ``chroot /proc/1/root`` escape),
3. mounts a fresh procfs (hidepid=2), a read-only sysfs, a fresh tmpfs /dev
   with the minimal character devices, a newinstance devpts and a tmpfs
   /dev/shm — all from *inside* the namespace, so the parent never has to
   ``nsenter`` in to set up mounts (which is unreliable on some Android
   kernels whose per-namespace ns files cannot be opened),
4. signals readiness to the parent over a pipe (fd given by --ready-fd),
5. sleeps for effectively forever, keeping the namespaces alive.

It is intentionally dependency-free (stdlib only) and uses the ``mount(2)``
syscall via ctypes plus ``os.mknod`` so it needs no external binaries inside
the rootfs.

Configuration is passed as JSON on argv (``--config <json>``) to avoid any
quoting/escaping pitfalls.
"""

from __future__ import annotations

import argparse
import contextlib
import ctypes
import ctypes.util
import json
import logging
import os
import sys
import time

from chroot_distro.syscalls._constants import (
    MS_NODEV,
    MS_NOEXEC,
    MS_NOSUID,
    MS_PRIVATE,
    MS_RDONLY,
    MS_REC,
    S_IFCHR,
)

log = logging.getLogger(__name__)

HOLDER_SLEEP_SECONDS = 2147483647


def _libc() -> ctypes.CDLL:
    name = ctypes.util.find_library("c") or "libc.so.6"
    return ctypes.CDLL(name, use_errno=True)


def _mount(libc, source, target, fstype, flags, data=None) -> None:
    s = source.encode() if source else None
    t = target.encode()
    f = fstype.encode() if fstype else None
    d = data.encode() if data else None
    if libc.mount(s, t, f, ctypes.c_ulong(flags), d) != 0:
        err = ctypes.get_errno()
        raise OSError(err, f"mount {source} -> {target} ({fstype}): {os.strerror(err)}")


def _make_node(path: str, major: int, minor: int, mode: int) -> None:
    try:
        os.mknod(path, S_IFCHR | mode, os.makedev(major, minor))
        os.chmod(path, mode)
    except FileExistsError as exc:
        log.debug("Node %s already exists: %s", path, exc)
    except OSError as exc:
        # mknod can be denied on some Android kernels; the node is best-effort.
        log.debug("Failed to mknod %s (best-effort): %s", path, exc)


def setup(config: dict) -> None:
    rootfs = config["rootfs"]
    dev_nodes = config.get("dev_nodes", [])
    libc = _libc()

    # Detach our mount tree from the host so nothing we do propagates back.
    with contextlib.suppress(OSError):
        _mount(libc, "none", "/", "", MS_REC | MS_PRIVATE, None)

    os.chroot(rootfs)
    os.chdir("/")

    # Fresh procfs reflecting this PID namespace, hardened.
    os.makedirs("/proc", exist_ok=True)
    try:
        _mount(libc, "proc", "/proc", "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC, "hidepid=2")
    except OSError:
        # Some kernels reject hidepid in this context; retry without it.
        _mount(libc, "proc", "/proc", "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC, None)

    # Read-only sysfs (best effort: not all Android kernels allow a fresh one).
    try:
        os.makedirs("/sys", exist_ok=True)
        _mount(libc, "sysfs", "/sys", "sysfs", MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC, None)
    except OSError as exc:
        log.warning("Failed to mount sysfs (best-effort): %s", exc)

    # Fresh /dev tmpfs with the minimal device nodes.
    os.makedirs("/dev", exist_ok=True)
    _mount(libc, "tmpfs", "/dev", "tmpfs", MS_NOSUID, "mode=0755,size=64M")
    for name, major, minor, mode in dev_nodes:
        _make_node("/dev/" + name, major, minor, mode)

    # devpts for login ptys, plus the /dev/ptmx -> pts/ptmx symlink.
    os.makedirs("/dev/pts", exist_ok=True)
    _mount(
        libc,
        "devpts",
        "/dev/pts",
        "devpts",
        MS_NOSUID | MS_NOEXEC,
        "gid=5,mode=620,ptmxmode=0666,newinstance",
    )
    try:
        if os.path.islink("/dev/ptmx") or os.path.exists("/dev/ptmx"):
            os.remove("/dev/ptmx")
        os.symlink("/dev/pts/ptmx", "/dev/ptmx")
    except OSError as exc:
        log.warning("Failed to create /dev/ptmx symlink: %s", exc)

    # Fresh /dev/shm.
    try:
        os.makedirs("/dev/shm", exist_ok=True)
        _mount(libc, "tmpfs", "/dev/shm", "tmpfs", MS_NOSUID | MS_NODEV, "size=256M,mode=1777")
    except OSError as exc:
        log.warning("Failed to mount /dev/shm: %s", exc)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--config", required=True)
    parser.add_argument("--ready-fd", type=int, default=-1)
    args = parser.parse_args(argv)

    config = json.loads(args.config)
    ready_fd = args.ready_fd

    try:
        setup(config)
    except Exception as exc:
        if ready_fd >= 0:
            try:
                os.write(ready_fd, ("E" + str(exc))[:240].encode())
                os.close(ready_fd)
            except OSError as write_exc:
                log.warning("Failed to write setup failure to ready_fd: %s", write_exc)
        sys.stderr.write(f"max-isolation holder setup failed: {exc}\n")
        return 1

    if ready_fd >= 0:
        try:
            os.write(ready_fd, b"K")
            os.close(ready_fd)
        except OSError as exc:
            log.warning("Failed to write setup success to ready_fd: %s", exc)

    time.sleep(HOLDER_SLEEP_SECONDS)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

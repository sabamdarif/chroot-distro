"""idmapped mount support (Linux 5.12+) for Tier B user-namespace isolation.

An *idmapped mount* attaches a uid/gid translation to a mount without touching
the underlying filesystem. Tier B uses it so a rootfs owned by host uid 0 stays
usable inside a container whose user namespace maps container uid 0 to an
unprivileged host subordinate uid (e.g. 100000) — no ``chown -R`` required.

The three syscalls involved (``open_tree``, ``move_mount``, ``mount_setattr``)
have no glibc wrappers, so they are issued directly via ``syscall(2)``. Their
numbers are in the architecture-synchronised range (>= 424), i.e. identical on
x86_64, aarch64, arm and x86, so a single set of constants is correct
everywhere Linux runs.
"""

from __future__ import annotations

import contextlib
import ctypes
import logging
import os

from chroot_distro.syscalls._libc import get_libc

log = logging.getLogger(__name__)

# ── Syscall numbers (arch-synchronised, >= 424) ──────────────────────────────
__NR_open_tree = 428
__NR_move_mount = 429
__NR_mount_setattr = 442

# ── Flags ────────────────────────────────────────────────────────────────────
OPEN_TREE_CLONE = 0x00000001
OPEN_TREE_CLOEXEC = 0o2000000  # O_CLOEXEC
AT_EMPTY_PATH = 0x1000
AT_RECURSIVE = 0x8000
MOVE_MOUNT_F_EMPTY_PATH = 0x00000004
MOUNT_ATTR_RDONLY = 0x00000001
MOUNT_ATTR_IDMAP = 0x00100000


class MountAttr(ctypes.Structure):
    """The ``struct mount_attr`` passed to ``mount_setattr(2)``."""

    _fields_ = (
        ("attr_set", ctypes.c_uint64),
        ("attr_clr", ctypes.c_uint64),
        ("propagation", ctypes.c_uint64),
        ("userns_fd", ctypes.c_uint64),
    )


def _check(result: int, name: str) -> int:
    if result == -1:
        err = ctypes.get_errno()
        raise OSError(err, f"{name}: {os.strerror(err)}")
    return result


def _syscall_libc() -> ctypes.CDLL:
    """Return the shared libc handle with ``syscall`` typed to return long."""
    libc = get_libc()
    libc.syscall.restype = ctypes.c_long
    return libc


def open_tree(dfd: int, path: str, flags: int) -> int:
    """``open_tree(2)`` — return an fd referring to a (clone of a) mount tree."""
    libc = _syscall_libc()
    fd = libc.syscall(
        ctypes.c_long(__NR_open_tree),
        ctypes.c_int(dfd),
        ctypes.c_char_p(path.encode()),
        ctypes.c_uint(flags),
    )
    return _check(fd, "open_tree")


def move_mount(from_dfd: int, from_path: str, to_dfd: int, to_path: str, flags: int) -> None:
    """``move_mount(2)`` — attach a detached mount tree at a new location."""
    libc = _syscall_libc()
    result = libc.syscall(
        ctypes.c_long(__NR_move_mount),
        ctypes.c_int(from_dfd),
        ctypes.c_char_p(from_path.encode()),
        ctypes.c_int(to_dfd),
        ctypes.c_char_p(to_path.encode()),
        ctypes.c_uint(flags),
    )
    _check(result, "move_mount")


def mount_setattr(dfd: int, path: str, flags: int, attr: MountAttr) -> None:
    """``mount_setattr(2)`` — change mount attributes (here: attach an idmap).

    Note: ``MOUNT_ATTR_IDMAP`` cannot be combined with ``AT_RECURSIVE`` — the
    kernel does not support setting an idmap recursively.
    """
    libc = _syscall_libc()
    result = libc.syscall(
        ctypes.c_long(__NR_mount_setattr),
        ctypes.c_int(dfd),
        ctypes.c_char_p(path.encode()),
        ctypes.c_uint(flags),
        ctypes.byref(attr),
        ctypes.c_size_t(ctypes.sizeof(attr)),
    )
    _check(result, "mount_setattr")


def idmapped_mounts_supported() -> bool:
    """Return True if the kernel supports idmapped mounts (Linux 5.12+).

    Forks a child that ``unshare``\\ s a user namespace (so its
    ``/proc/<pid>/ns/user`` carries a real mapping), clones a detached mount of
    a fresh private tmpfs, and attaches that userns as an idmap. Everything is
    disposable. Any failure (old kernel → ENOSYS/EINVAL, restricted environment
    → EPERM) reports unsupported.
    """
    import tempfile

    from chroot_distro.syscalls._constants import CLONE_NEWUSER
    from chroot_distro.syscalls._libc import libc_mount, py_unshare

    ready_r, ready_w = os.pipe()  # child → parent: "user namespace ready"
    done_r, done_w = os.pipe()  # parent → child: "you may exit"
    child = os.fork()
    if child == 0:
        os.close(ready_r)
        os.close(done_w)
        try:
            py_unshare(CLONE_NEWUSER)
            os.write(ready_w, b"U")
        except OSError:
            os._exit(1)
        with contextlib.suppress(OSError):
            os.read(done_r, 1)
        os._exit(0)

    os.close(ready_w)
    os.close(done_r)
    ok = False
    tree_fd = -1
    userns_fd = -1
    try:
        if os.read(ready_r, 1) != b"U":
            return False
        with open(f"/proc/{child}/uid_map", "w") as fh:
            fh.write(f"0 {os.getuid()} 1\n")
        with open(f"/proc/{child}/gid_map", "w") as fh:
            fh.write(f"0 {os.getgid()} 1\n")
        userns_fd = os.open(f"/proc/{child}/ns/user", os.O_RDONLY)
        scratch = tempfile.mkdtemp()
        libc_mount(b"tmpfs", scratch.encode(), b"tmpfs", 0, None)
        tree_fd = open_tree(-100, scratch, OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC)
        attr = MountAttr(attr_set=MOUNT_ATTR_IDMAP, attr_clr=0, propagation=0, userns_fd=userns_fd)
        mount_setattr(tree_fd, "", AT_EMPTY_PATH, attr)
        ok = True
    except OSError as exc:
        log.debug("idmapped mounts not supported: %s", exc)
        ok = False
    finally:
        if tree_fd >= 0:
            with contextlib.suppress(OSError):
                os.close(tree_fd)
        if userns_fd >= 0:
            with contextlib.suppress(OSError):
                os.close(userns_fd)
        with contextlib.suppress(OSError):
            os.write(done_w, b"1")
            os.close(done_w)
        with contextlib.suppress(OSError, ChildProcessError):
            os.waitpid(child, 0)
    return ok


def make_idmapped_tree(source: str, userns_fd: int, *, recursive: bool = True) -> int:
    """Return a detached, idmapped clone of the mount at *source*.

    The caller is responsible for ``move_mount``-ing the returned fd into place
    and closing it. The idmap is taken from *userns_fd* — a file descriptor for
    a ``/proc/<pid>/ns/user`` whose mapping defines how the filesystem's uids
    are translated for this mount.
    """
    flags = OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC
    if recursive:
        flags |= AT_RECURSIVE
    tree_fd = open_tree(-100, source, flags)  # AT_FDCWD = -100
    try:
        attr = MountAttr(attr_set=MOUNT_ATTR_IDMAP, attr_clr=0, propagation=0, userns_fd=userns_fd)
        setattr_flags = AT_EMPTY_PATH
        if recursive:
            setattr_flags |= AT_RECURSIVE
        mount_setattr(tree_fd, "", setattr_flags, attr)
    except OSError:
        with contextlib.suppress(OSError):
            os.close(tree_fd)
        raise
    return tree_fd

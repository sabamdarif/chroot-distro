# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
"""Path composition and safe resolution of `name:path` specs.

Two unrelated jobs live here. The composition half (`container_dir`,
`container_rootfs`, `container_manifest`, `container_log_path`,
`installed_containers`) is the only place that knows how a container's files are
laid out under CONTAINERS_DIR: nothing else may build those paths by hand. The
resolution half is a trust boundary, and it is where the care goes.

A `name:path` spec is user input naming an entry inside a rootfs a guest can
write. `resolve_container_path` walks it with the guest's own semantics, *root*
standing in for `/`, so a symlink the guest planted resolves the way the
container sees it and cannot reach the host; `..` written in the spec is refused
outright. `refuse_src_dest_overlap` then compares the two ends of a transfer
after resolution, because a link on either side is enough to make a directory a
copy of itself. `resolve_container_child` exists so the base name `copy` and
`sync` append to a destination directory gets the same walk as one that was
typed.

Resolving says where an entry belongs; it does not make it safe to use. The path
came back with no symlink components, but a guest can swap one in before the
call that acts on it, so a caller re-walks those components with `pin_path` and
works from the `(dir_fd, leaf)` a `PinnedPath` carries. That re-walk both detects
the swap and pins the inode it validated. Handing the resolved string back to the
kernel is the bug this file exists to prevent.

`open_container_rootfs` is the entry to that world: `containers/<name>` is
guest-writable on Termux, so it is descended with O_NOFOLLOW at every step rather
than opened by composed path, and `container_is_installed` answers through the
same walk. FileNotFoundError from either is an ordinary "not installed"; any
other refusal is an entry this program did not create, and becomes
`_unusable_storage`. ENOTDIR is ambiguous (an O_NOFOLLOW open declining a link,
or a component that is simply not a directory), so a refusal is only reported as
a race once the component has been confirmed to be a symlink.

The chroot-semantics resolver, the overlap guard and the descriptor pins below
are ported from proot-distro (https://github.com/termux/proot-distro), created
by Sylirre <sylirre@termux.dev> for the Termux project and licensed GPL-3.0,
then adapted to chroot-distro's exception-based error reporting.
"""

import contextlib
import os
import stat
from collections.abc import Iterator
from contextlib import contextmanager

from chroot_distro import dirfd
from chroot_distro.constants import CONTAINERS_DIR, RUNTIME_DIR
from chroot_distro.exceptions import (
    ChrootDistroError,
    ContainerNotFoundError,
    InvalidNameError,
)
from chroot_distro.locking import ContainerLock
from chroot_distro.message import quote_path
from chroot_distro.names import is_valid_name


def container_dir(name: str) -> str:
    """Return the absolute path to a container's top-level directory."""
    return os.path.join(CONTAINERS_DIR, name)


def container_log_path(name: str) -> str:
    """Return the log-file path used by detached `run` sessions.

    Lives alongside the session/holder state under the runtime data dir so it
    persists for the lifetime of the container's mounts and is not part of the
    rootfs itself.
    """
    data_dir = os.path.join(RUNTIME_DIR, "data", name)
    os.makedirs(data_dir, exist_ok=True)
    return os.path.join(data_dir, "run.log")


def container_rootfs(name: str) -> str:
    """Return the absolute path to a container's rootfs directory."""
    return os.path.join(container_dir(name), "rootfs")


def container_manifest(name: str) -> str:
    """Return the absolute path to a container's manifest.json sentinel."""
    return os.path.join(container_dir(name), "manifest.json")


def container_incomplete_marker(name: str) -> str:
    """Return the path of the marker that flags an in-progress install.

    The marker is created before the first byte of rootfs data is written
    and removed as the final step of a successful install. A rootfs that
    coexists with this marker is a leftover from an interrupted install
    (Ctrl+C, SIGKILL, power loss, ...) and is safe to wipe and redo. Without
    it, "already exists" checks cannot distinguish a finished
    container from an aborted one.
    """
    return os.path.join(container_dir(name), ".install-incomplete")


def is_install_incomplete(name: str) -> bool:
    """Return True if *name* is a leftover from an interrupted install."""
    return os.path.isfile(container_incomplete_marker(name))


def container_from_spec(spec: str) -> str | None:
    """Return the container name in a `name:path` spec, or None.

    A colon separates a container from a path only when nothing before it is a
    directory separator, which is the rule scp and rsync use: `box:/etc` names a
    container, while `/tmp/a:b` and `./a:b` are host paths that happen to have a
    colon in the name. Treating every colon as a separator left such a path
    unreachable: the whole prefix was taken for a container name and rejected as
    invalid, with no spelling that could say otherwise. A bare `a:b` is still a
    container spec, so a host file named that way in the current directory is
    addressed as `./a:b`, exactly as scp requires.
    """
    head, sep, _ = spec.partition(":")
    if not sep or "/" in head:
        return None
    return head


_MAX_SYMLINK_HOPS = 40


def _resolve_within_root(root: str, rel_path: str, spec: str) -> str:
    """Resolve *rel_path* under *root* the way the guest would see it.

    Path components are consumed one at a time and every symlink met on the way
    is expanded with *root* standing in for `/`: an absolute link target
    restarts the walk at *root*, a relative one continues from the directory
    holding the link, and `..` is clamped so it can never climb above *root*. The
    returned path is therefore always inside *root* and contains no symlink
    components.

    Purely lexical normalisation is not enough here. os.path.normpath collapses
    `..` without looking at the filesystem, so a symlink planted inside the
    rootfs (`escape -> /`, which is perfectly ordinary as seen from inside the
    container) would pass a startswith(rootfs) check and then be followed by the
    copy, reading from or writing to the host filesystem outside the container.

    The hop count mirrors the kernel's ELOOP limit, guarding against a link cycle
    (a -> b -> a).
    """
    resolved = root
    pending = rel_path.split("/")
    hops = 0

    while pending:
        part = pending.pop(0)
        if part in ("", "."):
            continue
        if part == "..":
            if resolved != root:
                resolved = os.path.dirname(resolved)
            continue

        candidate = os.path.join(resolved, part)
        try:
            target = os.readlink(candidate)
        except OSError:
            resolved = candidate
            continue

        hops += 1
        if hops > _MAX_SYMLINK_HOPS:
            raise ChrootDistroError(f"too many symbolic links while resolving '{spec}'.")
        if target.startswith("/"):
            resolved = root
        pending = target.split("/") + pending

    return resolved


def _host_path(path: str, deref_leaf: bool) -> str:
    """Resolve a host path's symlinks, keeping the final name when asked.

    Host paths are not walked component by component the way container ones are,
    since the host filesystem is not what the chroot walk defends against, but their
    links still decide what an operation touches, and two of those decisions have
    to come out right.

    An endpoint that *is* a link is acted on by what it points at, as cp and
    rsync both do; `sync /sdcard box:/x` is the ordinary way to ask for it on
    Termux. And every parent link has to be gone before two paths can be weighed
    for overlap: `sync <dir> <link>/inner` with `link -> <dir>` is a directory
    copied into itself, and only resolution shows it.

    With deref_leaf=False just the parents are resolved, for `copy --move`, which
    renames the final name rather than following it.
    """
    if deref_leaf:
        return os.path.realpath(path)
    parent = os.path.dirname(path) or os.sep
    return os.path.join(os.path.realpath(parent), os.path.basename(path))


def _walk_spec(rootfs: str, rel_path: str, spec: str, deref_leaf: bool) -> str:
    """Resolve *rel_path* under *rootfs*, optionally keeping the last name.

    With deref_leaf=False only the parents are walked, for an operation that acts
    on the final component itself rather than on what it names. `.` and `..` name
    no entry of their own, so there is nothing to keep and the full walk
    collapses them as usual.
    """
    if not deref_leaf:
        head, _, tail = rel_path.rstrip("/").rpartition("/")
        if tail and tail not in (os.curdir, os.pardir):
            return os.path.join(_resolve_within_root(rootfs, head, spec), tail)
    return _resolve_within_root(rootfs, rel_path, spec)


_O_DIR = (getattr(os, "O_PATH", 0) or os.O_RDONLY) | os.O_DIRECTORY


def open_container_rootfs(name: str, *, create: bool = False) -> int:
    """Open containers/<name>/rootfs as a descriptor. The caller closes it.

    Walked down from CONTAINERS_DIR with O_NOFOLLOW at every step rather than
    opened by composed path. On Termux the runtime tree lives under the prefix
    that is bound read-write into every non-isolated container, so
    `containers/<name>` is guest-writable, and a symlink left in place of it or
    of its rootfs is how a transfer ends up reading or writing a host directory.

    With create=True each missing level is made with mkdirat off the descriptor
    of the level above, which is what `install` needs: the tree it is about to
    unpack into has to be created the same way it is checked, and the
    descriptor it gets back is the one every member is then written beneath.

    FileNotFoundError means the container, or its rootfs, is not there, an
    ordinary answer, left to the caller. Any other refusal is an entry this
    program did not create.
    """
    root_fd = os.open(CONTAINERS_DIR, _O_DIR)
    try:
        return dirfd.descend_at(root_fd, (name, "rootfs"), create=create)
    finally:
        os.close(root_fd)


def _unusable_storage(name: str, exc: OSError) -> ChrootDistroError:
    """The error for a container directory that must not be followed."""
    return ChrootDistroError(
        f"the storage of container '{name}' is not usable: "
        f"'{quote_path(container_rootfs(name))}' is not a directory this program created "
        f"({exc.strerror}). Refusing to follow it; remove or move that entry and try again."
    )


def container_is_installed(name: str) -> bool:
    """True when containers/<name>/rootfs is a directory reachable as one.

    os.path.isdir() on the composed path follows whatever stands in the way; this
    walks down to it instead, so False means the container is genuinely not
    installed rather than that a planted entry led somewhere without a rootfs.
    """
    try:
        fd = open_container_rootfs(name)
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise _unusable_storage(name, exc) from None
    os.close(fd)
    return True


def resolve_container_path(spec: str, *, deref_leaf: bool = True) -> str:
    """Resolve a `name:path` or plain host path to an absolute host path.

    For a `name:path` spec the result is forced to stay inside the container's
    rootfs. An attempt to traverse out with `..` segments written in the spec
    itself is rejected; symlinks stored in the rootfs are instead resolved
    against the rootfs as if it were `/`, matching what the container sees and
    denying any escape (see _resolve_within_root).

    Pass deref_leaf=False for an operation that acts on the last component
    *itself* rather than on what it names: `copy --move`, which renames the
    entry, as mv does. Only the parents then get the chroot walk. Without it,
    moving a container symlink would resolve to the link's target and move that
    instead, leaving the link behind and dangling.

    A host path is resolved to the same depth (see _host_path), so both sides of
    a transfer name the entry that will really be touched.
    """
    name = container_from_spec(spec)
    if name is None:
        return _host_path(os.path.abspath(spec), deref_leaf)

    rel_path = spec.partition(":")[2]
    if not is_valid_name(name):
        raise InvalidNameError(f"invalid container name '{name}' in spec '{spec}'.")
    rootfs = os.path.normpath(container_rootfs(name))
    if not container_is_installed(name):
        raise ContainerNotFoundError(f"container '{name}' does not exist.")
    rel_path = rel_path.lstrip("/")
    lexical = os.path.normpath(os.path.join(rootfs, rel_path))
    if lexical != rootfs and not lexical.startswith(rootfs + os.sep):
        raise ChrootDistroError("destination path escapes the container directory.")
    return _walk_spec(rootfs, rel_path, spec, deref_leaf)


def _overlap_path(spec: str, path: str, deref_leaf: bool) -> str:
    """The form of *path* to weigh an overlap against.

    Two paths can only be compared as strings once both are spelled the same way,
    and the two sides arrive spelled differently. A host path is fully resolved by
    _host_path, which is where resolve_container_path() already sent it.

    A container path cannot simply be handed to realpath(): below the rootfs the
    chroot walk has already resolved every component, and re-resolving those with
    *host* semantics would undo the very thing that walk is for. But the walk
    starts at a rootfs that was only ever composed lexically, and a symlink
    *above* the rootfs (a symlinked HOME or ~/.local/share, ordinary enough)
    then left the two sides incomparable: `copy -r box:/data <the same directory
    named as a host path>` did not look like a directory copied into itself. So
    the prefix is resolved and the walked remainder, which realpath must not
    touch, joined back on.
    """
    name = container_from_spec(spec)
    if name is None:
        return _host_path(path, deref_leaf)
    rootfs = os.path.normpath(container_rootfs(name))
    if path == rootfs:
        return os.path.realpath(rootfs)
    if not path.startswith(rootfs + os.sep):
        return path
    return os.path.join(os.path.realpath(rootfs), os.path.relpath(path, rootfs))


def refuse_src_dest_overlap(
    src_spec: str,
    src_path: str,
    dest_spec: str,
    dest_path: str,
    *,
    deref_leaf: bool = True,
    pruning: bool = False,
) -> None:
    """Raise when the two ends of a transfer overlap.

    Both paths are already resolved, so this weighs what the transfer will really
    touch rather than what was typed. That matters: a symlink the guest planted in
    the rootfs (`backup -> /data`) is enough to make `copy -r box:/data
    box:/backup` a directory copied into itself, which recursed until the
    interpreter's stack gave out and left a partial tree behind. A host link does
    the same from the other side, including one standing *as* an endpoint.

    Source onto itself is refused for the reason cp refuses it too: the
    destination is opened while the source is still being read, so the file comes
    out empty. The stat follows a final symlink only when the operation itself
    would, so `copy f link` is refused and `copy --move f link` renames, matching
    cp and mv; a hardlinked pair is caught either way.

    With pruning=True (`sync --delete`) the reverse containment is refused as
    well. Entries of the destination that the source does not contain are removed,
    and a source *inside* the destination is exactly such an entry: `sync --delete
    box:/a/b box:/a` deleted box:/a/b itself.
    """
    src_cmp = _overlap_path(src_spec, src_path, deref_leaf)
    dest_cmp = _overlap_path(dest_spec, dest_path, deref_leaf)
    stat_at = os.stat if deref_leaf else os.lstat

    same = src_cmp == dest_cmp
    if not same:
        try:
            same = os.path.samestat(stat_at(src_path), stat_at(dest_path))
        except OSError:
            same = False
    if same:
        raise ChrootDistroError(f"'{src_spec}' and '{dest_spec}' are the same file.")

    if dest_cmp.startswith(src_cmp.rstrip(os.sep) + os.sep):
        raise ChrootDistroError(f"cannot copy '{src_spec}' into itself: '{dest_spec}' is inside it.")

    if pruning and src_cmp.startswith(dest_cmp.rstrip(os.sep) + os.sep):
        raise ChrootDistroError(
            f"cannot sync '{src_spec}' into '{dest_spec}' with '--delete': "
            f"the source is inside the destination and would be deleted as an orphan."
        )


def resolve_container_child(spec: str, resolved: str, child: str, *, deref_leaf: bool = True) -> str:
    """Resolve *child* under the already-resolved container path *resolved*.

    `copy` and `sync` extend a destination directory with the source's base name,
    so that `copy f box:/dir` writes to `box:/dir/f`. That appended component is
    container content like any other and has to go through the same chroot walk as
    one written in the spec: `/dir/f` may itself be a symlink, and joining it
    literally would leave an unresolved link at the leaf, which the O_NOFOLLOW open
    then refuses, failing an operation that succeeds when spelled `box:/dir/f`.

    deref_leaf carries the same meaning as in resolve_container_path, and for the
    same reason: `copy --move f box:/dir` renames onto `box:/dir/f` and must
    replace a link planted there rather than follow it.
    """
    joined = os.path.join(resolved, child)
    name = container_from_spec(spec)
    if name is None:
        return _host_path(joined, deref_leaf)
    rootfs = os.path.normpath(container_rootfs(name))
    return _walk_spec(rootfs, os.path.relpath(joined, rootfs), spec, deref_leaf)


class PinnedPath:
    """A resolved path together with an fd pinning the directory it is in.

    `str(pin)` is the real path, for messages. `pin.dir_fd` and `pin.leaf` are
    what every filesystem call should use: the fd refers to a directory *inode*
    that an O_NOFOLLOW walk has just validated, so renaming a directory cannot
    re-point it, and `leaf` is the single remaining name, which callers open with
    O_NOFOLLOW themselves (see dirfd.open_file_at). A pin taken with inside=True
    has an empty leaf and its fd refers to the path itself.

    O_PATH opens a directory without needing read permission on it, which matters
    for the execute-only directories `sync` deliberately tolerates;
    dirfd.reopen() turns such a pin into a readable fd when one is needed.
    """

    __slots__ = ("dir_fd", "leaf", "path")

    def __init__(self, path: str, dir_fd: int, leaf: str = "") -> None:
        self.path = path
        self.dir_fd = dir_fd
        self.leaf = leaf

    def __str__(self) -> str:
        return self.path


class _RefusedError(OSError):
    """A walk component is a symlink now, and was not at resolve time."""


def _is_link_at(fd: int, part: str) -> bool:
    """True when *part* under *fd* is a symlink right now."""
    try:
        return stat.S_ISLNK(dirfd.lstat_at(fd, part).st_mode)
    except OSError:
        return False


def _descend(fd: int, part: str, create: bool) -> int:
    """Open *part* under *fd*, close *fd*, and return the new fd.

    With create=True a missing component is made on the way down. The mkdir is
    relative to a directory fd the walk has already validated and the open that
    follows is O_NOFOLLOW, so a component created here is no more redirectable
    than one that was already present, which is the whole reason the parents are
    not made by path beforehand.

    A refusal is raised as _RefusedError only once the component has been confirmed to
    be a symlink. ENOTDIR covers two unrelated things, the O_NOFOLLOW open
    declining a link and a component that is simply not a directory
    (`copy x box:/etc/passwd/y`, a plain mistake), and reporting the second as a
    race would send the user hunting for an attack.
    """
    try:
        nxt = os.open(part, _O_DIR | os.O_NOFOLLOW, dir_fd=fd)
    except FileNotFoundError:
        if not create:
            raise
        with contextlib.suppress(FileExistsError):
            os.mkdir(part, 0o777, dir_fd=fd)
        nxt = os.open(part, _O_DIR | os.O_NOFOLLOW, dir_fd=fd)
    except OSError as exc:
        if dirfd.is_refusal(exc) and _is_link_at(fd, part):
            raise _RefusedError(exc.errno, exc.strerror, part) from None
        raise
    os.close(fd)
    return nxt


@contextmanager
def pin_path(spec: str, resolved: str, *, inside: bool = False, create: bool = False) -> Iterator[PinnedPath]:
    """Yield a PinnedPath for *resolved*, the result of resolving *spec*.

    resolve_container_path() returns a path with no symlink components, but
    resolving and then using it are two steps: a process inside the container can
    swap a directory for a symlink in between, and the copy would follow it out to
    the host. Re-walking the components with O_NOFOLLOW closes that window twice
    over: it *detects* the swap (a component that is now a symlink fails, and the
    command aborts) and it *pins* what it validated, since the returned fd keeps
    naming the same directory inode no matter what happens to the name.

    By default the *parent* is pinned and the final component is carried as `leaf`,
    which is what a caller operating on the path itself needs. Pass inside=True for
    a path the caller only ever works *underneath* (sync's source and destination
    roots) to walk the final component too and pin that directory itself.
    inside=True therefore also *refuses* a root that has become a symlink, which
    the default cannot do: everything written below it would go straight through.

    Pass create=True when the caller needs the walked directories to exist. Making
    them here rather than with os.makedirs() beforehand is what keeps the guarantee
    whole: makedirs() addresses each level by path, so a component swapped for a
    symlink between the resolve and the call is followed, and directories land
    outside the container before the pin gets its chance to refuse.

    A host path (no container prefix) is not walked component by component, since
    the host filesystem is not the threat, but its parent is still opened, so callers
    get the same (dir_fd, leaf) pair either way.
    """
    name = container_from_spec(spec)
    fd = None
    try:
        try:
            if name is None:
                base = resolved if inside else (os.path.dirname(resolved) or os.sep)
                leaf = "" if inside else os.path.basename(resolved)
                if create:
                    os.makedirs(base, exist_ok=True)
                fd = os.open(base, _O_DIR)
            else:
                rootfs = os.path.normpath(container_rootfs(name))
                rel = os.path.relpath(resolved, rootfs)
                parts = [] if rel == os.curdir else rel.split(os.sep)
                leaf = "" if inside else (parts.pop() if parts else "")
                fd = open_container_rootfs(name)
                for part in parts:
                    fd = _descend(fd, part, create)
        except OSError as exc:
            if fd is not None:
                os.close(fd)
                fd = None
            if isinstance(exc, _RefusedError):
                raise ChrootDistroError(
                    f"path '{spec}' changed while it was being resolved ({exc.strerror}); refusing to continue."
                ) from None
            raise ChrootDistroError(f"cannot open '{spec}': {exc.strerror}.") from None
        yield PinnedPath(resolved, fd, leaf)
    finally:
        if fd is not None:
            with contextlib.suppress(OSError):
                os.close(fd)


def container_locks_for_spec_pair(src_spec: str, dst_spec: str, command: str) -> list[ContainerLock]:
    """Return ContainerLock instances needed for a `src -> dst` op."""
    src_name = container_from_spec(src_spec)
    dst_name = container_from_spec(dst_spec)
    if src_name and dst_name:
        if src_name == dst_name:
            return [ContainerLock(src_name, exclusive=True, command=command)]
        return [
            ContainerLock(name, exclusive=(name == dst_name), command=command) for name in sorted({src_name, dst_name})
        ]
    if dst_name:
        return [ContainerLock(dst_name, exclusive=True, command=command)]
    if src_name:
        return [ContainerLock(src_name, exclusive=False, command=command)]
    return []


def installed_containers() -> list[str]:
    """Return sorted names of all installed containers (those with a rootfs).

    Leftovers from interrupted installs (see container_incomplete_marker)
    are not installed containers and are excluded.
    """
    try:
        return sorted(
            e for e in os.listdir(CONTAINERS_DIR) if os.path.isdir(container_rootfs(e)) and not is_install_incomplete(e)
        )
    except OSError as exc:
        import errno

        if exc.errno in (errno.EACCES, errno.EPERM):
            import logging

            logging.getLogger(__name__).warning(
                "Permission denied: cannot read containers directory '%s'", CONTAINERS_DIR
            )
        return []

# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
"""RUN --mount support (BuildKit syntax) on the existing mount machinery.

Five types: bind, cache, tmpfs, secret, ssh. `run_mount_session` applies them
for one step and tears them down in a `finally`, so a failed step leaves nothing
mounted, no scratch copy behind and no cache lock held. Per-type readonly
defaults are BuildKit's, and a flag or an option this program does not implement
is a `BuildError` naming the line: warned-and-ignored would mean building
something other than what the Dockerfile says. Validation runs before the
build-cache lookup for the same reason, so a cache hit cannot smuggle an
unsupported flag past it.

A mount target is a guest path and a mount point is a name, which is where the
care goes. `safe_mount` creates a missing target with a named makedirs and
mount(2) resolves it again, and both follow a symlink standing there, so
`--mount=target=/var/tmp/x` against an image shipping `var/tmp -> <host dir>`
put the source outside the rootfs. `_host_target` resolves every component
including the last and re-anchors an absolute link at the rootfs, which is the
view the guest has of its own path, so `/var/run/...` still lands on `/run/...`.

Writes are kept off anything the build did not mean to change: a rw bind and a
`sharing=private` cache are bound from a throwaway copy under the scratch root,
a `sharing=locked` cache takes a `RunCacheLock` so two builds do not write it at
once, and a secret is copied to a 0400 file that teardown removes. Placeholders
this module created for the mount points are removed deepest-first with rmdir,
so an empty one does not leak into the layer diff (BuildKit excludes mount
targets from layers) while whatever the step actually wrote into one is kept.
"""

import contextlib
import hashlib
import os
import shutil
import typing
from dataclasses import dataclass

from chroot_distro import dirfd
from chroot_distro.constants import BASE_CACHE_DIR
from chroot_distro.helpers.build_engine.errors import BuildError
from chroot_distro.helpers.tar_extract import _safe_resolve

RUN_CACHE_DIR = os.path.join(BASE_CACHE_DIR, "build-run-cache")

_KNOWN_RUN_FLAGS = frozenset({"mount", "network", "security"})
_MOUNT_TYPES = frozenset({"bind", "cache", "tmpfs", "secret", "ssh"})
_SHARING_VALUES = frozenset({"shared", "private", "locked"})

# Per-type readonly default (BuildKit semantics).
_RO_DEFAULT = {"bind": True, "cache": False, "tmpfs": False, "secret": True, "ssh": False}


@dataclass
class RunMount:
    """One parsed --mount=... entry on a RUN instruction."""

    type: str = "bind"
    target: str = ""
    source: str = ""
    from_: str = ""
    id: str = ""
    readonly: bool | None = None  # None = per-type default
    mode: int | None = None
    uid: int = 0
    gid: int = 0
    sharing: str = "locked"
    required: bool = False


def validate_and_parse_run_flags(instr: dict[str, typing.Any]) -> list[RunMount]:
    """Validate every RUN flag and return the parsed --mount entries.

    Must run before the build-cache lookup so unsupported flags are
    rejected even when the layer is cached.
    """
    flags = instr.get("flags") or {}
    lineno = instr.get("lineno", 0)

    for key in flags:
        if key not in _KNOWN_RUN_FLAGS:
            raise BuildError(f"RUN --{key} is not supported (line {lineno}); refusing to silently ignore it.")

    network = flags.get("network")
    if network is not None:
        if network == "none":
            raise BuildError(
                f"RUN --network=none requires network-namespace support that "
                f"chroot-distro does not provide yet (line {lineno})."
            )
        if network not in ("host", "default"):
            raise BuildError(f"RUN --network={network} is not supported (line {lineno}).")
        # host/default: host networking is what the step gets anyway.

    if "security" in flags:
        raise BuildError(
            f"RUN --security is not supported yet; it is sequenced after the isolation/sandbox work (line {lineno})."
        )

    raw = flags.get("mount")
    if raw is None:
        return []
    entries = raw if isinstance(raw, list) else [raw]
    return [_parse_one_mount(str(e), lineno) for e in entries]


def _parse_bool(key: str, value: str, lineno: int) -> bool:
    v = value.strip().lower()
    if v in ("", "true", "1"):
        return True
    if v in ("false", "0"):
        return False
    raise BuildError(f"RUN --mount: invalid boolean '{key}={value}' (line {lineno}).")


def _parse_one_mount(spec: str, lineno: int) -> RunMount:
    kv: dict[str, str] = {}
    for part in spec.split(","):
        if not part:
            continue
        k, _, v = part.partition("=")
        kv[k.strip()] = v

    mtype = kv.pop("type", "bind")
    if mtype not in _MOUNT_TYPES:
        raise BuildError(f"RUN --mount type '{mtype}' is not supported (line {lineno}).")

    m = RunMount(type=mtype)
    for k, v in kv.items():
        if k in ("target", "dst", "destination"):
            m.target = v
        elif k in ("source", "src"):
            m.source = v
        elif k == "from":
            m.from_ = v
        elif k in ("readonly", "ro"):
            m.readonly = _parse_bool(k, v, lineno)
        elif k in ("readwrite", "rw"):
            m.readonly = not _parse_bool(k, v, lineno)
        elif k == "id":
            m.id = v
        elif k == "mode":
            try:
                m.mode = int(v, 8)
            except ValueError as exc:
                raise BuildError(f"RUN --mount: invalid mode '{v}' (line {lineno}).") from exc
        elif k in ("uid", "gid"):
            try:
                setattr(m, k, int(v))
            except ValueError as exc:
                raise BuildError(f"RUN --mount: invalid {k} '{v}' (line {lineno}).") from exc
        elif k == "sharing":
            if v not in _SHARING_VALUES:
                raise BuildError(f"RUN --mount: invalid sharing '{v}' (line {lineno}).")
            m.sharing = v
        elif k == "required":
            m.required = _parse_bool(k, v, lineno)
        else:
            raise BuildError(f"RUN --mount: unknown option '{k}' (line {lineno}).")

    if m.readonly is None:
        m.readonly = _RO_DEFAULT[mtype]

    if mtype == "secret":
        if not m.id:
            m.id = os.path.basename(m.target) if m.target else ""
        if not m.id:
            raise BuildError(f"RUN --mount=type=secret requires an id or target (line {lineno}).")
        if not m.target:
            m.target = f"/run/secrets/{m.id}"
    elif mtype == "ssh":
        if not m.id:
            m.id = "default"
    elif not m.target:
        raise BuildError(f"RUN --mount=type={mtype} requires a target (line {lineno}).")

    return m


def _host_target(rootfs: str, target_abs: str) -> str:
    """Resolve a guest target path to a host path clamped inside rootfs.

    The last component is resolved along with the rest of them. A mount point
    is a name: safe_mount() creates it with a named makedirs and mount(2)
    resolves it again, and both follow a symlink standing there, so
    ``--mount=target=/var/tmp/x`` against an image shipping
    ``var/tmp -> <host dir>`` put the source outside the rootfs. Following the
    link re-anchored at the rootfs is what the guest's own view gives, so
    ``/var/run/...`` still lands on ``/run/...``.
    """
    parts = [p for p in target_abs.split("/") if p not in ("", ".")]
    if not parts or ".." in parts:
        raise BuildError(f"invalid RUN --mount target '{target_abs}'.")
    host = _safe_resolve(rootfs, parts)
    if host is None:
        raise BuildError(f"RUN --mount target '{target_abs}' cannot be resolved inside the rootfs.")
    return host


def _record_missing(rootfs: str, host_tgt: str, created: list[str]) -> None:
    """Record rootfs paths the mount will create (mountpoint + parents).

    safe_mount creates the target file/dir if absent; without cleanup the
    empty placeholder survives the unmount and leaks into the layer diff
    (BuildKit excludes mount targets from layers). Parents first, so
    teardown can remove deepest-first.
    """
    path = host_tgt
    missing = []
    while len(path) > len(rootfs) and not os.path.lexists(path):
        missing.append(path)
        path = os.path.dirname(path)
    created.extend(reversed(missing))


def _scratch_copy(src: str, scratch: str) -> str:
    """Copy *src* (file or tree) to *scratch* for writes-discarded rw binds."""
    if os.path.isdir(src):
        shutil.copytree(src, scratch, symlinks=True)
    else:
        shutil.copyfile(src, scratch)
        shutil.copymode(src, scratch)
    return scratch


def _remove_scratch(engine: typing.Any, parts: typing.Sequence[str]) -> None:
    """Remove the scratch copy *parts* names below the build's scratch root.

    What a mount leaves there is a RUN step's own doing (a rw bind of the build
    context or of a pulled image, a private cache the step wrote into), so the
    depth and the modes are the step's choice, not this program's.
    `shutil.rmtree(ignore_errors=True)` swallowed an OSError but not the
    RecursionError a tree deeper than the interpreter's limit raises, and this
    runs in the session's `finally`: a step that had otherwise succeeded ended
    the build in a traceback. The walk answers both, and it starts from the
    scratch root's own descriptor, so a `tmp_root` re-pointed while the step ran
    does not get to say where the removal lands.
    """
    root_fd = getattr(engine, "tmp_root_fd", None)
    try:
        if root_fd is None:
            parent_fd = dirfd.opendir(os.path.join(engine.tmp_root, *parts[:-1]))
        else:
            parent_fd = dirfd.descend_at(root_fd, parts[:-1])
    except OSError:
        return
    try:
        dirfd.rmtree_at(parent_fd, parts[-1], force=True, on_error=lambda _rel, _exc: None)
    finally:
        os.close(parent_fd)


def _resolve_bind(engine: typing.Any, m: RunMount, n: int, scratch_names: list[tuple[str, ...]]) -> tuple[str, bool]:
    if m.from_:
        from chroot_distro.helpers.build_engine.copy_step import _pull_throwaway_image

        ref_stage = engine.stages.get(m.from_)
        if ref_stage is None:
            # The bind source reaches mount(2) as a path whatever happens, so
            # the pull's descriptor buys nothing here.
            base, pulled_fd = _pull_throwaway_image(engine, m.from_)
            with contextlib.suppress(OSError):
                os.close(pulled_fd)
        else:
            base = ref_stage.rootfs_dir
    else:
        base = engine.build_dir
    base_abs = os.path.abspath(base)
    src_parts = [p for p in m.source.lstrip("/").split("/") if p not in ("", ".")]
    src = _safe_resolve(base_abs, src_parts)
    if src is None or not (src == base_abs or src.startswith(base_abs + os.sep)):
        raise BuildError(f"RUN --mount source '{m.source}' escapes the build context.")
    if not os.path.exists(src):
        raise BuildError(f"RUN --mount source '{m.source}' not found.")
    if not m.readonly:
        # rw bind: writes must not hit the build context / stage rootfs, so
        # bind a scratch copy instead (writes are discarded after the step).
        parts = (f"runmount-rw-{n}",)
        scratch_names.append(parts)
        src = _scratch_copy(src, os.path.join(engine.tmp_root, *parts))
    return src, bool(m.readonly)


def _resolve_cache(
    engine: typing.Any, m: RunMount, n: int, scratch_names: list[tuple[str, ...]], locks: list
) -> tuple[str, bool]:
    from chroot_distro.locking import RunCacheLock

    key = hashlib.sha256((m.id or m.target).encode()).hexdigest()[:16]
    cache_dir = os.path.join(RUN_CACHE_DIR, key)
    os.makedirs(cache_dir, exist_ok=True)
    with contextlib.suppress(OSError):
        os.chmod(cache_dir, m.mode if m.mode is not None else 0o755)
    if m.uid or m.gid:
        with contextlib.suppress(OSError):
            os.chown(cache_dir, m.uid, m.gid)

    if m.sharing == "locked":
        lock = RunCacheLock(key)
        lock.__enter__()
        locks.append(lock)
    elif m.sharing == "private":
        # private = throwaway copy, writes discarded; switch to a
        # persist-back copy if private caches ever need to accumulate.
        parts = (f"runmount-cache-{n}",)
        scratch_names.append(parts)
        return _scratch_copy(cache_dir, os.path.join(engine.tmp_root, *parts)), False
    return cache_dir, False


def _resolve_secret(engine: typing.Any, m: RunMount, scratch_names: list[tuple[str, ...]]) -> tuple[str, bool]:
    src_path = (getattr(engine, "secrets", None) or {}).get(m.id)
    if src_path is None:
        raise BuildError(
            f"RUN --mount=type=secret,id={m.id} requires a matching "
            f"--secret id={m.id}[,src=PATH] on the build command line."
        )
    if not os.path.isfile(src_path):
        raise BuildError(f"--secret id={m.id}: source file '{src_path}' not found.")
    secrets_dir = os.path.join(engine.tmp_root, "secrets")
    os.makedirs(secrets_dir, exist_ok=True)
    tmp_copy = os.path.join(secrets_dir, m.id)
    shutil.copyfile(src_path, tmp_copy)
    os.chmod(tmp_copy, m.mode if m.mode is not None else 0o400)
    if m.uid or m.gid:
        with contextlib.suppress(OSError):
            os.chown(tmp_copy, m.uid, m.gid)
    scratch_names.append(("secrets", m.id))
    return tmp_copy, True


@contextlib.contextmanager
def run_mount_session(
    engine: typing.Any,
    stage: typing.Any,
    mounts: list[RunMount],
    holder: typing.Any = None,
) -> typing.Iterator[dict[str, str]]:
    """Apply *mounts* into the stage rootfs for one RUN step.

    Yields extra environment variables for the child (SSH_AUTH_SOCK).
    Teardown unmounts deepest-last-first, removes tmp secret/scratch
    copies, and releases cache locks, also on step failure.
    """
    if not mounts:
        yield {}
        return

    import chroot_distro.helpers.mount_manager as mount_manager
    from chroot_distro.commands.login.bindings import SpecialMount

    rootfs = stage.rootfs_dir
    extra_env: dict[str, str] = {}
    mounted: list[str] = []
    scratch_names: list[tuple[str, ...]] = []
    locks: list[typing.Any] = []
    created: list[str] = []

    try:
        for n, m in enumerate(mounts):
            target_abs = m.target or ""
            if target_abs and not target_abs.startswith("/"):
                target_abs = os.path.normpath(os.path.join(stage.workdir or "/", target_abs))

            if m.type == "tmpfs":
                host_tgt = _host_target(rootfs, target_abs)  # validates the path
                _record_missing(rootfs, host_tgt, created)
                sm = SpecialMount(
                    fstype="tmpfs",
                    source="tmpfs",
                    target="/" + os.path.relpath(host_tgt, rootfs),
                    options=f"mode={m.mode:o}" if m.mode is not None else "",
                    optional=False,
                )
                mount_manager.apply_special_mount(rootfs, sm, holder=holder)
                mounted.append(host_tgt)
                continue

            if m.type == "bind":
                src, ro = _resolve_bind(engine, m, n, scratch_names)
            elif m.type == "cache":
                src, ro = _resolve_cache(engine, m, n, scratch_names, locks)
            elif m.type == "secret":
                src, ro = _resolve_secret(engine, m, scratch_names)
            else:  # ssh
                sock = (getattr(engine, "ssh_sockets", None) or {}).get(m.id)
                if sock is None:
                    raise BuildError(f"RUN --mount=type=ssh (id={m.id}) requires --ssh on the build command line.")
                if not target_abs:
                    target_abs = f"/run/buildkit/ssh_agent.{n}"
                src, ro = sock, False
                extra_env["SSH_AUTH_SOCK"] = target_abs

            host_tgt = _host_target(rootfs, target_abs)
            _record_missing(rootfs, host_tgt, created)
            mount_manager.safe_mount(src, host_tgt, holder=holder, options="ro" if ro else "")
            mounted.append(host_tgt)

        yield extra_env
    finally:
        for tgt in reversed(mounted):
            with contextlib.suppress(Exception):
                mount_manager.safe_unmount(tgt, holder=holder)
        # Remove mountpoint placeholders we created, deepest-first. rmdir
        # only deletes empty dirs, so anything the RUN step actually wrote
        # into them is kept.
        for path in reversed(created):
            with contextlib.suppress(OSError):
                if os.path.isdir(path) and not os.path.islink(path):
                    os.rmdir(path)
                else:
                    os.remove(path)
        for parts in reversed(scratch_names):
            _remove_scratch(engine, parts)
        for lock in locks:
            lock.release()

# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
"""Compose namespaces plus chroot once, for every command that needs isolation.

`login`, `run` and `build` all want the same setup, so the holder bring-up, the
bind-recursion rules, the special-mount set and the teardown live here rather than
three times over. `login` composes the pieces inline because it also has a PTY, a
richer bind set and session bookkeeping; `build` takes `max_isolation_session` or
`namespace_session` whole.

Three levels, and the difference between them is the mount set, not the namespaces:
the default keeps host mounts and no namespaces at all; `CD_USE_NS` turns the
namespaces on and keeps the default mount set (`namespace_session`, holder not
chrooted); `--isolated` or `CD_USE_ISOLATION` binds nothing from the host and
chroots the holder (`max_isolation_session`). `CD_USE_ISOLATION` wins when both env
vars are set, and `resolve_isolated` is the only place the flag and the env var are
combined. `build` has no CLI flag, so for it the env vars are the whole interface.

What a bind needs is decided by `bind_is_recursive`, and each clause is a kernel or
platform fact, not a preference: /run holds nested socket submounts, /apex is a
tmpfs whose entries are separate mounts with the bionic linker under one of them,
and inside a user namespace a non-recursive bind of /sys or /dev is refused outright
because their locked submounts cannot be split off. A /dev bind is also made rslave
straight away, or the devpts mounted into it next propagates back onto the host /dev.

Failure policy is per source. A bind listed in *best_effort_sources* warns and is
skipped, anything else re-raises, and a missing mount namespace is not an error at
all: both session wrappers yield None so the caller runs unisolated rather than not
at all. The fresh tmpfs /dev under maximum isolation is the same shape, since some
Android kernels deny it under SELinux, and falling back to the container's own empty
/dev directory is still not a host bind.

`safe_hostname` exists because container names may hold underscores and hostnames
may not, so the UTS hostname is filtered rather than the name restricted.
"""

from __future__ import annotations

import contextlib
import logging
import os
from collections.abc import Iterator
from typing import TYPE_CHECKING

from chroot_distro.constants import IS_TERMUX
from chroot_distro.helpers import mount_manager, namespace
from chroot_distro.helpers.namespace import NamespaceError, NamespaceHolder
from chroot_distro.helpers.rootfs import write_resolv_conf
from chroot_distro.message import warn

if TYPE_CHECKING:
    from chroot_distro.helpers.namespace import NamespaceProbeResult

log = logging.getLogger(__name__)

# Same truthy set used for CD_USE_NS so the two env vars behave identically.
_TRUTHY_ENV_VALUES = namespace._TRUTHY_ENV_VALUES

# Android system partitions that must be bound recursively: /apex is a tmpfs
# whose entries are separate nested mounts, and the bionic linker lives under
# it, so a plain bind captures only empty stubs.
_ANDROID_SYS_MOUNTS = frozenset({"/apex", "/system", "/vendor", "/odm", "/product", "/system_ext"})


def use_isolation_env_enabled() -> bool:
    """Return True when ``CD_USE_ISOLATION`` requests maximum isolation."""
    return os.environ.get("CD_USE_ISOLATION", "").strip().lower() in _TRUTHY_ENV_VALUES


def resolve_isolated(args) -> bool:
    """Effective isolation state: the ``--isolated`` flag OR ``CD_USE_ISOLATION``.

    The env var wins even when the flag is absent, so a caller can force
    maximum isolation without touching the command line.
    """
    return bool(getattr(args, "isolated", False)) or use_isolation_env_enabled()


def safe_hostname(name: str) -> str:
    """Return *name* if it is a safe hostname token, else "localhost".

    Container names allow underscores (see names.is_valid_name), which are
    not valid in hostnames and are rejected by some consuming tools. Accept
    only alphanumerics, '-' and '.', with each dot-separated label at most
    63 characters; otherwise fall back to a safe default.
    """
    if not name:
        return "localhost"
    for label in name.split("."):
        if not label or len(label) > 63:
            return "localhost"
        if not all(ch.isalnum() or ch == "-" for ch in label):
            return "localhost"
    return name


# Host pseudo-filesystems that must be bound recursively when a user namespace
# is active: a non-recursive bind of /sys or /dev is rejected by the kernel
# inside a userns (their locked submounts cannot be split off), whereas a
# recursive bind of the whole subtree is permitted.
_USERNS_RECURSIVE_BINDS = frozenset({"/sys", "/dev"})


def bind_is_recursive(src: str, dst_real: str, run_root: str, *, use_userns: bool = False) -> bool:
    """Whether a bind of *src* → *dst_real* must be recursive.

    Recurse for /run and anything under it (nested socket submounts), for the
    WSL lib dir, and for the Android system partitions (nested mounts under a
    tmpfs). *run_root* is ``realpath(rootfs/run)``, computed once by the caller.
    When *use_userns* is set, also recurse for /sys and /dev, since a plain bind of
    those is rejected inside a user namespace.
    """
    is_run = dst_real == run_root or dst_real.startswith(run_root + os.sep)
    is_wsl = src == "/usr/lib/wsl"
    is_android_sys = IS_TERMUX and src in _ANDROID_SYS_MOUNTS
    is_userns_pseudo = use_userns and src in _USERNS_RECURSIVE_BINDS
    return is_run or is_wsl or is_android_sys or is_userns_pseudo


def apply_bind_mounts(
    rootfs: str,
    resolved_binds: list[tuple[str, str]],
    *,
    holder: NamespaceHolder | None = None,
    use_userns: bool = False,
    bind_options: dict[str, str] | None = None,
    best_effort_sources: frozenset[str] = frozenset(),
) -> None:
    """Mount every (source, resolved_target) bind, in order.

    Shared by login and the isolation sessions: recursion rules, stale-/dev
    detection and failure policy in one place. Failures re-raise unless the
    source is in *best_effort_sources* (warn + skip).

    *bind_options* maps realpath(resolved_target) -> mount option string.
    """
    opts_map = bind_options or {}
    run_root = os.path.realpath(os.path.join(rootfs, "run"))
    dev_root = os.path.realpath(os.path.join(rootfs, "dev"))
    for src, dst in resolved_binds:
        dst_real = os.path.realpath(dst)
        try:
            mount_manager.safe_mount(
                src,
                dst,
                holder=holder,
                recursive=bind_is_recursive(src, dst_real, run_root, use_userns=use_userns),
                options=opts_map.get(dst_real, ""),
                # A stale MNT_LOCKED mount can shadow /dev without ptmx;
                # detect and mount over.
                required_child="ptmx" if dst_real == dev_root else "",
            )
        except Exception as exc:
            if src in best_effort_sources:
                warn(f"Skipping optional bind {src} -> {dst}: {exc}")
                continue
            raise
        # Stop send-propagation from the /dev bind, or mounts made inside it
        # next (/dev/pts, devpts) propagate copies back onto the host /dev.
        if holder is None and dst_real == dev_root:
            mount_manager.make_rslave(dst)


def finalize_holder(holder: NamespaceHolder, container_key: str, *, hostname: str) -> None:
    """Record the namespace mode, make mounts private, and set the hostname.

    The steps every isolated session performs immediately after acquiring (or
    reusing) its holder, regardless of how the holder was created.
    """
    namespace.write_isolation_mode(container_key, namespace.ISOLATION_MODE_NAMESPACE)
    if not namespace.make_mount_private(holder):
        # Many Android kernels already provide isolated propagation in the new
        # mount namespace, so failing to set it explicitly is benign.
        log.debug("Could not set mount propagation to private in isolated namespace.")
    # Cosmetic: give the UTS namespace its own hostname; never fatal.
    namespace.set_namespace_hostname(holder, safe_hostname(hostname))


def _ensure_ptmx_symlink(rootfs: str, holder: NamespaceHolder | None) -> None:
    """Ensure ``/dev/ptmx`` is a symlink to the private ``pts/ptmx`` multiplexer.

    Under maximum isolation ``/dev`` is a fresh tmpfs, so ``ptmx`` must point at
    the ``newinstance`` devpts multiplexer. Runs inside the holder's namespaces
    when given, else directly on the host view of the rootfs.
    """
    ptmx_path = os.path.join(rootfs, "dev/ptmx")

    def _relink() -> None:
        if os.path.islink(ptmx_path):
            return
        if os.path.exists(ptmx_path):
            os.remove(ptmx_path)
        os.symlink("pts/ptmx", ptmx_path)

    if holder is not None:
        if holder.call(_relink) is None:
            log.debug("Failed to create ptmx symlink in the holder's namespaces")
        return
    try:
        _relink()
    except OSError as exc:
        log.debug("Failed to create ptmx symlink: %s", exc)


def apply_special_mounts(
    rootfs: str,
    holder: NamespaceHolder | None,
    *,
    isolated: bool,
    max_isolation: bool,
    minimal: bool,
    use_userns: bool = False,
) -> None:
    """Apply the special filesystem mounts (/proc, /sys, /dev, …) into *rootfs*.

    Under maximum isolation, ``/dev`` becomes a fresh private tmpfs populated
    with the minimal device nodes (the host ``/dev`` is never bound), and
    ``/dev/ptmx`` is pointed at the private devpts multiplexer. Runs inside the
    holder's mount namespace when *holder* is given.
    """
    from chroot_distro.commands.login import bindings

    specials = bindings.get_special_mounts(
        rootfs,
        isolated=isolated,
        max_isolation=max_isolation,
        use_userns=use_userns,
        enable_usb=not minimal,
        enable_binfmt=not minimal,
        enable_shm=not minimal,
    )
    for sm in specials:
        is_maxiso_dev = max_isolation and sm.fstype == "tmpfs" and sm.target == "/dev"
        if is_maxiso_dev:
            # Best-effort under max isolation: if the kernel denies the fresh
            # tmpfs (SELinux on some Android kernels), fall back to the
            # container's own empty /dev dir, which is still not a host bind.
            mounted = mount_manager.apply_special_mount(rootfs, sm, holder=holder, force_optional=True)
            if not mounted:
                warn(
                    "Could not mount a fresh tmpfs /dev; using the "
                    "container's own /dev directory (still isolated, no host bind)."
                )
            mount_manager.create_dev_nodes(
                rootfs, bindings.MAX_ISOLATION_DEV_NODES, holder=holder, use_userns=use_userns
            )
        else:
            mount_manager.apply_special_mount(rootfs, sm, holder=holder)

    if max_isolation:
        _ensure_ptmx_symlink(rootfs, holder)


def probe_isolation(*, warn_on_gaps: bool = True) -> NamespaceProbeResult:
    """Probe kernel namespace support, optionally emitting warnings for gaps.

    Thin wrapper over :func:`namespace.probe_and_report_namespaces` so callers
    share the "probe, then warn about missing recommended/enhancement
    namespaces" step. Inspect ``.missing_mandatory`` on the result to decide
    whether isolation can proceed at all.
    """
    result = namespace.probe_and_report_namespaces()
    if not result.missing_mandatory:
        # Stay silent when everything is working; only speak up about gaps
        # (missing recommended/enhancement namespaces, or a user namespace whose
        # in-userns mounts were rejected). No "all good" banner in normal runs.
        has_gaps = result.missing_recommended or result.missing_enhancements or not result.userns_mounts_ok
        if warn_on_gaps and has_gaps:
            namespace.emit_isolation_warnings(result)
    return result


@contextlib.contextmanager
def max_isolation_session(
    container_key: str,
    rootfs: str,
    *,
    minimal: bool = False,
    dist_type: str = "normal",
    hostname: str | None = None,
) -> Iterator[NamespaceHolder | None]:
    """Set up a maximum-isolation namespace holder around *rootfs* and yield it.

    Convenience wrapper that composes the primitives above for callers with no
    richer requirements (currently ``build``): acquire a *chrooted* holder,
    finalize it, write ``/etc/resolv.conf`` so DNS keeps working, bind the
    (max-isolation → empty) host set, then the special mounts.

    Yields the live :class:`NamespaceHolder`, or ``None`` when the kernel lacks
    the mount namespace (the caller should then fall back to a non-isolated
    run). All mounts and the holder are torn down on exit.
    """
    from chroot_distro.commands.login import bindings

    probe_result = probe_isolation()
    if probe_result.missing_mandatory:
        warn(
            "Mount namespace (CLONE_NEWNS) is unavailable on this kernel; "
            "cannot isolate this step. Running without isolation."
        )
        yield None
        return

    use_userns = probe_result.has_userns
    holder: NamespaceHolder | None = None
    try:
        holder = namespace.acquire_holder(container_key, rootfs=rootfs)
        finalize_holder(holder, container_key, hostname=hostname or container_key)

        write_resolv_conf(rootfs)

        # Maximum isolation binds nothing from the host, so this set is
        # normally empty.
        resolved_binds, rslave_targets = bindings.get_bindings(
            rootfs=rootfs,
            minimal=minimal,
            isolated=True,
            max_isolation=True,
            use_namespaces=True,
            use_userns=use_userns,
            dist_type=dist_type,
        )
        with contextlib.suppress(Exception):
            mount_manager.unmount_all(rootfs, holder=holder)

        apply_bind_mounts(rootfs, resolved_binds, holder=holder, use_userns=use_userns)
        for rslave_path in rslave_targets:
            mount_manager.make_rslave(rslave_path, holder=holder)

        apply_special_mounts(rootfs, holder, isolated=True, max_isolation=True, minimal=minimal, use_userns=use_userns)

        yield holder
    except NamespaceError as exc:
        warn(f"Failed to set up isolation: {exc}. Running without isolation.")
        if holder is not None:
            _teardown(container_key, rootfs, holder)
            holder = None
        yield None
    finally:
        if holder is not None:
            _teardown(container_key, rootfs, holder)


@contextlib.contextmanager
def namespace_session(
    container_key: str,
    rootfs: str,
    *,
    minimal: bool = True,
    dist_type: str = "normal",
    hostname: str | None = None,
) -> Iterator[NamespaceHolder | None]:
    """Set up a namespace-only (CD_USE_NS) holder around *rootfs* and yield it.

    Sibling of :func:`max_isolation_session` with the *default* mount set:
    the holder is NOT chrooted, the host binds stay (``isolated=False``),
    and only the namespaces (mount/PID/UTS/IPC) separate the step from the
    host. Yields ``None`` when the kernel lacks the mount namespace so the
    caller can fall back to a plain run.
    """
    from chroot_distro.commands.login import bindings

    probe_result = probe_isolation()
    if probe_result.missing_mandatory:
        warn(
            "Mount namespace (CLONE_NEWNS) is unavailable on this kernel; "
            "cannot namespace this step. Running without namespaces."
        )
        yield None
        return

    use_userns = probe_result.has_userns
    holder: NamespaceHolder | None = None
    try:
        # No rootfs=, so the namespace-only holder is not chrooted, matching
        # login's non-max path.
        holder = namespace.acquire_holder(container_key)
        finalize_holder(holder, container_key, hostname=hostname or container_key)

        write_resolv_conf(rootfs)

        resolved_binds, rslave_targets = bindings.get_bindings(
            rootfs=rootfs,
            minimal=minimal,
            isolated=False,
            max_isolation=False,
            use_namespaces=True,
            use_userns=use_userns,
            dist_type=dist_type,
        )
        with contextlib.suppress(Exception):
            mount_manager.unmount_all(rootfs, holder=holder)

        apply_bind_mounts(
            rootfs,
            resolved_binds,
            holder=holder,
            use_userns=use_userns,
            best_effort_sources=bindings.best_effort_bind_sources(),
        )
        for rslave_path in rslave_targets:
            mount_manager.make_rslave(rslave_path, holder=holder)

        apply_special_mounts(
            rootfs, holder, isolated=False, max_isolation=False, minimal=minimal, use_userns=use_userns
        )

        yield holder
    except NamespaceError as exc:
        warn(f"Failed to set up namespaces: {exc}. Running without namespaces.")
        if holder is not None:
            _teardown(container_key, rootfs, holder)
            holder = None
        yield None
    finally:
        if holder is not None:
            _teardown(container_key, rootfs, holder)


def _teardown(container_key: str, rootfs: str, holder: NamespaceHolder) -> None:
    """Unmount everything in the holder and release it (best-effort)."""
    with contextlib.suppress(Exception):
        mount_manager.unmount_all(rootfs, holder=holder)
    with contextlib.suppress(Exception):
        namespace.release_holder(container_key)
    with contextlib.suppress(Exception):
        namespace.clear_isolation_mode(container_key)

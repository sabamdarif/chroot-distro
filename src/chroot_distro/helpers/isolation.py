"""Shared Linux isolation (maximum-isolation namespace sessions).

This module centralises the "isolation technology" used across ``login``,
``run`` and ``build`` so every command applies the *same* namespace + chroot
setup instead of each reimplementing it.

Two switches request isolation:

* the ``--isolated``/``--isolate`` flag on ``login``/``run`` (→ ``args.isolated``);
* the ``CD_USE_ISOLATION`` environment variable, which forces maximum isolation
  on regardless of the flag.

``CD_USE_ISOLATION`` is the env-var equivalent of ``--isolated`` (maximum
isolation: bind nothing from the host, chroot the namespace holder). It is
distinct from ``CD_USE_NS`` (see :func:`namespace.use_ns_env_enabled`), which
only turns on namespaces while keeping the default mount set. ``build`` honours
both env vars (it has no CLI flag): ``CD_USE_ISOLATION`` → maximum isolation via
:func:`max_isolation_session`, ``CD_USE_NS`` → namespace-only mode via
:func:`namespace_session`; ``CD_USE_ISOLATION`` wins when both are set.

The building blocks below are shared by ``login`` (which composes them inline
with its richer bind set, PTY handling and session bookkeeping) and by the
:func:`max_isolation_session` convenience wrapper used by ``build``. Keeping
them here means the holder bring-up, the special-mount / fresh-``/dev`` logic
and the bind-recursion rules live in exactly one place.
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
    When *use_userns* is set, also recurse for /sys and /dev — a plain bind of
    those is rejected inside a user namespace.
    """
    is_run = dst_real == run_root or dst_real.startswith(run_root + os.sep)
    is_wsl = src == "/usr/lib/wsl"
    is_android_sys = IS_TERMUX and src in _ANDROID_SYS_MOUNTS
    is_userns_pseudo = use_userns and src in _USERNS_RECURSIVE_BINDS
    return is_run or is_wsl or is_android_sys or is_userns_pseudo


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
    if holder is not None:
        is_link = holder.run(["test", "-L", ptmx_path]).returncode == 0
        if not is_link:
            if holder.run(["test", "-e", ptmx_path]).returncode == 0:
                holder.run(["rm", "-f", ptmx_path])
            holder.run(["ln", "-s", "pts/ptmx", ptmx_path], capture_output=True, text=True)
    else:
        try:
            if not os.path.islink(ptmx_path):
                if os.path.exists(ptmx_path):
                    os.remove(ptmx_path)
                os.symlink("pts/ptmx", ptmx_path)
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
            # container's own empty /dev dir — still not a host bind.
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

        # Maximum isolation binds NOTHING from the host; this set is normally
        # empty, but we honour whatever get_bindings returns for completeness.
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

        run_root = os.path.realpath(os.path.join(rootfs, "run"))
        dev_root = os.path.realpath(os.path.join(rootfs, "dev"))
        for src, dst in resolved_binds:
            dst_real = os.path.realpath(dst)
            mount_manager.safe_mount(
                src,
                dst,
                holder=holder,
                recursive=bind_is_recursive(src, dst_real, run_root, use_userns=use_userns),
                required_child="ptmx" if dst_real == dev_root else "",
            )
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
        # No rootfs= : the namespace-only holder is not chrooted (matches
        # login's non-max path).
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

        run_root = os.path.realpath(os.path.join(rootfs, "run"))
        dev_root = os.path.realpath(os.path.join(rootfs, "dev"))
        for src, dst in resolved_binds:
            dst_real = os.path.realpath(dst)
            mount_manager.safe_mount(
                src,
                dst,
                holder=holder,
                recursive=bind_is_recursive(src, dst_real, run_root, use_userns=use_userns),
                required_child="ptmx" if dst_real == dev_root else "",
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

"""Linux namespace isolation for --isolated sessions (Ubuntu-Chroot pattern)."""

from __future__ import annotations

import contextlib
import logging
import os
import signal
import subprocess
import time
from dataclasses import dataclass, field

from chroot_distro.constants import IS_TERMUX, PROGRAM_NAME, RUNTIME_DIR
from chroot_distro.exceptions import ChrootDistroError, MountError
from chroot_distro.syscalls._constants import (
    CLONE_NEWCGROUP,
    CLONE_NEWIPC,
    CLONE_NEWNS,
    CLONE_NEWPID,
    CLONE_NEWUTS,
    MS_PRIVATE,
    MS_REC,
    MS_SLAVE,
    NS_FILE_MAP,
    cli_flags_to_bitmask,
    bitmask_to_cli_flags,
)
from chroot_distro.syscalls._libc import libc_sethostname
from chroot_distro.syscalls.mount import bind_mount, mount_filesystem, set_propagation
from chroot_distro.syscalls.nsenter import (
    check_ns_accessible,
    filter_accessible_namespaces,
    run_in_namespaces,
)
from chroot_distro.syscalls.umount import native_umount
from chroot_distro.syscalls.unshare import (
    create_holder_process,
    probe_namespace_support as _probe_ns_support,
)

log = logging.getLogger(__name__)

# ── Required / optional namespace flags ──────────────────────────────────────
# The pre-flight check is all-or-nothing over _REQUIRED_NS_FLAGS.
_REQUIRED_NS_FLAGS: int = CLONE_NEWPID | CLONE_NEWNS | CLONE_NEWUTS | CLONE_NEWIPC
# Cgroup NS is opportunistic (excluded on Termux/Android entirely).
_OPTIONAL_NS_FLAGS: int = 0 if IS_TERMUX else CLONE_NEWCGROUP
_ALL_PROBE_FLAGS: int = _REQUIRED_NS_FLAGS | _OPTIONAL_NS_FLAGS

# Backward-compat: the old code stored holder flags as CLI strings.
# We keep the same _REQUIRED_PROBE_FLAGS tuple for probe_namespace_support()
# callers that still use the string-based API.
_REQUIRED_PROBE_FLAGS = ("--pid", "--mount", "--uts", "--ipc")
_OPTIONAL_PROBE_FLAGS: tuple[str, ...] = () if IS_TERMUX else ("--cgroup",)

ISOLATION_MODE_NAMESPACE = "namespace"
ISOLATION_MODE_HOST = "host"

_TRUTHY_ENV_VALUES = frozenset({"1", "true", "yes", "on"})

# Android's toybox sleep rejects "infinity"; use a large finite value.
HOLDER_SLEEP_SECONDS = "2147483647"
_LEGACY_HOLDER_SLEEP_ARG = "infinity"
_HOLDER_SLEEP_ARGS = frozenset({HOLDER_SLEEP_SECONDS, _LEGACY_HOLDER_SLEEP_ARG})


def use_ns_env_enabled() -> bool:
    """Return True when CD_USE_NS requests full namespace isolation."""
    return os.environ.get("CD_USE_NS", "").strip().lower() in _TRUTHY_ENV_VALUES


def should_use_namespaces(isolated: bool) -> bool:
    """Decide whether to set up Linux namespace isolation."""
    return bool(isolated) or use_ns_env_enabled()


class NamespaceError(ChrootDistroError):
    """Raised when namespace setup or execution fails."""


# ── State file helpers ───────────────────────────────────────────────────────

def _container_data_dir(container_name: str) -> str:
    data_dir = os.path.join(RUNTIME_DIR, "data", container_name)
    os.makedirs(data_dir, exist_ok=True)
    return data_dir


def _holder_pid_file(container_name: str) -> str:
    return os.path.join(_container_data_dir(container_name), "holder.pid")


def _holder_flags_file(container_name: str) -> str:
    return os.path.join(_container_data_dir(container_name), "holder.flags")


def _isolation_mode_file(container_name: str) -> str:
    return os.path.join(_container_data_dir(container_name), "isolation.mode")


def _holder_maxiso_file(container_name: str) -> str:
    return os.path.join(_container_data_dir(container_name), "holder.maxiso")


def holder_is_max_isolation(container_name: str) -> bool:
    """Return True if the live holder was created chrooted (max isolation)."""
    return os.path.isfile(_holder_maxiso_file(container_name))


# ── Namespace probing (native — no subprocess) ──────────────────────────────


def probe_unshare_flags() -> int:
    """Return a bitmask of supported namespace flags; mount NS is required.

    Replaces the old string-list based probe_unshare_flags() that shelled
    out to the ``unshare`` binary.
    """
    supported = _probe_ns_support(_ALL_PROBE_FLAGS)

    if not (supported & CLONE_NEWNS):
        raise NamespaceError("Mount namespace not supported by this kernel (unshare CLONE_NEWNS failed).")
    return supported


def probe_namespace_support(flags: tuple[str, ...] = _REQUIRED_PROBE_FLAGS) -> list[str]:
    """Return the subset of *flags* the kernel does NOT support.

    Backward-compatible API that accepts CLI-style flag strings.
    An empty list means every requested namespace is available.
    """
    bitmask = cli_flags_to_bitmask(list(flags))
    supported = _probe_ns_support(bitmask)
    missing: list[str] = []
    for flag in flags:
        clone_bit = cli_flags_to_bitmask([flag])
        if not (supported & clone_bit):
            missing.append(flag)
    return missing


# ── Isolation mode persistence ───────────────────────────────────────────────

def read_isolation_mode(container_name: str) -> str | None:
    path = _isolation_mode_file(container_name)
    if not os.path.isfile(path):
        return None
    try:
        with open(path) as fh:
            mode = fh.read().strip()
    except OSError:
        return None
    return mode or None


def write_isolation_mode(container_name: str, mode: str) -> None:
    with open(_isolation_mode_file(container_name), "w") as fh:
        fh.write(mode)


def clear_isolation_mode(container_name: str) -> None:
    with contextlib.suppress(OSError):
        os.remove(_isolation_mode_file(container_name))


# ── Process helpers ──────────────────────────────────────────────────────────

def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def _get_process_start_time(pid: int) -> float | None:
    try:
        return os.stat(f"/proc/{pid}").st_mtime
    except OSError:
        return None


def _read_holder_pid(container_name: str) -> int | None:
    path = _holder_pid_file(container_name)
    if not os.path.isfile(path):
        return None

    pid: int | None = None
    start_time: float | None = None
    is_custom = False
    try:
        with open(path) as fh:
            lines = fh.read().splitlines()
            if lines:
                pid = int(lines[0].strip())
                if len(lines) > 1 and lines[1].strip():
                    start_time = float(lines[1].strip())
                if len(lines) > 2 and lines[2].strip() == "custom":
                    is_custom = True
    except (OSError, ValueError):
        _remove_holder_state(container_name)
        return None

    if pid is None:
        _remove_holder_state(container_name)
        return None

    is_valid = True
    if not _pid_alive(pid):
        is_valid = False
    elif start_time is not None:
        curr_start_time = _get_process_start_time(pid)
        if curr_start_time is None or abs(curr_start_time - start_time) > 0.1:
            is_valid = False
    elif not is_custom and not _is_sleep_infinity_holder(pid):
        is_valid = False

    if not is_valid:
        _remove_holder_state(container_name)
        return None

    return pid


def _read_holder_flags(container_name: str) -> int:
    """Read the holder's namespace flags as a bitmask.

    Handles backward compatibility: old state files store CLI-style strings
    (``--mount --pid ...``), new ones store hex bitmasks (``0x2c020000``).
    """
    path = _holder_flags_file(container_name)
    if not os.path.isfile(path):
        return CLONE_NEWNS  # minimal default
    try:
        with open(path) as fh:
            raw = fh.read().strip()
    except OSError:
        return CLONE_NEWNS

    if not raw:
        return CLONE_NEWNS

    # New format: hex bitmask
    if raw.startswith("0x"):
        try:
            return int(raw, 16)
        except ValueError:
            return CLONE_NEWNS

    # Old format: space-separated CLI flags (backward compat)
    return cli_flags_to_bitmask(raw.split()) or CLONE_NEWNS


def _write_holder_flags(container_name: str, flags: int) -> None:
    """Write holder flags in the new hex bitmask format."""
    with open(_holder_flags_file(container_name), "w") as fh:
        fh.write(f"0x{flags:08x}")


def _remove_holder_state(container_name: str) -> None:
    for path in (
        _holder_pid_file(container_name),
        _holder_flags_file(container_name),
        _holder_maxiso_file(container_name),
    ):
        with contextlib.suppress(OSError):
            os.remove(path)


def _proc_comm(pid: int) -> str:
    try:
        with open(f"/proc/{pid}/comm") as fh:
            return fh.read().strip()
    except OSError:
        return ""


def _is_sleep_infinity_holder(pid: int) -> bool:
    if _proc_comm(pid) != "sleep":
        return False
    try:
        with open(f"/proc/{pid}/cmdline") as fh:
            cmdline = fh.read().replace("\0", " ")
    except OSError:
        return False
    return bool(_HOLDER_SLEEP_ARGS.intersection(cmdline.split()))


def _read_host_child_pids(pid: int) -> list[int]:
    children: list[int] = []
    task_dir = f"/proc/{pid}/task"
    if not os.path.isdir(task_dir):
        return children
    for tid in os.listdir(task_dir):
        children_path = os.path.join(task_dir, tid, "children")
        try:
            with open(children_path) as fh:
                for token in fh.read().split():
                    if token.isdigit():
                        children.append(int(token))
        except OSError:
            continue
    return children


# Maps each unshare long flag to the /proc/<pid>/ns/<name> entry.
_FLAG_TO_NS_FILE = {
    "--mount": "mnt",
    "--uts": "uts",
    "--ipc": "ipc",
    "--pid": "pid",
    "--cgroup": "cgroup",
    "--net": "net",
    "--user": "user",
}


def filter_flags_by_ns_files(pid: int, flags: list[str]) -> list[str]:
    """Return *flags* keeping only those whose /proc/<pid>/ns/<name> exists.

    Backward-compatible API for callers still using CLI-flag strings.
    """
    kept: list[str] = []
    for flag in flags:
        ns_name = _FLAG_TO_NS_FILE.get(flag)
        if ns_name is None:
            kept.append(flag)
            continue
        ns_path = f"/proc/{pid}/ns/{ns_name}"
        try:
            fd = os.open(ns_path, os.O_RDONLY)
        except OSError as exc:
            log.debug("Dropping namespace flag %s: cannot open %s (%s)", flag, ns_path, exc)
            continue
        os.close(fd)
        kept.append(flag)
    return kept


# ── NamespaceHolder ──────────────────────────────────────────────────────────

@dataclass
class NamespaceHolder:
    """A long-lived process holding mount/PID/UTS/IPC namespaces."""

    pid: int
    ns_flags: int  # CLONE_NEW* bitmask
    container_name: str
    proc: subprocess.Popen | None = None

    # Kept for backward compat — callers that used nsenter_flags as
    # a list of CLI strings can still access them via this property.
    @property
    def nsenter_flags(self) -> list[str]:
        return bitmask_to_cli_flags(self.ns_flags)

    def _live_ns_flags(self) -> int:
        """Return ns_flags minus any namespace not openable right now."""
        live = filter_accessible_namespaces(self.pid, self.ns_flags)
        # Mount NS is essential: keep it even if the probe is inconclusive.
        if self.ns_flags & CLONE_NEWNS:
            live |= CLONE_NEWNS
        return live

    def run_argv(self, cmd: list[str]) -> list[str]:
        """Build a command that would run *cmd* inside this holder's namespaces.

        .. deprecated::
            Prefer :meth:`run` which enters namespaces natively.
            This method is kept for callers that need the raw argv
            (e.g. for os.execvp).
        """
        # Build the equivalent nsenter-style argv using native nsenter.
        # This is only used as a fallback or for display purposes.
        flags = self._live_ns_flags()
        ns_args: list[str] = []
        for bit, name in NS_FILE_MAP.items():
            if flags & bit:
                ns_args.extend(["--" + ("mount" if name == "mnt" else name)])
        return ["nsenter", "--target", str(self.pid), *ns_args, "--", *cmd]

    def run(self, cmd: list[str], **kwargs) -> subprocess.CompletedProcess:
        """Execute *cmd* inside this holder's namespaces.

        Uses native setns(2) via run_in_namespaces instead of spawning
        the nsenter binary.
        """
        flags = self._live_ns_flags()
        capture = kwargs.pop("capture_output", False)
        text = kwargs.pop("text", False)
        timeout = kwargs.pop("timeout", None)
        check = kwargs.pop("check", False)
        env = kwargs.pop("env", None)
        result = run_in_namespaces(
            self.pid,
            flags,
            cmd,
            capture_output=capture,
            text=text,
            timeout=timeout,
            env=env,
        )
        if check and result.returncode != 0:
            raise subprocess.CalledProcessError(
                result.returncode, cmd, result.stdout, result.stderr
            )
        return result

    def is_mounted(self, target: str) -> bool:
        """Check if *target* is a mount point inside this holder's namespaces."""
        try:
            result = self.run(["mountpoint", "-q", target], capture_output=True)
        except OSError:
            return False
        return result.returncode == 0

    def get_proc_mounts(self) -> str:
        """Read /proc/mounts from inside this holder's namespaces."""
        result = self.run(["cat", "/proc/mounts"], capture_output=True, text=True)
        if result.returncode != 0:
            return ""
        return result.stdout or ""

    # ── Native mount/umount operations inside the holder's namespaces ──

    def do_bind_mount(
        self,
        source: str,
        target: str,
        *,
        recursive: bool = False,
        options: str = "",
    ) -> None:
        """Bind-mount source to target inside this holder's namespaces."""
        flags = self._live_ns_flags()
        readonly = "ro" in options.split(",") if options else False
        clean_opts = ",".join(o for o in options.split(",") if o and o != "ro") if options else ""

        child_pid = os.fork()
        if child_pid == 0:
            try:
                from chroot_distro.syscalls.nsenter import enter_namespaces
                enter_namespaces(self.pid, flags)
                bind_mount(source, target, recursive=recursive, readonly=readonly, options=clean_opts)
                os._exit(0)
            except Exception as exc:
                import sys
                try:
                    sys.stderr.write(f"do_bind_mount: {exc}\n")
                    sys.stderr.flush()
                except Exception:
                    pass
                os._exit(1)

        _, status = os.waitpid(child_pid, 0)
        if os.WIFEXITED(status) and os.WEXITSTATUS(status) != 0:
            raise MountError(f"Bind mount {source} -> {target} failed in namespace")
        if os.WIFSIGNALED(status):
            raise MountError(f"Bind mount {source} -> {target} killed by signal {os.WTERMSIG(status)}")

    def do_umount(self, target: str, *, lazy: bool = False) -> None:
        """Unmount target inside this holder's namespaces."""
        flags = self._live_ns_flags()
        child_pid = os.fork()
        if child_pid == 0:
            try:
                from chroot_distro.syscalls.nsenter import enter_namespaces
                enter_namespaces(self.pid, flags)
                native_umount(target, lazy=lazy)
                os._exit(0)
            except Exception:
                # Try lazy unmount as fallback
                if not lazy:
                    try:
                        native_umount(target, lazy=True)
                        os._exit(0)
                    except Exception:
                        pass
                os._exit(1)

        _, status = os.waitpid(child_pid, 0)
        if os.WIFEXITED(status) and os.WEXITSTATUS(status) != 0:
            raise MountError(f"Unmount {target} failed in namespace")

    def do_mount_filesystem(
        self,
        source: str,
        target: str,
        fstype: str,
        *,
        options: str = "",
    ) -> None:
        """Mount a filesystem inside this holder's namespaces."""
        flags = self._live_ns_flags()
        child_pid = os.fork()
        if child_pid == 0:
            try:
                from chroot_distro.syscalls.nsenter import enter_namespaces
                enter_namespaces(self.pid, flags)
                mount_filesystem(source, target, fstype, options=options)
                os._exit(0)
            except Exception as exc:
                import sys
                try:
                    sys.stderr.write(f"do_mount_filesystem: {exc}\n")
                    sys.stderr.flush()
                except Exception:
                    pass
                os._exit(1)

        _, status = os.waitpid(child_pid, 0)
        if os.WIFEXITED(status) and os.WEXITSTATUS(status) != 0:
            raise OSError(f"mount -t {fstype} {source} {target} failed in namespace")
        if os.WIFSIGNALED(status):
            raise OSError(f"mount -t {fstype} killed by signal {os.WTERMSIG(status)}")

    def do_set_propagation(self, target: str, propagation: int) -> None:
        """Set mount propagation inside this holder's namespaces."""
        flags = self._live_ns_flags()
        child_pid = os.fork()
        if child_pid == 0:
            try:
                from chroot_distro.syscalls.nsenter import enter_namespaces
                enter_namespaces(self.pid, flags)
                set_propagation(target, propagation)
                os._exit(0)
            except Exception:
                os._exit(1)

        _, status = os.waitpid(child_pid, 0)
        if os.WIFEXITED(status) and os.WEXITSTATUS(status) != 0:
            raise OSError(f"set_propagation({target}, {propagation:#x}) failed in namespace")


# ── Holder lifecycle ─────────────────────────────────────────────────────────

def get_live_holder(container_name: str) -> NamespaceHolder | None:
    """Return an active holder for the container, or None."""
    pid = _read_holder_pid(container_name)
    if pid is None:
        return None
    flags = _read_holder_flags(container_name)
    # Drop any namespace whose /proc/<pid>/ns/<name> file is not openable.
    flags = filter_accessible_namespaces(pid, flags)
    if not (flags & CLONE_NEWNS):
        log.debug("Holder %d has no accessible mount namespace; treating as dead", pid)
        _remove_holder_state(container_name)
        return None
    return NamespaceHolder(
        pid=pid,
        ns_flags=flags,
        container_name=container_name,
    )


def _snapshot_sleep_infinity_pids() -> set[int]:
    pids: set[int] = set()
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        pid = int(entry)
        if _is_sleep_infinity_holder(pid):
            pids.add(pid)
    return pids


def _snapshot_all_pids() -> set[int]:
    pids: set[int] = set()
    try:
        for entry in os.listdir("/proc"):
            if entry.isdigit():
                pids.add(int(entry))
    except OSError:
        pass
    return pids


def _is_custom_holder(pid: int, pipe_r: int) -> bool:
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as fh:
            cmdline = fh.read().decode("utf-8", errors="ignore").replace("\0", " ")
    except OSError:
        return False
    return f"os.read({pipe_r}, 1)" in cmdline


def _descendant_sleep_holders(launcher_pid: int, max_depth: int = 4) -> list[int]:
    """Return ``sleep infinity`` holders reachable from *launcher_pid*."""
    found: list[int] = []
    seen: set[int] = {launcher_pid}
    frontier = [launcher_pid]
    depth = 0
    while frontier and depth <= max_depth:
        next_frontier: list[int] = []
        for pid in frontier:
            if pid != launcher_pid and _is_sleep_infinity_holder(pid) and pid not in found:
                found.append(pid)
            for child_pid in _read_host_child_pids(pid):
                if child_pid not in seen:
                    seen.add(child_pid)
                    next_frontier.append(child_pid)
        frontier = next_frontier
        depth += 1
    return found


def _pick_new_holder_pid(before: set[int], launcher_pid: int | None = None) -> int | None:
    if launcher_pid is not None:
        if launcher_pid not in before and _is_sleep_infinity_holder(launcher_pid):
            return launcher_pid
        descendants = [pid for pid in _descendant_sleep_holders(launcher_pid) if pid not in before]
        if descendants:
            if len(descendants) == 1:
                return descendants[0]
            return min(descendants, key=lambda pid: os.stat(f"/proc/{pid}").st_mtime)

    candidates = [pid for pid in _snapshot_sleep_infinity_pids() if pid not in before]
    if not candidates:
        return None
    if len(candidates) == 1:
        return candidates[0]
    return min(candidates, key=lambda pid: os.stat(f"/proc/{pid}").st_mtime)


def _create_holder(
    container_name: str,
    flags: int,
    holder_cmd: list[str] | None = None,
    pipe_r: int | None = None,
    env: dict | None = None,
    rootfs: str | None = None,
) -> NamespaceHolder:
    """Create a new namespace holder process.

    When *holder_cmd* is given (custom foreground holder), we still use
    subprocess.Popen with the unshare binary for that code path to
    preserve the pipe-sync protocol. For the normal (sleep-based) and
    max-isolation (chrooted) holders, we use the native
    create_holder_process() via ctypes.
    """
    pid_file = _holder_pid_file(container_name)
    _remove_holder_state(container_name)

    before_pids = _snapshot_all_pids()
    before_sleep = _snapshot_sleep_infinity_pids()

    # ── Custom holder command path (subprocess-based, preserves pipe sync) ──
    if holder_cmd:
        return _create_holder_subprocess(
            container_name, flags, holder_cmd, pipe_r, env, before_pids
        )

    # ── Native holder path (no subprocess) ──
    self_chroot_holder = bool(rootfs)

    try:
        # Use the native create_holder_process which forks+unshares directly.
        holder_pid = create_holder_process(
            flags,
            rootfs=rootfs,
        )
    except (OSError, RuntimeError) as exc:
        raise NamespaceError(
            "Failed to create the isolation namespace holder. "
            f"Error: {exc}. "
            "Isolation requires root with CAP_SYS_ADMIN and kernel support "
            "for the mount/PID/UTS/IPC namespaces; some Android kernels "
            "restrict this."
        ) from exc

    # Verify the holder is alive.
    if not _pid_alive(holder_pid):
        _remove_holder_state(container_name)
        raise NamespaceError("Namespace holder process exited immediately after creation.")

    # Filter to only accessible namespaces.
    flags = filter_accessible_namespaces(holder_pid, flags)
    if not (flags & CLONE_NEWNS):
        with contextlib.suppress(OSError):
            os.kill(holder_pid, signal.SIGKILL)
        _remove_holder_state(container_name)
        raise NamespaceError(
            f"Namespace holder PID {holder_pid} exposes no mount namespace "
            "(/proc/<pid>/ns/mnt missing); isolation cannot proceed."
        )

    # Persist state.
    start_time = _get_process_start_time(holder_pid)
    with open(pid_file, "w") as fh:
        if start_time is not None:
            fh.write(f"{holder_pid}\n{start_time}\n")
        else:
            fh.write(f"{holder_pid}\n")
        if self_chroot_holder:
            fh.write("custom\n")

    _write_holder_flags(container_name, flags)

    if self_chroot_holder:
        with open(_holder_maxiso_file(container_name), "w") as fh:
            fh.write("1")

    return NamespaceHolder(
        pid=holder_pid,
        ns_flags=flags,
        container_name=container_name,
    )


def _create_holder_subprocess(
    container_name: str,
    flags: int,
    holder_cmd: list[str],
    pipe_r: int | None,
    env: dict | None,
    before_pids: set[int],
) -> NamespaceHolder:
    """Create a holder with a custom foreground command via subprocess.

    This path is kept for the case where the caller provides a custom
    holder_cmd with pipe-based synchronization.
    """
    import shutil
    from chroot_distro.constants import TERMUX_PREFIX

    def _resolve_unshare() -> str:
        if IS_TERMUX:
            termux_unshare = os.path.join(TERMUX_PREFIX, "bin", "unshare")
            if os.path.isfile(termux_unshare):
                return termux_unshare
        resolved = shutil.which("unshare")
        if not resolved:
            raise NamespaceError("Required executable 'unshare' not found.")
        return resolved

    unshare = _resolve_unshare()
    pid_file = _holder_pid_file(container_name)
    cli_flags = bitmask_to_cli_flags(flags)

    assert pipe_r is not None
    python_script = (
        "import os, sys\n"
        f"data = os.read({pipe_r}, 1)\n"
        f"os.close({pipe_r})\n"
        "if data == b'\\n':\n"
        "    os.execvp(sys.argv[1], sys.argv[1:])\n"
    )
    unshare_argv = [unshare]
    if flags & CLONE_NEWPID:
        unshare_argv.append("--fork")
    unshare_argv.extend(cli_flags)
    unshare_argv.extend(["python3", "-c", python_script, *holder_cmd])

    popen_kwargs: dict = {}
    if pipe_r is not None:
        popen_kwargs["pass_fds"] = (pipe_r,)
    if env is not None:
        popen_kwargs["env"] = env

    proc = subprocess.Popen(unshare_argv, **popen_kwargs)

    success = False
    host_pid: int | None = None
    try:
        for _ in range(250):
            children = _read_host_child_pids(proc.pid)
            if children:
                host_pid = children[0]
                break
            # Fallback scan
            for pid in _snapshot_all_pids() - before_pids:
                if _is_custom_holder(pid, pipe_r):
                    host_pid = pid
                    break
            if host_pid is not None:
                break
            if proc.poll() is not None and proc.returncode not in (0, None):
                break
            time.sleep(0.02)

        if host_pid is None:
            raise NamespaceError("Failed to locate custom namespace holder process.")

        # Filter accessible namespaces.
        flags = filter_accessible_namespaces(host_pid, flags)

        start_time = _get_process_start_time(host_pid)
        with open(pid_file, "w") as fh:
            if start_time is not None:
                fh.write(f"{host_pid}\n{start_time}\n")
            else:
                fh.write(f"{host_pid}\n")
            fh.write("custom\n")

        _write_holder_flags(container_name, flags)
        success = True

    finally:
        if not success:
            with contextlib.suppress(OSError):
                proc.kill()
            if host_pid is not None:
                with contextlib.suppress(OSError):
                    os.kill(host_pid, signal.SIGKILL)
            _remove_holder_state(container_name)

    assert host_pid is not None
    return NamespaceHolder(
        pid=host_pid,
        ns_flags=flags,
        container_name=container_name,
        proc=proc,
    )


def acquire_holder(
    container_name: str,
    holder_cmd: list[str] | None = None,
    pipe_r: int | None = None,
    env: dict | None = None,
    rootfs: str | None = None,
) -> NamespaceHolder:
    """Reuse or create a namespace holder for the container."""
    existing = get_live_holder(container_name)
    if existing is not None:
        return existing
    flags = probe_unshare_flags()
    return _create_holder(
        container_name, flags, holder_cmd=holder_cmd, pipe_r=pipe_r, env=env, rootfs=rootfs
    )


def release_holder(container_name: str) -> None:
    """Kill the namespace holder and remove state files."""
    try:
        pid = _read_holder_pid(container_name)
        if pid is not None:
            with contextlib.suppress(OSError):
                os.kill(pid, signal.SIGTERM)
            for _ in range(10):
                if not _pid_alive(pid):
                    break
                time.sleep(0.05)
            if _pid_alive(pid):
                with contextlib.suppress(OSError):
                    os.kill(pid, signal.SIGKILL)
    finally:
        _remove_holder_state(container_name)


def make_mount_private(holder: NamespaceHolder) -> bool:
    """Set mount propagation private inside the holder's mount namespace.

    Uses native syscalls instead of running ``mount --make-rprivate /``.
    Falls back through rprivate → private → rslave.
    """
    for propagation in (MS_REC | MS_PRIVATE, MS_PRIVATE, MS_REC | MS_SLAVE):
        try:
            holder.do_set_propagation("/", propagation)
            return True
        except OSError:
            log.debug("set_propagation(/, %#x) failed in holder", propagation, exc_info=True)
    return False


def set_namespace_hostname(holder: NamespaceHolder, hostname: str) -> bool:
    """Set *hostname* inside the holder's UTS namespace (best-effort).

    Uses native sethostname(2) via setns into the holder's UTS namespace.
    """
    if not hostname:
        return False
    flags = _read_holder_flags(holder.container_name)
    if not (flags & CLONE_NEWUTS):
        log.debug("UTS namespace not held; skipping sethostname for %s", hostname)
        return False

    # Fork, enter the holder's namespaces, and call sethostname.
    child_pid = os.fork()
    if child_pid == 0:
        try:
            from chroot_distro.syscalls.nsenter import enter_namespaces
            enter_namespaces(holder.pid, holder._live_ns_flags())
            libc_sethostname(hostname)
            os._exit(0)
        except Exception:
            os._exit(1)

    _, status = os.waitpid(child_pid, 0)
    if os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0:
        return True

    log.debug("Native sethostname failed; trying hostname binary fallback")
    # Fallback: use the hostname binary inside the namespace.
    try:
        result = holder.run(["hostname", hostname], capture_output=True, text=True)
        if result.returncode == 0:
            return True
    except OSError:
        pass

    # Last resort: write to /proc/sys/kernel/hostname.
    try:
        result = holder.run(
            ["sh", "-c", f"printf %s {hostname!r} > /proc/sys/kernel/hostname"],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            return True
    except OSError:
        pass
    return False


def check_isolation_conflicts(
    container_name: str,
    *,
    use_namespaces: bool,
    host_mounts_exist: bool,
) -> None:
    """Raise NamespaceError when isolated and non-isolated modes would mix."""
    mode = read_isolation_mode(container_name)
    live_holder = get_live_holder(container_name)

    if use_namespaces:
        if mode == ISOLATION_MODE_HOST and host_mounts_exist:
            raise NamespaceError(
                f"Container '{container_name}' has active mounts in the host mount namespace. "
                f"Run '{PROGRAM_NAME} unmount {container_name}' before using --isolated."
            )
        if mode == ISOLATION_MODE_HOST and not host_mounts_exist:
            clear_isolation_mode(container_name)
    else:
        if live_holder is not None or mode == ISOLATION_MODE_NAMESPACE:
            raise NamespaceError(
                f"Container '{container_name}' is in isolated namespace mode. "
                f"Use --isolated or run '{PROGRAM_NAME} unmount {container_name}' first."
            )

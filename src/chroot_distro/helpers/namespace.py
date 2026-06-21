"""Linux namespace isolation for --isolated sessions (Ubuntu-Chroot pattern)."""

from __future__ import annotations

import contextlib
import logging
import os
import shutil
import signal
import subprocess
import time
from dataclasses import dataclass

from chroot_distro.constants import IS_TERMUX, PROGRAM_NAME, RUNTIME_DIR, TERMUX_PREFIX
from chroot_distro.exceptions import ChrootDistroError

log = logging.getLogger(__name__)

# Namespaces that must all be available for isolation to be acquired. The
# pre-flight check in command_login is all-or-nothing over this set, so it is
# kept to the widely supported namespaces; missing any of them means a full
# fall back to host mode rather than a half-isolated session.
_REQUIRED_PROBE_FLAGS = ("--pid", "--mount", "--uts", "--ipc")
# The cgroup namespace is acquired opportunistically: it is added to the
# holder when the kernel supports it (probe_unshare_flags drops unsupported
# flags), but it is NOT part of the strict pre-check because several Android
# kernels lack cgroupns and we still want pid/mount/uts/ipc isolation there.
_OPTIONAL_PROBE_FLAGS = ("--cgroup",)
_PROBE_FLAGS = _REQUIRED_PROBE_FLAGS + _OPTIONAL_PROBE_FLAGS
_LONG_TO_SHORT = {
    "--mount": "-m",
    "--uts": "-u",
    "--ipc": "-i",
    "--pid": "-p",
    "--cgroup": "-C",
}

ISOLATION_MODE_NAMESPACE = "namespace"
ISOLATION_MODE_HOST = "host"

# Truthy spellings accepted for the CD_USE_NS environment variable.
_TRUTHY_ENV_VALUES = frozenset({"1", "true", "yes", "on"})


def use_ns_env_enabled() -> bool:
    """Return True when CD_USE_NS requests full namespace isolation.

    CD_USE_NS turns on the same PID/UTS/IPC/mount namespace isolation that
    ``--isolated`` uses, but *without* skipping any of the default bind
    mounts. Accepts ``1``/``true``/``yes``/``on`` (case-insensitive).
    """
    return os.environ.get("CD_USE_NS", "").strip().lower() in _TRUTHY_ENV_VALUES


def should_use_namespaces(isolated: bool) -> bool:
    """Decide whether to set up Linux namespace isolation.

    Namespaces are used when the user passes ``--isolated`` (which also
    skips the extra host mounts) or when ``CD_USE_NS`` is set (which keeps
    every default mount and only adds namespace isolation).
    """
    return bool(isolated) or use_ns_env_enabled()

# Android's toybox/toolbox `sleep` rejects the GNU coreutils `infinity`
# keyword ("sleep: Not a number 'infinity'") and aborts immediately, which
# tears down the namespace holder the moment it is created. Use a large
# finite duration (~68 years) that both coreutils and toybox accept.
HOLDER_SLEEP_SECONDS = "2147483647"
# Historical sentinel; still recognised so holders created by older versions
# that are kept alive across an upgrade continue to be detected.
_LEGACY_HOLDER_SLEEP_ARG = "infinity"
_HOLDER_SLEEP_ARGS = frozenset({HOLDER_SLEEP_SECONDS, _LEGACY_HOLDER_SLEEP_ARG})


class NamespaceError(ChrootDistroError):
    """Raised when namespace setup or execution fails."""


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


def _resolve_unshare() -> str:
    if IS_TERMUX:
        termux_unshare = os.path.join(TERMUX_PREFIX, "bin", "unshare")
        if os.path.isfile(termux_unshare):
            return termux_unshare
    resolved = shutil.which("unshare")
    if not resolved:
        raise NamespaceError("Required executable 'unshare' not found on the system. Please ensure it is in your PATH.")
    return resolved


def _resolve_nsenter() -> str:
    if IS_TERMUX:
        termux_nsenter = os.path.join(TERMUX_PREFIX, "bin", "nsenter")
        if os.path.isfile(termux_nsenter):
            return termux_nsenter
    resolved = shutil.which("nsenter")
    if not resolved:
        raise NamespaceError("Required executable 'nsenter' not found on the system. Please ensure it is in your PATH.")
    return resolved


def _nsenter_supports_long_flags(nsenter: str) -> bool:
    try:
        result = subprocess.run(
            [nsenter, "--help"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    output = (result.stdout or "") + (result.stderr or "")
    return "--mount" in output


def long_flags_to_nsenter(flags: list[str], *, use_long: bool) -> list[str]:
    """Translate unshare long flags to nsenter argv tokens."""
    if use_long:
        return list(flags)
    return [_LONG_TO_SHORT[f] for f in flags if f in _LONG_TO_SHORT]


def probe_unshare_flags() -> list[str]:
    """Return supported unshare flags; mount namespace is required."""
    unshare = _resolve_unshare()
    supported: list[str] = []
    for flag in _PROBE_FLAGS:
        try:
            result = subprocess.run(
                [unshare, flag, "true"],
                capture_output=True,
                timeout=5,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            continue
        if result.returncode == 0:
            supported.append(flag)

    if "--mount" not in supported:
        raise NamespaceError("Mount namespace not supported by this kernel (unshare --mount failed).")
    return supported


def probe_namespace_support(flags: tuple[str, ...] = _REQUIRED_PROBE_FLAGS) -> list[str]:
    """Return the subset of *flags* the kernel does NOT support.

    Probes each flag with `unshare <flag> true` without entering any
    namespace in the caller. An empty list means every requested namespace
    is available, so isolation can be acquired atomically; a non-empty list
    means the caller must fall back to full host mode (acquire none of
    them) rather than a half-isolated session.
    """
    try:
        unshare = _resolve_unshare()
    except NamespaceError:
        return list(flags)
    missing: list[str] = []
    for flag in flags:
        try:
            result = subprocess.run(
                [unshare, flag, "true"],
                capture_output=True,
                timeout=5,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            missing.append(flag)
            continue
        if result.returncode != 0:
            missing.append(flag)
    return missing


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


def _read_holder_flags(container_name: str) -> list[str]:
    path = _holder_flags_file(container_name)
    if not os.path.isfile(path):
        return ["--mount"]
    try:
        with open(path) as fh:
            flags = fh.read().split()
    except OSError:
        return ["--mount"]
    return flags or ["--mount"]


def _remove_holder_state(container_name: str) -> None:
    for path in (_holder_pid_file(container_name), _holder_flags_file(container_name)):
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


def _snapshot_sleep_infinity_pids() -> set[int]:
    pids: set[int] = set()
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        pid = int(entry)
        if _is_sleep_infinity_holder(pid):
            pids.add(pid)
    return pids


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
    """Return ``sleep infinity`` holders reachable from *launcher_pid*.

    ``unshare --pid --fork`` re-parents the ``sleep`` process one or more
    levels below the launched ``unshare``. Walk the process-tree descendants
    (via ``/proc/<pid>/task/*/children``) breadth-first so the holder is
    located deterministically from the process we started, instead of a
    global ``/proc`` scan that collides with pre-existing/leaked holders.
    """
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
    # Prefer holders that are descendants of the process we launched. This is
    # deterministic even when stale/leaked `sleep infinity` holders already
    # exist on the host (which a global scan would confuse for the new one).
    if launcher_pid is not None:
        if launcher_pid not in before and _is_sleep_infinity_holder(launcher_pid):
            return launcher_pid
        descendants = [pid for pid in _descendant_sleep_holders(launcher_pid) if pid not in before]
        if descendants:
            if len(descendants) == 1:
                return descendants[0]
            return min(descendants, key=lambda pid: os.stat(f"/proc/{pid}").st_mtime)

    # Fall back to the global new-PID scan only when descendant walking found
    # nothing (e.g. kernels that hide /proc/<pid>/children).
    candidates = [pid for pid in _snapshot_sleep_infinity_pids() if pid not in before]
    if not candidates:
        return None
    if len(candidates) == 1:
        return candidates[0]
    return min(candidates, key=lambda pid: os.stat(f"/proc/{pid}").st_mtime)


@dataclass
class NamespaceHolder:
    """A long-lived process holding mount/PID/UTS/IPC namespaces."""

    pid: int
    nsenter_flags: list[str]
    nsenter_exe: str
    container_name: str
    proc: subprocess.Popen | None = None

    def run_argv(self, cmd: list[str]) -> list[str]:
        return [self.nsenter_exe, "--target", str(self.pid), *self.nsenter_flags, "--", *cmd]

    def run(self, cmd: list[str], **kwargs) -> subprocess.CompletedProcess:
        check = kwargs.pop("check", False)
        return subprocess.run(self.run_argv(cmd), check=check, **kwargs)

    def is_mounted(self, target: str) -> bool:
        try:
            result = self.run(["mountpoint", "-q", target], capture_output=True)
        except OSError:
            return False
        return result.returncode == 0

    def get_proc_mounts(self) -> str:
        result = self.run(["cat", "/proc/mounts"], capture_output=True, text=True, check=False)
        if result.returncode != 0:
            return ""
        return result.stdout or ""


def get_live_holder(container_name: str) -> NamespaceHolder | None:
    """Return an active holder for the container, or None."""
    pid = _read_holder_pid(container_name)
    if pid is None:
        return None
    flags = _read_holder_flags(container_name)
    nsenter = _resolve_nsenter()
    use_long = _nsenter_supports_long_flags(nsenter)
    return NamespaceHolder(
        pid=pid,
        nsenter_flags=long_flags_to_nsenter(flags, use_long=use_long),
        nsenter_exe=nsenter,
        container_name=container_name,
    )


def _holder_unshare_argv(unshare: str, flags: list[str]) -> list[str]:
    """Build unshare argv for a detached ``sleep infinity`` namespace holder."""
    argv = [unshare]
    if "--pid" in flags and "--fork" not in flags and "-f" not in flags:
        argv.append("--fork")
    argv.extend(flags)
    argv.extend(["sleep", HOLDER_SLEEP_SECONDS])
    return argv


def _create_holder(
    container_name: str,
    flags: list[str],
    holder_cmd: list[str] | None = None,
    pipe_r: int | None = None,
    env: dict | None = None,
) -> NamespaceHolder:
    unshare = _resolve_unshare()
    pid_file = _holder_pid_file(container_name)
    flags_file = _holder_flags_file(container_name)

    _remove_holder_state(container_name)

    before_pids = _snapshot_all_pids()
    before_sleep = _snapshot_sleep_infinity_pids()
    if holder_cmd:
        assert pipe_r is not None
        # Construct a python synchronization script to exec the custom command
        # after reading from the synchronization pipe descriptor.
        # Ensure we only exec if we receive the success newline byte from the parent.
        python_script = (
            "import os, sys\n"
            f"data = os.read({pipe_r}, 1)\n"
            f"os.close({pipe_r})\n"
            "if data == b'\\n':\n"
            "    os.execvp(sys.argv[1], sys.argv[1:])\n"
        )
        unshare_argv = [unshare]
        if "--pid" in flags and "--fork" not in flags and "-f" not in flags:
            unshare_argv.append("--fork")
        unshare_argv.extend(flags)
        unshare_argv.extend(["python3", "-c", python_script, *holder_cmd])
    else:
        unshare_argv = _holder_unshare_argv(unshare, flags)

    popen_kwargs: dict = {
        "start_new_session": True,
    }
    if holder_cmd:
        # Do not redirect stdout/stderr or start a new session for a user command run in the foreground.
        popen_kwargs = {}
        if pipe_r is not None:
            popen_kwargs["pass_fds"] = (pipe_r,)
        if env is not None:
            popen_kwargs["env"] = env
    else:
        popen_kwargs["stdout"] = subprocess.DEVNULL
        popen_kwargs["stderr"] = subprocess.PIPE

    proc = subprocess.Popen(unshare_argv, **popen_kwargs)

    success = False
    host_pid: int | None = None
    launch_failed = False
    try:
        # Up to ~5s: the forked grandchild/child process can take a moment to appear
        # under a busy /proc, especially on Android kernels.
        for _ in range(250):
            if holder_cmd:
                assert pipe_r is not None
                children = _read_host_child_pids(proc.pid)
                if children:
                    host_pid = children[0]
                    break
                # Fallback to scanning all new PIDs (for Android kernels that hide children)
                for pid in _snapshot_all_pids() - before_pids:
                    if _is_custom_holder(pid, pipe_r):
                        host_pid = pid
                        break
                if host_pid is not None:
                    break
            else:
                host_pid = _pick_new_holder_pid(before_sleep, launcher_pid=proc.pid)
                if host_pid is not None:
                    break
            if proc.poll() is not None and proc.returncode not in (0, None):
                launch_failed = True
                break
            time.sleep(0.02)

        if host_pid is None:
            stderr_text = ""
            with contextlib.suppress(Exception):
                if proc.poll() is None:
                    proc.kill()
                _, err = proc.communicate(timeout=2)
                if err:
                    if isinstance(err, bytes):
                        stderr_text = err.decode(errors="replace").strip()
                    elif isinstance(err, str):
                        stderr_text = err.strip()

            detail = f": {stderr_text}" if stderr_text else ""
            if launch_failed or stderr_text:
                raise NamespaceError(
                    "Failed to create the isolation namespace holder. "
                    f"'unshare' exited with an error{detail}. "
                    "Isolation requires root with CAP_SYS_ADMIN and kernel support "
                    "for the mount/PID/UTS/IPC namespaces; some Android kernels "
                    "restrict this. Run without --isolate, or check that "
                    "'unshare --pid --mount --uts --ipc --fork sleep infinity' works."
                )
            raise NamespaceError("Failed to locate namespace holder process on the host.")

        if not holder_cmd and _proc_comm(host_pid) != "sleep":
            raise NamespaceError(f"Namespace holder PID {host_pid} is not a sleep process.")

        start_time = _get_process_start_time(host_pid)
        with open(pid_file, "w") as fh:
            if start_time is not None:
                fh.write(f"{host_pid}\n{start_time}\n")
            else:
                fh.write(f"{host_pid}\n")
            if holder_cmd:
                fh.write("custom\n")
        with open(flags_file, "w") as fh:
            fh.write(" ".join(flags))

        success = True

    finally:
        if not success:
            with contextlib.suppress(OSError):
                proc.kill()
            if host_pid is not None:
                with contextlib.suppress(OSError):
                    os.kill(host_pid, signal.SIGKILL)
            _remove_holder_state(container_name)

    nsenter = _resolve_nsenter()
    use_long = _nsenter_supports_long_flags(nsenter)
    assert host_pid is not None
    return NamespaceHolder(
        pid=host_pid,
        nsenter_flags=long_flags_to_nsenter(flags, use_long=use_long),
        nsenter_exe=nsenter,
        container_name=container_name,
        proc=proc if holder_cmd else None,
    )


def acquire_holder(
    container_name: str,
    holder_cmd: list[str] | None = None,
    pipe_r: int | None = None,
    env: dict | None = None,
) -> NamespaceHolder:
    """Reuse or create a namespace holder for the container."""
    existing = get_live_holder(container_name)
    if existing is not None:
        return existing
    flags = probe_unshare_flags()
    return _create_holder(container_name, flags, holder_cmd=holder_cmd, pipe_r=pipe_r, env=env)


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

    Many Android kernels reject the recursive ``--make-rprivate /`` variant
    inside a mount namespace. Fall back to the non-recursive ``--make-private``
    and then ``--make-rslave`` so isolation still degrades gracefully instead
    of failing outright. Returns True if any variant succeeds.
    """
    for propagation in ("--make-rprivate", "--make-private", "--make-rslave"):
        try:
            result = holder.run(["mount", propagation, "/"], capture_output=True, text=True)
        except OSError:
            continue
        if result.returncode == 0:
            return True
        log.debug("mount %s / failed: %s", propagation, (result.stderr or "").strip())
    return False


def set_namespace_hostname(holder: NamespaceHolder, hostname: str) -> bool:
    """Set *hostname* inside the holder's UTS namespace (best-effort).

    Only attempts anything when the holder actually owns a UTS namespace
    (i.e. --uts is among its flags). Tries the `hostname` binary first and
    falls back to writing /proc/sys/kernel/hostname. Returns True on
    success; logs at debug and returns False on any failure. This is
    cosmetic (so `uname -n` shows the container name) and must never break
    an otherwise-successful login.
    """
    if not hostname:
        return False
    flags = _read_holder_flags(holder.container_name)
    if "--uts" not in flags:
        log.debug("UTS namespace not held; skipping sethostname for %s", hostname)
        return False

    try:
        result = holder.run(["hostname", hostname], capture_output=True, text=True)
        if result.returncode == 0:
            return True
        log.debug("hostname %s failed: %s", hostname, (result.stderr or "").strip())
    except OSError as exc:
        log.debug("hostname binary unavailable in namespace: %s", exc)

    # Fallback: write the UTS hostname directly via sysctl path.
    try:
        result = holder.run(
            ["sh", "-c", f"printf %s {hostname!r} > /proc/sys/kernel/hostname"],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            return True
        log.debug("writing /proc/sys/kernel/hostname failed: %s", (result.stderr or "").strip())
    except OSError as exc:
        log.debug("could not write hostname via /proc: %s", exc)
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

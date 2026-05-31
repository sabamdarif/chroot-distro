"""Linux namespace isolation for --isolated sessions (Ubuntu-Chroot pattern)."""

from __future__ import annotations

import contextlib
import logging
import os
import signal
import subprocess
import time
from dataclasses import dataclass

from chroot_distro.constants import IS_TERMUX, PROGRAM_NAME, RUNTIME_DIR, TERMUX_PREFIX
from chroot_distro.exceptions import ChrootDistroError

log = logging.getLogger(__name__)

_PROBE_FLAGS = ("--pid", "--mount", "--uts", "--ipc")
_LONG_TO_SHORT = {
    "--mount": "-m",
    "--uts": "-u",
    "--ipc": "-i",
    "--pid": "-p",
}

ISOLATION_MODE_NAMESPACE = "namespace"
ISOLATION_MODE_HOST = "host"


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
    return "unshare"


def _resolve_nsenter() -> str:
    if IS_TERMUX:
        termux_nsenter = os.path.join(TERMUX_PREFIX, "bin", "nsenter")
        if os.path.isfile(termux_nsenter):
            return termux_nsenter
    return "nsenter"


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


def _read_holder_pid(container_name: str) -> int | None:
    path = _holder_pid_file(container_name)
    if not os.path.isfile(path):
        return None
    try:
        with open(path) as fh:
            pid = int(fh.read().strip())
    except (OSError, ValueError):
        return None
    if not _pid_alive(pid):
        return None
    if not _is_sleep_infinity_holder(pid):
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
    return "infinity" in cmdline.split()


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


def _pick_new_holder_pid(before: set[int], launcher_pid: int | None = None) -> int | None:
    candidates: list[int] = []
    if launcher_pid is not None:
        if launcher_pid not in before and _is_sleep_infinity_holder(launcher_pid):
            candidates.append(launcher_pid)
        for child_pid in _read_host_child_pids(launcher_pid):
            if child_pid not in before and _is_sleep_infinity_holder(child_pid):
                candidates.append(child_pid)

    for pid in _snapshot_sleep_infinity_pids():
        if pid not in before and pid not in candidates:
            candidates.append(pid)

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
    argv.extend(["sleep", "infinity"])
    return argv


def _create_holder(container_name: str, flags: list[str]) -> NamespaceHolder:
    unshare = _resolve_unshare()
    pid_file = _holder_pid_file(container_name)
    flags_file = _holder_flags_file(container_name)

    _remove_holder_state(container_name)

    before_sleep = _snapshot_sleep_infinity_pids()
    unshare_argv = _holder_unshare_argv(unshare, flags)
    proc = subprocess.Popen(
        unshare_argv,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )

    host_pid: int | None = None
    for _ in range(100):
        host_pid = _pick_new_holder_pid(before_sleep, launcher_pid=proc.pid)
        if host_pid is not None:
            break
        if proc.poll() is not None and proc.returncode not in (0, None):
            break
        time.sleep(0.02)

    if host_pid is None:
        with contextlib.suppress(OSError):
            proc.kill()
        raise NamespaceError("Failed to locate namespace holder process (sleep infinity) on the host.")

    if _proc_comm(host_pid) != "sleep":
        with contextlib.suppress(OSError):
            os.kill(host_pid, signal.SIGKILL)
        raise NamespaceError(f"Namespace holder PID {host_pid} is not a sleep process.")

    with open(pid_file, "w") as fh:
        fh.write(str(host_pid))
    with open(flags_file, "w") as fh:
        fh.write(" ".join(flags))

    nsenter = _resolve_nsenter()
    use_long = _nsenter_supports_long_flags(nsenter)
    return NamespaceHolder(
        pid=host_pid,
        nsenter_flags=long_flags_to_nsenter(flags, use_long=use_long),
        nsenter_exe=nsenter,
        container_name=container_name,
    )


def acquire_holder(container_name: str) -> NamespaceHolder:
    """Reuse or create a namespace holder for the container."""
    existing = get_live_holder(container_name)
    if existing is not None:
        return existing
    flags = probe_unshare_flags()
    return _create_holder(container_name, flags)


def release_holder(container_name: str) -> None:
    """Kill the namespace holder and remove state files."""
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
    _remove_holder_state(container_name)


def make_mount_private(holder: NamespaceHolder) -> bool:
    """Set mount propagation to rprivate inside the holder's mount namespace."""
    try:
        result = holder.run(["mount", "--make-rprivate", "/"], capture_output=True, text=True)
    except OSError:
        return False
    if result.returncode != 0:
        log.debug("mount --make-rprivate / failed: %s", (result.stderr or "").strip())
        return False
    return True


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

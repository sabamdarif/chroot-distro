import logging
import os
import shlex
import shutil
import sys

from chroot_distro.constants import IS_TERMUX
from chroot_distro.exceptions import RootRequiredError
from chroot_distro.syscalls._constants import (
    CAP_DAC_OVERRIDE,
    CAP_MKNOD,
    CAP_SETGID,
    CAP_SETUID,
    CAP_SYS_ADMIN,
    CAP_SYS_CHROOT,
    PR_CAP_AMBIENT,
    PR_CAP_AMBIENT_IS_SET,
)
from chroot_distro.syscalls._libc import libc_prctl

log = logging.getLogger(__name__)

# Runtime CD_* environment variables that influence behaviour *after* the
# tool re-executes as root. They must be forwarded explicitly across the
# privilege-elevation boundary because many sudoers policies strip the
# environment and ignore `sudo -E` ("preserving the entire environment is
# not supported, '-E' is ignored").
_FORWARDED_ENV_VARS = (
    "CD_USE_NS",
    "CD_DOCKER_AUTH",
    "CD_DOWNLOAD_WORKERS",
    "CD_DOWNLOAD_MAX_RETRIES",
    "CD_DOWNLOAD_RATE_LIMIT",
)


def is_root() -> bool:
    """Check if the current process is running with root privileges (UID 0)."""
    return os.getuid() == 0


def _forwarded_env_assignments() -> list[str]:
    """Return ``VAR=value`` strings for the CD_* vars present in the env."""
    assignments: list[str] = []
    for name in _FORWARDED_ENV_VARS:
        value = os.environ.get(name)
        if value is not None:
            assignments.append(f"{name}={value}")
    return assignments


def get_reexec_argv() -> list[str]:
    """Build the argument list for re-executing the current process."""
    args = list(sys.argv)

    executable = args[0]
    if not os.path.isabs(executable):
        resolved = shutil.which(executable)
        executable = os.path.abspath(resolved) if resolved else os.path.abspath(executable)

    args[0] = executable

    # If the executable ends with .py, we run it with the current python interpreter
    # to preserve virtualenv and shebang settings.
    if executable.endswith(".py"):
        return [sys.executable, *args]

    return args


def _find_escalation_tool() -> list[str] | None:
    """Find the best escalation tool depending on the environment."""
    # Try sudo -> doas -> pkexec -> su in order of preference.
    if shutil.which("sudo"):
        return ["sudo"] if IS_TERMUX else ["sudo", "-E"]
    if shutil.which("doas"):
        return ["doas", "--"]
    if shutil.which("pkexec"):
        return ["pkexec", "--disable-internal-agent"]
    if shutil.which("su"):
        return ["su", "-c"]

    return None


# ---------------------------------------------------------------------------
# Linux capability checking
# ---------------------------------------------------------------------------

# The minimum set of capabilities chroot-distro needs.
REQUIRED_CAPS: tuple[int, ...] = (
    CAP_SYS_CHROOT,  # chroot(2)
    CAP_SYS_ADMIN,  # mount(2), umount2(2), unshare(2), setns(2)
    CAP_SETUID,  # setuid(2) — switch to container user
    CAP_SETGID,  # setgid(2), setgroups(2)
    CAP_MKNOD,  # mknod(2) — create /dev nodes
    CAP_DAC_OVERRIDE,  # file access inside rootfs
)


def _check_proc_cap(cap: int) -> bool:
    """Fall back to reading /proc/self/status for the effective capability set."""
    try:
        with open("/proc/self/status") as fh:
            for line in fh:
                if line.startswith("CapEff:"):
                    cap_hex = int(line.split(":")[1].strip(), 16)
                    return bool(cap_hex & (1 << cap))
    except (OSError, ValueError, IndexError) as exc:
        log.warning("Failed to read capabilities from /proc/self/status: %s", exc)
    return False


def has_capability(cap: int) -> bool:
    """Check if the current process has a specific Linux capability.

    Tries ``prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_IS_SET, cap)`` first,
    falls back to parsing ``/proc/self/status`` CapEff.
    """
    result = libc_prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_IS_SET, cap)
    if result >= 0:
        return bool(result)
    # prctl may return -1 if ambient caps are not supported; fall back.
    return _check_proc_cap(cap)


def has_required_capabilities() -> bool:
    """Return True if all required capabilities are available.

    Root (UID 0) is assumed to have all capabilities.
    """
    if os.getuid() == 0:
        return True
    return all(has_capability(cap) for cap in REQUIRED_CAPS)


def elevate_or_die() -> None:
    """Attempt to re-execute the current script with root privileges.

    The check order is:

    1. Already root → return immediately.
    2. File capabilities are set → return (no sudo needed).
    3. Otherwise → re-exec via sudo/doas/pkexec/su.

    If already elevating (to prevent infinite loops) or if no escalation
    tool is found, raises RootRequiredError.
    """
    if is_root():
        return

    # Phase 2: check if we have sufficient file capabilities.
    if has_required_capabilities():
        log.debug("Running with file capabilities — sudo not required")
        return

    # Check loop sentinel
    if os.environ.get("_CHROOT_DISTRO_ELEVATING") == "1":
        raise RootRequiredError("Privilege elevation loop detected. The tool is still not running as root.")

    tool_cmd = _find_escalation_tool()
    if not tool_cmd:
        raise RootRequiredError(
            "chroot-distro requires root privileges, but no privilege elevation tool "
            "(sudo, doas, pkexec, su) was found on the system."
        )

    # Set loop sentinel env var in the child environment
    os.environ["_CHROOT_DISTRO_ELEVATING"] = "1"

    reexec_argv = get_reexec_argv()

    # Runtime CD_* vars set by the invoking user must cross the elevation
    # boundary explicitly: `sudo -E` is frequently ignored by sudoers policy,
    # which would silently drop e.g. CD_USE_NS and skip namespace isolation.
    # The loop sentinel is forwarded the same way so it survives a stripped
    # environment and still prevents an elevation loop.
    env_assignments = ["_CHROOT_DISTRO_ELEVATING=1", *_forwarded_env_assignments()]

    tool_name = tool_cmd[0]

    # Prefix the re-executed program with `env VAR=value ...` so the
    # forwarded variables are set by the root-side `env` binary. This is
    # independent of the elevation tool's own environment policy (sudoers
    # env_keep / -E, doas keepenv, pkexec sanitisation), which can otherwise
    # silently drop CD_USE_NS and skip namespace isolation.
    env_prefix = ["env", *env_assignments] if env_assignments else []

    # Construct the final command line
    if tool_cmd[-1] == "-c":
        # su -c "<command string>": the whole invocation is a single string.
        cmd_str = shlex.join([*env_prefix, *reexec_argv])
        full_argv = [*tool_cmd, cmd_str]
    else:
        # sudo / doas / pkexec: run `env VAR=value <reexec>` as root.
        full_argv = [*tool_cmd, *env_prefix, *reexec_argv]

    try:
        os.execvp(full_argv[0], full_argv)
    except OSError as e:
        raise RootRequiredError(f"Failed to execute privilege elevation tool '{tool_name}': {e}") from e

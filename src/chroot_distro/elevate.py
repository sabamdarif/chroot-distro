import os
import shlex
import shutil
import sys

from chroot_distro.constants import IS_TERMUX
from chroot_distro.exceptions import RootRequiredError

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


def elevate_or_die() -> None:
    """Attempt to re-execute the current script with root privileges.

    If already elevating (to prevent infinite loops) or if no escalation tool is found,
    raises RootRequiredError.
    """
    if is_root():
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
    env_assignments = _forwarded_env_assignments()

    tool_name = tool_cmd[0]

    # Construct the final command line
    if tool_cmd[-1] == "-c":
        # su -c "<command string>": embed the assignments via `env` so they
        # are applied for the re-executed process.
        inner = ["env", *env_assignments, *reexec_argv] if env_assignments else reexec_argv
        cmd_str = shlex.join(inner)
        full_argv = [*tool_cmd, cmd_str]
    elif tool_name == "pkexec":
        # pkexec does not accept VAR=value assignments before the command,
        # so prefix the program with `env VAR=value ...`.
        prefix = ["env", *env_assignments] if env_assignments else []
        full_argv = [*tool_cmd, *prefix, *reexec_argv]
    else:
        # sudo and doas both accept `VAR=value` assignments placed before the
        # command to run; this works even when env_keep / -E is disabled.
        full_argv = [*tool_cmd, *env_assignments, *reexec_argv]

    try:
        os.execvp(full_argv[0], full_argv)
    except OSError as e:
        raise RootRequiredError(f"Failed to execute privilege elevation tool '{tool_name}': {e}") from e

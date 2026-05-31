import os
import shlex
import shutil
import sys

from chroot_distro.constants import IS_TERMUX
from chroot_distro.exceptions import RootRequiredError


def is_root() -> bool:
    """Check if the current process is running with root privileges (UID 0)."""
    return os.getuid() == 0


def get_reexec_argv() -> list[str]:
    """Build the argument list for re-executing the current process."""
    # Filter out '--no-elevate' to prevent it from propagating to the child
    args = [arg for arg in sys.argv if arg != "--no-elevate"]

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


def _find_escalation_tool(use_sudo: bool = False) -> list[str] | None:
    """Find the best escalation tool depending on the environment."""
    if IS_TERMUX:
        # In Termux, prefer 'su' (real root) over 'sudo' (which might be fake root via proot).
        # If use_sudo is True, we try 'sudo' first.
        tools = ["su", "sudo"] if not use_sudo else ["sudo", "su"]
        for tool in tools:
            if tool == "su" and shutil.which("su"):
                return ["su", "-c"]
            if tool == "sudo" and shutil.which("sudo"):
                return ["sudo"]
    else:
        # In normal Linux, try sudo -> doas -> pkexec -> su in order of preference.
        if shutil.which("sudo"):
            return ["sudo", "-E"]
        if shutil.which("doas"):
            return ["doas", "--"]
        if shutil.which("pkexec"):
            return ["pkexec", "--disable-internal-agent"]
        if shutil.which("su"):
            return ["su", "-c"]

    return None


def elevate_or_die(use_sudo: bool = False) -> None:
    """Attempt to re-execute the current script with root privileges.

    If already elevating (to prevent infinite loops) or if no escalation tool is found,
    raises RootRequiredError.
    """
    if is_root():
        return

    # Check loop sentinel
    if os.environ.get("_CHROOT_DISTRO_ELEVATING") == "1":
        raise RootRequiredError("Privilege elevation loop detected. The tool is still not running as root.")

    tool_cmd = _find_escalation_tool(use_sudo=use_sudo)
    if not tool_cmd:
        raise RootRequiredError(
            "chroot-distro requires root privileges, but no privilege elevation tool "
            "(sudo, doas, pkexec, su) was found on the system."
        )

    # Set loop sentinel env var in the child environment
    os.environ["_CHROOT_DISTRO_ELEVATING"] = "1"

    reexec_argv = get_reexec_argv()

    # Construct the final command line
    if tool_cmd[-1] == "-c":
        cmd_str = shlex.join(reexec_argv)
        full_argv = [*tool_cmd, cmd_str]
    else:
        full_argv = [*tool_cmd, *reexec_argv]

    tool_name = tool_cmd[0]

    try:
        os.execvp(full_argv[0], full_argv)
    except OSError as e:
        raise RootRequiredError(f"Failed to execute privilege elevation tool '{tool_name}': {e}") from e

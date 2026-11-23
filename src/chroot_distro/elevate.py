# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
"""Re-execute this program as root, by whatever mechanism the system offers.

Commands that need root require effective UID 0. `elevate_or_die()` uses the
root manager's `su` on Termux, or the first available tool on Linux in the
order sudo, doas, pkexec, su.
`_CHROOT_DISTRO_ELEVATING=1` in the child's environment is what turns a failed
elevation into an error instead of an infinite re-exec.

Elevation tools can reset the environment. Runtime settings that must survive
are set explicitly in the new process. A new `CD_*` variable read after
elevation needs an entry in `_FORWARDED_ENV_VARS` or the secret handoff.
`_FORWARDED_DISPLAY_VARS` exists for the same reason on the display side, since
doas, pkexec and su set no SUDO_UID and `helpers.x11.get_invoking_env()`'s
process-tree walk then has nothing to find.

Credentials and environment-backed build inputs use the anonymous descriptor
in elevation_handoff.py. The Linux Python prelude restores the caller's
working directory and fixed environment before replaying the original argv.

Termux is the other half. `su -c` from Magisk, KernelSU or APatch drops into a raw
Android environment (toybox PATH, no writable HOME, no /usr/bin for a shebang to
name), so `_termux_root_env_exports` builds a shell prelude that puts Termux's bin
dirs first, sets LD_PRELOAD to libtermux-exec's loader shim, points HOME at a
writable `~/.suroot` and TMPDIR at Termux's tmp, and restores the working
directory `su` changed. Android's `su` receives shell exports before Python starts.
"""

import json
import os
import re
import selectors
import shlex
import shutil
import subprocess
import sys
import time
from argparse import Namespace
from importlib.machinery import ModuleSpec

from chroot_distro.constants import (
    ANDROID_HOST_ENV_VARS,
    IS_TERMUX,
    TERMUX_APP_PACKAGE,
    TERMUX_HOME,
    TERMUX_PREFIX,
)
from chroot_distro.elevation_handoff import HANDOFF_ENV, send_handoff
from chroot_distro.exceptions import RootRequiredError

_FORWARDED_ENV_VARS = (
    "CD_USE_NS",
    "CD_USE_ISOLATION",
    "CD_DOWNLOAD_WORKERS",
    "CD_DOWNLOAD_MAX_RETRIES",
    "CD_DOWNLOAD_RATE_LIMIT",
    "CD_BUILD_CACHE_MAX",
    "CD_USER",
    "CD_WORKDIR",
    "CD_ENTRYPOINT",
    "CD_FORCE_NO_COLORS",
    "CD_NO_BINFMT",
    "CD_NO_CAP_DROP",
    "CD_NO_NEW_PRIVS",
    "CD_NO_SECCOMP",
    "CD_PUSH_CHUNK_SIZE",
    "CD_SUBID_BASE",
)

# Display/session/audio variables needed by --shared-display. These are
# forwarded as a belt-and-suspenders complement to the get_invoking_env()
# process-tree walk: doas/pkexec/su do not set SUDO_UID, so the walk
# looks for UID 0 processes and never finds the user's session vars.
# The values are non-secret session metadata (socket names, runtime-dir
# paths), so exposing them in /proc/*/cmdline is harmless.
_FORWARDED_DISPLAY_VARS = (
    "DISPLAY",
    "WAYLAND_DISPLAY",
    "XAUTHORITY",
    "XDG_RUNTIME_DIR",
    "XDG_SESSION_TYPE",
    "XDG_CURRENT_DESKTOP",
    "DESKTOP_SESSION",
    "PULSE_SERVER",
    "DBUS_SESSION_BUS_ADDRESS",
)


def is_root() -> bool:
    """Return whether the process has effective UID 0."""
    return os.geteuid() == 0


def is_root_available() -> bool:
    """Check if the current process is root or can obtain root privileges."""
    if is_root():
        return True
    if IS_TERMUX:
        return _find_termux_su() is not None

    return _find_escalation_tool() is not None


def _module_entry_point() -> ModuleSpec | None:
    spec = getattr(sys.modules["__main__"], "__spec__", None)
    return spec if spec is not None and spec.name == "chroot_distro.__main__" else None


def _forwarded_env(*, termux: bool = False) -> dict[str, str]:
    names: tuple[str, ...] = (*_FORWARDED_ENV_VARS, *_FORWARDED_DISPLAY_VARS, *ANDROID_HOST_ENV_VARS)
    if termux:
        names += ("TERMUX_APP__APP_VERSION_NAME", "TERMUX_VERSION")
    values = {name: os.environ[name] for name in names if name in os.environ}
    if termux:
        values.update(
            TERMUX_APP__PACKAGE_NAME=TERMUX_APP_PACKAGE,
            TERMUX__HOME=TERMUX_HOME,
            TERMUX__PREFIX=TERMUX_PREFIX,
        )
    else:
        for name in ("XDG_DATA_HOME", "XDG_CACHE_HOME"):
            if value := os.environ.get(name):
                values[name] = value if os.path.isabs(value) else os.path.join(os.getcwd(), value)

    spec = _module_entry_point()
    if spec is not None and spec.origin and not sys.flags.ignore_environment:
        parent = os.path.dirname(os.path.dirname(os.path.abspath(spec.origin)))
        pythonpath = os.environ.get("PYTHONPATH", "").split(os.pathsep)
        if parent == os.getcwd() or any(os.path.abspath(entry) == parent for entry in pythonpath):
            values["PYTHONPATH"] = parent
    return values


def get_reexec_argv() -> list[str]:
    """Build the argument list for re-executing the current process."""
    args = list(sys.argv)
    if _module_entry_point() is not None:
        app_start = len(sys.orig_argv) - len(args) + 1
        return [sys.executable, *sys.orig_argv[1:app_start], *args[1:]]

    executable = args[0]
    if not os.path.isabs(executable):
        resolved = shutil.which(executable)
        executable = os.path.abspath(resolved) if resolved else os.path.abspath(executable)

    args[0] = executable

    # A .py entry point has to go back through this interpreter, or the
    # re-exec loses the virtualenv it was started from.
    if executable.endswith(".py"):
        return [sys.executable, *args]

    return args


def _find_escalation_tool() -> list[str] | None:
    """Find the first available Linux elevation tool."""
    if shutil.which("sudo"):
        return ["sudo", "-H", "-u", "root", "--"]
    if shutil.which("doas"):
        return ["doas", "--"]
    if shutil.which("pkexec"):
        return ["pkexec", "--disable-internal-agent"]
    if shutil.which("su"):
        return ["su", "-c"]

    return None


# Known su binary locations on rooted Android (Magisk, KernelSU, APatch,
# LineageOS su, older SuperSU layouts). Mirrors termux-sudo's search list.
_SU_SEARCH_PATHS = (
    "/system/bin/su",
    "/debug_ramdisk/su",
    "/system/xbin/su",
    "/sbin/su",
    "/sbin/bin/su",
    "/system/sbin/su",
    "/su/xbin/su",
    "/su/bin/su",
    "/magisk/.core/bin/su",
)


_SU_POSITIONAL = re.compile(r"usage:\s+su \[who \[command\.\.\.\]\]|usage:\s+su \[uid\[,gid", re.I)
_SU_COMMAND = re.compile(r"(?:^|\s)(?:--command\b|-c(?:[\s,]|$))", re.M)
_SU_MANAGER = re.compile(r"\b(?:MagiskSU|KernelSU|APatch)\b", re.I)
_SU_HELP_LIMIT = 64 * 1024
_SU_HELP_TIMEOUT = 10


def _termux_su_env() -> dict[str, str]:
    return {key: value for key, value in os.environ.items() if key not in ("LD_PRELOAD", "LD_LIBRARY_PATH")}


def _su_help_text(su: str) -> str | None:
    """Read bounded informational output from su before requesting elevation."""
    deadline = time.monotonic() + _SU_HELP_TIMEOUT
    try:
        with subprocess.Popen(
            [su, "--help"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env=_termux_su_env(),
            start_new_session=True,
        ) as proc:
            assert proc.stdout is not None
            try:
                with selectors.DefaultSelector() as selector:
                    selector.register(proc.stdout, selectors.EVENT_READ)
                    output = bytearray()
                    while selector.select(max(0, deadline - time.monotonic())):
                        chunk = os.read(proc.stdout.fileno(), 4096)
                        if not chunk:
                            break
                        output.extend(chunk)
                        if len(output) > _SU_HELP_LIMIT or time.monotonic() >= deadline:
                            return None
                    else:
                        return None
                proc.wait(timeout=max(0, deadline - time.monotonic()))
                return output.decode(errors="replace")
            finally:
                if proc.poll() is None:
                    proc.kill()
    except (OSError, subprocess.TimeoutExpired):
        return None


def _find_termux_su() -> tuple[str, str] | None:
    override = os.environ.get("CD_SU_PATH")
    paths = [override] if override else [*_SU_SEARCH_PATHS, *(os.path.join(p, "su") for p in os.get_exec_path())]
    fallback = None
    for path in dict.fromkeys(os.path.abspath(path) for path in paths):
        if not os.path.isfile(path) or not os.access(path, os.X_OK):
            continue
        help_text = _su_help_text(path)
        if help_text is None or re.search(
            r"Termux does not supply tools|No su program found|(?:^|:\s*)(?:not allowed|permission denied)\s*$",
            help_text,
            re.I | re.M,
        ):
            continue
        candidate = (path, help_text)
        if override or _SU_POSITIONAL.search(help_text) or _SU_COMMAND.search(help_text) or _SU_MANAGER.search(help_text):
            return candidate
        if fallback is None:
            fallback = candidate
    return fallback


def _termux_su_argv(su: tuple[str, str], command: str, *, elevation: bool = False) -> list[str]:
    path, help_text = su
    argv = [path]
    if elevation and os.environ.get("CD_SU_MOUNT_MASTER") == "1":
        if "--mount-master" in help_text:
            argv.append("--mount-master")
        elif "--target" in help_text and re.search(r"\bpid\s+0\s+means[^\n]*global mount namespace", help_text, re.I):
            argv += ["--target", "0"]
        else:
            raise RootRequiredError("The selected su does not advertise global mount namespace support.")
    if _SU_POSITIONAL.search(help_text):
        return [*argv, "0", "/system/bin/sh", "-c", command]
    if elevation:
        if "--interactive" in help_text:
            argv.append("--interactive")
        bash = os.path.join(TERMUX_PREFIX, "bin", "bash")
        if "--shell" in help_text and os.access(bash, os.X_OK):
            argv += ["--shell", bash]
    return [*argv, "-c", command]


def _termux_root_env_exports(handoff: str = "") -> str:
    """Set Termux paths and the loader shim after Android's su starts its shell."""
    suroot = os.path.join(TERMUX_HOME, ".suroot")
    try:
        os.makedirs(suroot, exist_ok=True)
    except OSError:
        suroot = TERMUX_HOME
    termux_bin = os.path.join(TERMUX_PREFIX, "bin")
    exports: dict[str, str] = {
        "PATH": f"{termux_bin}:{termux_bin}/applets:/system/bin:/system/xbin",
        "HOME": suroot,
        "TMPDIR": os.path.join(TERMUX_PREFIX, "tmp"),
        "PREFIX": TERMUX_PREFIX,
        "TERM": os.environ.get("TERM", "xterm-256color"),
        "LANG": "en_US.UTF-8",
        "_CHROOT_DISTRO_ELEVATING": "1",
        HANDOFF_ENV: handoff,
    }
    for lib_name in ("libtermux-exec-ld-preload.so", "libtermux-exec.so"):
        termux_exec = os.path.join(TERMUX_PREFIX, "lib", lib_name)
        if os.path.exists(termux_exec):
            exports["LD_PRELOAD"] = termux_exec
            break
    exports.update(_forwarded_env(termux=True))
    return "unset PYTHONHOME PYTHONPATH; " + "; ".join(
        f"export {key}={shlex.quote(value)}" for key, value in exports.items()
    )


_LINUX_REEXEC = """\
import json
import os
import sys

cwd, settings, *command = sys.argv[1:]
try:
    os.chdir(cwd)
    env = {key: value for key, value in os.environ.items() if not key.startswith(("PYTHON", "LD_"))}
    env.update(json.loads(settings))
    os.execve(command[0], command, env)
except OSError as exc:
    print(f"chroot-distro: root re-entry failed: {exc!a}", file=sys.stderr)
    sys.exit(1)
"""


def elevate_or_die(args: Namespace) -> None:
    """Replace the caller with the selected elevation tool, or raise."""
    if os.environ.get("_CHROOT_DISTRO_ELEVATING") == "1":
        raise RootRequiredError("Privilege elevation loop detected. The tool is still not running as root.")

    try:
        cwd = os.getcwd()
    except OSError as exc:
        raise RootRequiredError(f"Could not read the working directory: {exc.strerror}") from exc

    reexec_argv = get_reexec_argv()
    su = _find_termux_su() if IS_TERMUX else None
    tool = _find_escalation_tool() if not IS_TERMUX else None
    if IS_TERMUX and su is None:
        if os.environ.get("CD_SU_PATH"):
            raise RootRequiredError("CD_SU_PATH does not name a usable su executable.")
        raise RootRequiredError("No usable Android su found. Is this device rooted (Magisk, KernelSU, APatch)?")
    if not IS_TERMUX and tool is None:
        raise RootRequiredError(
            "chroot-distro requires root privileges, but no privilege elevation tool "
            "(sudo, doas, pkexec, su) was found on the system."
        )

    with send_handoff(args) as handoff:
        env = None
        if su is not None:
            command = (
                _termux_root_env_exports(handoff)
                + f"; cd {shlex.quote(cwd)} || exit 1; exec "
                + shlex.join(reexec_argv)
            )
            argv = _termux_su_argv(su, command, elevation=True)
            env = _termux_su_env()
        else:
            assert tool is not None
            settings = _forwarded_env()
            settings.update({"_CHROOT_DISTRO_ELEVATING": "1", HANDOFF_ENV: handoff})
            bootstrap = [sys.executable, "-I", "-S", "-c", _LINUX_REEXEC, cwd, json.dumps(settings), *reexec_argv]
            argv = [*tool, shlex.join(bootstrap)] if tool[-1] == "-c" else [*tool, *bootstrap]

        try:
            if env is None:
                os.execvp(argv[0], argv)
            else:
                os.execve(argv[0], argv, env)
        except OSError as exc:
            raise RootRequiredError(f"Failed to execute privilege elevation tool {argv[0]!a}: {exc.strerror}") from exc

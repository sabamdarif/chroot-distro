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

The elevation argv contains a 0600 tempfile path in `CD_SECRET_FILE` when
`_SECRET_ENV_VARS` are set. The CLI's effective UID 0 shortcut bypasses the
legacy reader because the path comes from the environment.

Termux is the other half. `su -c` from Magisk, KernelSU or APatch drops into a raw
Android environment (toybox PATH, no writable HOME, no /usr/bin for a shebang to
name), so `_termux_root_env_exports` builds a shell prelude that puts Termux's bin
dirs first, sets LD_PRELOAD to libtermux-exec's loader shim, points HOME at a
writable `~/.suroot` and TMPDIR at Termux's tmp, and restores the working
directory `su` changed. Linux tools receive an `env VAR=value` prefix, and
Android's `su` receives shell exports.
"""

import contextlib
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
from importlib.machinery import ModuleSpec

from chroot_distro.constants import (
    ANDROID_HOST_ENV_VARS,
    IS_TERMUX,
    TERMUX_APP_PACKAGE,
    TERMUX_HOME,
    TERMUX_PREFIX,
)
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

# Vars whose values may hold secrets (guest env entries, registry
# credentials). They travel in a 0600 tempfile rather than argv so they are
# never visible in /proc/*/cmdline or kernel audit logs.
_SECRET_ENV_VARS = ("CD_DOCKER_AUTH", "CD_ENV")

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
        su = _find_termux_su()
        if su is None:
            return False
        help_text = _su_help_text(su)
        return "Termux does not supply tools" not in help_text and "No su program found" not in help_text

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


def _write_secret_file() -> str | None:
    """Write _SECRET_ENV_VARS to a 0600 JSON tempfile; return its path, or None if none are set."""
    secrets = {k: os.environ[k] for k in _SECRET_ENV_VARS if k in os.environ}
    if not secrets:
        return None
    import json

    fd, path = tempfile.mkstemp(prefix=".cd-secret-")
    try:
        os.chmod(path, 0o600)
        with os.fdopen(fd, "w") as fh:
            json.dump(secrets, fh)
    except Exception:
        with contextlib.suppress(OSError):
            os.unlink(path)
        raise
    return path


def _load_secret_file() -> None:
    """Read CD_SECRET_FILE if present, populate os.environ, then unlink the file."""
    path = os.environ.pop("CD_SECRET_FILE", None)
    if path is None:
        return
    import json

    try:
        with open(path) as fh:
            values = json.load(fh)
    except (OSError, ValueError):
        values = {}
    if isinstance(values, dict):
        for key, val in values.items():
            # Only the vars this channel exists for: the path arrives as a
            # CD_* var from the invoking environment, so an arbitrary key
            # here would let a caller set any root-side variable (PATH,
            # LD_PRELOAD, ...).
            if key in _SECRET_ENV_VARS and isinstance(val, str):
                os.environ[key] = val
    with contextlib.suppress(OSError):
        os.unlink(path)


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
        return ["sudo", "-E", "-H", "-u", "root", "--"]
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


def _find_termux_su() -> str | None:
    override = os.environ.get("CD_SU_PATH")
    if override and os.access(override, os.X_OK):
        return override
    for path in _SU_SEARCH_PATHS:
        if os.access(path, os.X_OK):
            return path
    return shutil.which("su")


def _su_help_text(su: str) -> str:
    """Probe `su --help` to discover supported options (never prompts)."""
    env = {k: v for k, v in os.environ.items() if k not in ("LD_PRELOAD", "LD_LIBRARY_PATH")}
    try:
        proc = subprocess.run(
            [su, "--help"],
            capture_output=True,
            text=True,
            timeout=10,
            stdin=subprocess.DEVNULL,
            env=env,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return (proc.stdout or "") + (proc.stderr or "")


def _termux_root_env_exports(secret_file: str | None = None) -> str:
    """Shell prelude that sets up Termux paths for the root side.

    Plain Magisk/KernelSU ``su -c`` drops into a raw Android environment
    (toybox PATH, mksh, no writable HOME). Four fixes make Termux binaries
    and pip-installed entry points work under root:

    - PATH with Termux's bin dirs *before* /system/bin
    - LD_PRELOAD=libtermux-exec.so so ``#!/usr/bin/env python3``-style
      shebangs are rewritten to Termux paths (Android has no /usr/bin)
    - a writable HOME inside the Termux rootfs (~/.suroot)
    - TMPDIR pointing at Termux's tmp

    *secret_file*, if given, is the path of a 0600 tempfile holding
    _SECRET_ENV_VARS; it is forwarded as CD_SECRET_FILE so the values
    never appear in the shell command string (i.e. not in /proc/*/cmdline).
    """
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
    }
    # termux-exec >= 2.0 renamed the preload library; probe both names.
    for lib_name in ("libtermux-exec-ld-preload.so", "libtermux-exec.so"):
        termux_exec = os.path.join(TERMUX_PREFIX, "lib", lib_name)
        if os.path.exists(termux_exec):
            exports["LD_PRELOAD"] = termux_exec
            break
    exports.update(_forwarded_env(termux=True))
    if secret_file:
        exports["CD_SECRET_FILE"] = secret_file
    return "; ".join(f"export {key}={shlex.quote(value)}" for key, value in exports.items())


def _elevate_termux() -> None:
    """Re-exec as root through Android's `su`, Termux-environment-aware.

    Never returns on success. The root manager (Magisk/KernelSU/APatch)
    shows its grant dialog only the first time; with 'remember' enabled
    every later run is passwordless and prompt-free.
    """
    su = _find_termux_su()
    if su is None:
        raise RootRequiredError(
            "chroot-distro requires root, but no 'su' binary was found. "
            "Is this device rooted (Magisk, KernelSU, APatch)?"
        )

    help_text = _su_help_text(su)
    if "Termux does not supply tools" in help_text or "No su program found" in help_text:
        raise RootRequiredError(
            "chroot-distro requires root, but the 'su' command on this device is a Termux stub. "
            "Is this device rooted (Magisk, KernelSU, APatch)?"
        )
    # su changes the working directory; restore it on the root side like
    # termux-sudo does (`cd -- "$CURRENT_WORKING_DIR"`).
    try:
        cwd = os.getcwd()
    except OSError:
        cwd = "/"
    secret_path = _write_secret_file()
    command = (
        _termux_root_env_exports(secret_file=secret_path)
        + "; cd "
        + shlex.quote(cwd)
        + " 2>/dev/null || cd /"
        + "; exec "
        + shlex.join(get_reexec_argv())
    )

    argv: list[str] = [su]
    # --mount-master is intentionally NOT used by default, matching
    # termux-sudo (it only adds the flag when the sudo HOME is on / or
    # /system, which never applies here). In the global root namespace
    # /data is MS_SHARED, so binding /data inside a rootfs that itself
    # lives under /data makes child binds propagate back into themselves:
    # recursive rootfs/.../rootfs/... phantom mounts that break unmount
    # cleanup and shadow the devpts instance needed for login ptys.
    # Magisk's default "requester" namespace is the Termux app's own
    # (slave propagation): mounts are still shared across all Termux
    # sessions but never recurse. Set CD_SU_MOUNT_MASTER=1 to force the
    # old global-namespace behaviour.
    if os.environ.get("CD_SU_MOUNT_MASTER") == "1" and "--mount-master" in help_text:
        argv.append("--mount-master")
    if "--preserve-environment" in help_text:
        argv.append("--preserve-environment")
    # Allocate a tty for -c on newer Magisk builds.
    if "--interactive" in help_text:
        argv.append("--interactive")
    bash = os.path.join(TERMUX_PREFIX, "bin", "bash")
    if "--shell" in help_text and os.access(bash, os.X_OK):
        argv += ["--shell", bash]
    argv += ["-c", command]

    # Magisk's su itself breaks when exec'd with Termux's LD_PRELOAD /
    # LD_LIBRARY_PATH; the prelude re-exports them on the root side.
    os.environ.pop("LD_PRELOAD", None)
    os.environ.pop("LD_LIBRARY_PATH", None)

    try:
        os.execvp(argv[0], argv)
    except OSError as e:
        if secret_path:
            with contextlib.suppress(OSError):
                os.unlink(secret_path)
        raise RootRequiredError(f"Failed to execute '{su}': {e}") from e


def elevate_or_die() -> None:
    """Attempt to re-execute the current process with root privileges.

    Raises RootRequiredError when elevation loops or no mechanism exists.
    """
    _load_secret_file()

    if is_root():
        return

    if os.environ.get("_CHROOT_DISTRO_ELEVATING") == "1":
        raise RootRequiredError("Privilege elevation loop detected. The tool is still not running as root.")

    if IS_TERMUX:
        _elevate_termux()
        return  # unreachable: _elevate_termux never returns on success

    tool_cmd = _find_escalation_tool()
    if not tool_cmd:
        raise RootRequiredError(
            "chroot-distro requires root privileges, but no privilege elevation tool "
            "(sudo, doas, pkexec, su) was found on the system."
        )

    os.environ["_CHROOT_DISTRO_ELEVATING"] = "1"

    reexec_argv = get_reexec_argv()

    env_assignments = ["_CHROOT_DISTRO_ELEVATING=1"]
    env_assignments.extend(f"{name}={value}" for name, value in _forwarded_env().items())

    secret_path = _write_secret_file()
    if secret_path:
        env_assignments.append(f"CD_SECRET_FILE={secret_path}")

    tool_name = tool_cmd[0]

    env_prefix = ["env", *env_assignments]

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
        if secret_path:
            with contextlib.suppress(OSError):
                os.unlink(secret_path)
        raise RootRequiredError(f"Failed to execute privilege elevation tool '{tool_name}': {e}") from e

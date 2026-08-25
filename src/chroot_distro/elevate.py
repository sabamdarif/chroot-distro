# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
"""Re-execute this program as root, by whatever mechanism the system offers.

Root is assumed everywhere else in the tree, so this is the one place that gets
it, and there is no unprivileged mode to degrade to. `elevate_or_die()` tries, in
order: already root; the required file capabilities already present
(REQUIRED_CAPS, checked through PR_CAP_AMBIENT rather than assumed);
Termux `su`; the Linux daemon socket; then sudo, doas, pkexec or su.
`_CHROOT_DISTRO_ELEVATING=1` in the child's environment is what turns a failed
elevation into an error instead of an infinite re-exec.

Crossing the boundary loses the environment, and that is what most of this file is
about. Many sudoers policies strip it and ignore `sudo -E` outright, so every
runtime variable that must survive is re-applied explicitly as an `env VAR=value`
prefix: a new `CD_*` variable whose effect happens *after* elevation has to be
added to `_FORWARDED_ENV_VARS`, or it will silently stop working under sudo.
`_FORWARDED_DISPLAY_VARS` exists for the same reason on the display side, since
doas, pkexec and su set no SUDO_UID and `helpers.x11.get_invoking_env()`'s
process-tree walk then has nothing to find.

A value that may hold a secret never goes in argv, which is world-readable through
/proc/*/cmdline: `_SECRET_ENV_VARS` are written to a 0600 tempfile and its path
forwarded as `CD_SECRET_FILE`, which the root side reads and unlinks. That path
arrives as an ordinary `CD_*` variable the daemon forwards from a client, so
`_load_secret_file` adopts only the two names the channel exists for; taking
arbitrary keys from it would let a client set PATH or LD_PRELOAD on the root side.

Termux is the other half. `su -c` from Magisk, KernelSU or APatch drops into a raw
Android environment (toybox PATH, no writable HOME, no /usr/bin for a shebang to
name), so `_termux_root_env_exports` builds a shell prelude that puts Termux's bin
dirs first, sets LD_PRELOAD to libtermux-exec's loader shim, points HOME at a
writable `~/.suroot` and TMPDIR at Termux's tmp, and restores the working
directory `su` changed. `su` is the one binary this program calls for work it
cannot do itself; the `shutil.which` probes in `_find_escalation_tool` are the
other, for the same reason. Nothing else here may grow into a shell-out.
"""

import contextlib
import logging
import os
import shlex
import shutil
import subprocess
import sys
import tempfile

from chroot_distro.constants import (
    ANDROID_HOST_ENV_VARS,
    IS_TERMUX,
    TERMUX_HOME,
    TERMUX_PREFIX,
)
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
    "CD_USE_ISOLATION",
    "CD_DOWNLOAD_WORKERS",
    "CD_DOWNLOAD_MAX_RETRIES",
    "CD_DOWNLOAD_RATE_LIMIT",
    "CD_FORCE_NO_COLORS",
    "CD_NO_CAP_DROP",
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
    """Check if the current process is running with root privileges (UID 0)."""
    return os.getuid() == 0


def is_root_available() -> bool:
    """Check if the current process is root or can obtain root privileges."""
    if is_root():
        return True
    if has_required_capabilities():
        return True
    if IS_TERMUX:
        su = _find_termux_su()
        if su is None:
            return False
        help_text = _su_help_text(su)
        return "Termux does not supply tools" not in help_text and "No su program found" not in help_text

    from chroot_distro.daemon import SOCKET_PATH

    if os.environ.get("CD_NO_DAEMON") != "1" and os.path.exists(SOCKET_PATH):
        import socket

        conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            conn.connect(SOCKET_PATH)
            return True
        except OSError:
            pass
        finally:
            conn.close()
    return _find_escalation_tool() is not None


def _forwarded_env_assignments() -> list[str]:
    """Return ``VAR=value`` strings for the forwarded vars present in the env."""
    assignments: list[str] = []
    for name in (*_FORWARDED_ENV_VARS, *_FORWARDED_DISPLAY_VARS, *ANDROID_HOST_ENV_VARS):
        value = os.environ.get(name)
        if value is not None:
            assignments.append(f"{name}={value}")
    return assignments


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
            # CD_* var, which the daemon forwards from the calling client,
            # so an arbitrary key here would let a client set any root-side
            # variable (PATH, LD_PRELOAD, ...).
            if key in _SECRET_ENV_VARS and isinstance(val, str):
                os.environ[key] = val
    with contextlib.suppress(OSError):
        os.unlink(path)


def get_reexec_argv() -> list[str]:
    """Build the argument list for re-executing the current process."""
    args = list(sys.argv)

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
    """Find the best escalation tool depending on the environment."""
    if shutil.which("sudo"):
        return ["sudo"] if IS_TERMUX else ["sudo", "-E"]
    if shutil.which("doas"):
        return ["doas", "--"]
    if shutil.which("pkexec"):
        return ["pkexec", "--disable-internal-agent"]
    if shutil.which("su"):
        return ["su", "-c"]

    return None


REQUIRED_CAPS: tuple[int, ...] = (
    CAP_SYS_CHROOT,  # chroot(2)
    CAP_SYS_ADMIN,  # mount(2), umount2(2), unshare(2), setns(2)
    CAP_SETUID,  # setuid(2), switch to container user
    CAP_SETGID,  # setgid(2), setgroups(2)
    CAP_MKNOD,  # mknod(2), create /dev nodes
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
    """Shell prelude replicating what termux-sudo sets up for the root side.

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
    for name in (*_FORWARDED_ENV_VARS, *_FORWARDED_DISPLAY_VARS, *ANDROID_HOST_ENV_VARS):
        value = os.environ.get(name)
        if value is not None:
            exports[name] = value
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


def _try_daemon_delegation() -> None:
    """Delegate to the root daemon socket when available.

    Exits the process with the delegated command's exit code on success;
    returns normally when the daemon is unavailable or access was denied
    so the caller can fall back to sudo/doas/pkexec/su.
    """
    from chroot_distro.daemon import run_client

    exit_code = run_client(sys.argv[1:])
    if exit_code is not None:
        sys.exit(exit_code)


def elevate_or_die() -> None:
    """Attempt to re-execute the current process with root privileges.

    The check order is:

    1. Already root → return immediately.
    2. Required file capabilities are present → return (no elevation).
    3. Termux → exec Android's ``su`` directly with a Termux-aware
       environment (no external sudo/tsu wrapper required).
    4. Linux → delegate to the group-gated root daemon socket if
       ``chroot-distro setup`` has been run (passwordless).
    5. Fall back to sudo/doas/pkexec/su.

    Raises RootRequiredError when elevation loops or no mechanism exists.
    """
    # Hydrate secrets that the pre-elevation process wrote to a tempfile to
    # avoid embedding them in argv (visible in /proc/*/cmdline).
    _load_secret_file()

    if is_root():
        return

    if has_required_capabilities():
        log.debug("Running with file capabilities, elevation not required")
        return

    if os.environ.get("_CHROOT_DISTRO_ELEVATING") == "1":
        raise RootRequiredError("Privilege elevation loop detected. The tool is still not running as root.")

    if IS_TERMUX:
        _elevate_termux()
        return  # unreachable: _elevate_termux never returns on success

    _try_daemon_delegation()

    tool_cmd = _find_escalation_tool()
    if not tool_cmd:
        raise RootRequiredError(
            "chroot-distro requires root privileges, but no privilege elevation tool "
            "(sudo, doas, pkexec, su) was found on the system. For passwordless "
            "operation run 'chroot-distro setup' once as root."
        )

    os.environ["_CHROOT_DISTRO_ELEVATING"] = "1"

    reexec_argv = get_reexec_argv()

    # Runtime CD_* vars set by the invoking user must cross the elevation
    # boundary explicitly: `sudo -E` is frequently ignored by sudoers policy,
    # which would silently drop e.g. CD_USE_NS and skip namespace isolation.
    # The loop sentinel is forwarded the same way so it survives a stripped
    # environment and still prevents an elevation loop.
    env_assignments = ["_CHROOT_DISTRO_ELEVATING=1", *_forwarded_env_assignments()]

    # Secrets and guest env entries travel via a 0600 tempfile, not argv, to
    # stay out of /proc/*/cmdline. The root-side elevate_or_die() call reads
    # and unlinks the file before is_root() returns.
    secret_path = _write_secret_file()
    if secret_path:
        env_assignments.append(f"CD_SECRET_FILE={secret_path}")

    tool_name = tool_cmd[0]

    # Prefix the re-executed program with `env VAR=value ...` so the
    # forwarded variables are set by the root-side `env` binary. This is
    # independent of the elevation tool's own environment policy (sudoers
    # env_keep / -E, doas keepenv, pkexec sanitisation), which can otherwise
    # silently drop CD_USE_NS and skip namespace isolation.
    env_prefix = ["env", *env_assignments] if env_assignments else []

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

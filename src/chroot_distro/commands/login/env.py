import contextlib
import json
import logging
import os
import re

from chroot_distro.constants import TERMUX_PREFIX
from chroot_distro.message import warn

log = logging.getLogger(__name__)

# Conservative identifier syntax for env var names.
_VALID_ENV_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_SENSITIVE_ENV_KEY_RE = re.compile(
    r"(?i)(^|_)(password|passwd|secret|token|api[_-]?key|auth|credential|private[_-]?key)($|_)"
)


# Vars that must never be logged or written to profile snippets.
_SENSITIVE_ENV_KEYS = frozenset(
    {
        "CD_DOCKER_AUTH",
        "GITHUB_TOKEN",
        "GH_TOKEN",
    }
)


ANDROID_HOST_ENV_VARS = (
    "ANDROID_ART_ROOT",
    "ANDROID_DATA",
    "ANDROID_I18N_ROOT",
    "ANDROID_ROOT",
    "ANDROID_RUNTIME_ROOT",
    "ANDROID_TZDATA_ROOT",
    "BOOTCLASSPATH",
    "DEX2OATBOOTCLASSPATH",
    "EXTERNAL_STORAGE",
)


# Vars the image Env must not override.
IMAGE_ENV_BLOCKED = frozenset(
    {
        "ANDROID_ART_ROOT",
        "ANDROID_DATA",
        "ANDROID_I18N_ROOT",
        "ANDROID_ROOT",
        "ANDROID_RUNTIME_ROOT",
        "ANDROID_TZDATA_ROOT",
        "BOOTCLASSPATH",
        "DEX2OATBOOTCLASSPATH",
        "EXTERNAL_STORAGE",
        "MOZ_FAKE_NO_SANDBOX",
        "PULSE_SERVER",
        "TERM",
        "COLORTERM",
        # Display / Wayland / Sound / D-Bus — session-specific, from host
        "DISPLAY",
        "WAYLAND_DISPLAY",
        "XAUTHORITY",
        "XDG_RUNTIME_DIR",
        "DBUS_SESSION_BUS_ADDRESS",
        "XDG_SESSION_TYPE",
        "XDG_CURRENT_DESKTOP",
        "DESKTOP_SESSION",
        # NVIDIA / GPU — set at login time based on auto-detection
        "GALLIUM_DRIVER",
        "MESA_D3D12_DEFAULT_DEVICE_TYPE",
        "LIBGL_ALWAYS_SOFTWARE",
        "__NV_PRIME_RENDER_OFFLOAD",
        "__GLX_VENDOR_LIBRARY_NAME",
    }
)


# Per-session vars (HOME, USER, TERM, COLORTERM) belong to the spawning
# shell.
_PROFILE_INJECT_SKIP = frozenset(
    {
        "HOME",
        "USER",
        "TERM",
        "COLORTERM",
        "PATH",
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        # Display / Wayland / Sound / D-Bus — per-session, not for profile
        "DISPLAY",
        "WAYLAND_DISPLAY",
        "XAUTHORITY",
        "XDG_RUNTIME_DIR",
        "DBUS_SESSION_BUS_ADDRESS",
        "PULSE_SERVER",
        "XDG_SESSION_TYPE",
        "XDG_CURRENT_DESKTOP",
        "DESKTOP_SESSION",
        # NVIDIA / GPU — per-session, set by auto-detection
        "GALLIUM_DRIVER",
        "MESA_D3D12_DEFAULT_DEVICE_TYPE",
        "LIBGL_ALWAYS_SOFTWARE",
        "__NV_PRIME_RENDER_OFFLOAD",
        "__GLX_VENDOR_LIBRARY_NAME",
    }
)


def is_sensitive_env_key(key: str) -> bool:
    """Return True when an env var name likely carries a secret value."""
    if key in _SENSITIVE_ENV_KEYS:
        return True
    return bool(_SENSITIVE_ENV_KEY_RE.search(key))


def _read_manifest_config(container_dir: str) -> dict:
    """Return the image_config.config dict from manifest.json, or {}."""
    manifest_path = os.path.join(container_dir, "manifest.json")
    try:
        with open(manifest_path) as fh:
            data = json.load(fh)
        return (data.get("image_config") or {}).get("config") or {}
    except (OSError, ValueError):
        return {}


def resolve_override(flag_value: str | None, env_var_name: str) -> str | None:
    """CLI flag wins, else the CD_* env var, else None."""
    if flag_value:
        return flag_value
    val = os.environ.get(env_var_name, "").strip()
    return val or None


def read_cd_env() -> list[str]:
    """Return newline-separated ``CD_ENV`` as ``VAR=VALUE`` entries."""
    raw = os.environ.get("CD_ENV", "")
    return [line.strip() for line in raw.splitlines() if "=" in line]


def read_manifest_env(container_dir: str) -> list:
    """Return image Env entries from manifest.json, or [] if absent/invalid."""
    cfg = _read_manifest_config(container_dir)
    env = cfg.get("Env") or []
    return [e for e in env if isinstance(e, str) and "=" in e]


def read_manifest_user(container_dir: str) -> str | None:
    """Return the image's default User (e.g. ``"65532:65532"``), or None."""
    user = _read_manifest_config(container_dir).get("User")
    return user if user and isinstance(user, str) else None


def read_manifest_workdir(container_dir: str) -> str | None:
    """Return the image's WorkingDir (e.g. ``"/app"``), or None."""
    wd = _read_manifest_config(container_dir).get("WorkingDir")
    return wd if wd and isinstance(wd, str) else None


def read_manifest_shell(container_dir: str) -> str | None:
    """Return the image Shell's interpreter path (e.g. ``"sh"``), or None."""
    shell = _read_manifest_config(container_dir).get("Shell")
    if isinstance(shell, list) and shell and isinstance(shell[0], str):
        return shell[0]
    return None


def read_manifest_exposed_ports(container_dir: str) -> list[str]:
    """Return declared ExposedPorts (e.g. ``["8080/tcp", "443/tcp"]``), or []."""
    ports = _read_manifest_config(container_dir).get("ExposedPorts")
    if isinstance(ports, dict):
        return sorted(ports.keys())
    return []


def read_manifest_volumes(container_dir: str) -> list[str]:
    """Return declared Volume paths (e.g. ``["/data", "/var/log"]``), or []."""
    volumes = _read_manifest_config(container_dir).get("Volumes")
    if isinstance(volumes, dict):
        return sorted(volumes.keys())
    return []


def inject_termux_profile(
    rootfs: str,
    env: dict,
    *,
    owner_uid: int | None = None,
    owner_gid: int | None = None,
    include_termux_bin: bool = False,
) -> None:
    """Write a profile.d snippet that re-applies the login-time environment.

    *include_termux_bin* appends the host ``$PREFIX/bin`` to PATH — only for
    termux-type containers; in normal distros host Termux binaries cannot
    execute inside the chroot.
    """
    profile_d = os.path.join(rootfs, "etc", "profile.d")
    if not os.path.isdir(profile_d):
        return
    snippet = os.path.join(profile_d, "chroot-profile.sh")
    legacy_snippet = os.path.join(profile_d, "termux-profile.sh")
    legacy_snippet2 = os.path.join(profile_d, "termux-prefix.sh")
    for ls in (legacy_snippet, legacy_snippet2):
        with contextlib.suppress(OSError):
            os.remove(ls)
    termux_bin = f"{TERMUX_PREFIX}/bin"

    lines: list[str] = []
    if include_termux_bin:
        lines += [
            'case ":${PATH}:" in',
            f'  *":{termux_bin}:"*) ;;',
            f'  *) export PATH="${{PATH}}:{termux_bin}" ;;',
            "esac",
        ]

    for key in sorted(env):
        if key in _PROFILE_INJECT_SKIP or is_sensitive_env_key(key):
            continue
        if not _VALID_ENV_KEY_RE.match(key):
            continue
        val = env[key]
        escaped = str(val).replace("'", "'\\''")
        lines.append(f"export {key}='{escaped}'")

    content = "\n".join(lines) + "\n"
    try:
        with open(snippet, "w") as fh:
            fh.write(content)
        os.chmod(snippet, 0o600)
        if owner_uid is not None and owner_gid is not None:
            os.chown(snippet, owner_uid, owner_gid)
    except OSError as exc:
        warn(f"Failed to write environment snippet file: {exc}")


def resolve_term(rootfs: str, term: str | None) -> str:
    """Return *term* if the rootfs has its terminfo, else 'xterm-256color'."""
    if not term:
        return "xterm-256color"

    # Terminfo dirs key on the first character, or its hex ord on some
    # systems.
    first_char = term[0]
    if not first_char.isalnum() and first_char != "_":
        return "xterm-256color"

    first_char_hex = f"{ord(first_char):02x}"

    termux_usr = TERMUX_PREFIX.lstrip("/")

    terminfo_dirs = [
        "usr/share/terminfo",
        "lib/terminfo",
        "etc/terminfo",
        "usr/lib/terminfo",
        os.path.join(termux_usr, "share", "terminfo"),
        os.path.join(termux_usr, "lib", "terminfo"),
    ]

    for d in terminfo_dirs:
        path1 = os.path.join(rootfs, d, first_char, term)
        path2 = os.path.join(rootfs, d, first_char_hex, term)
        try:
            if os.path.isfile(path1) or os.path.isfile(path2):
                return term
        except OSError as exc:
            log.debug("Failed to check terminfo path: %s", exc)

    return "xterm-256color"

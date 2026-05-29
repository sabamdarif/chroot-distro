import contextlib
import json
import os
import re

from chroot_distro.constants import TERMUX_PREFIX

# Conservative identifier syntax for env var names: a leading letter or
# underscore followed by letters, digits, or underscores.
_VALID_ENV_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


# Vars the image Env must not override.
IMAGE_ENV_BLOCKED = frozenset({
    "ANDROID_ART_ROOT", "ANDROID_DATA", "ANDROID_I18N_ROOT",
    "ANDROID_ROOT", "ANDROID_RUNTIME_ROOT", "ANDROID_TZDATA_ROOT",
    "BOOTCLASSPATH", "DEX2OATBOOTCLASSPATH", "EXTERNAL_STORAGE",
    "MOZ_FAKE_NO_SANDBOX", "PULSE_SERVER",
    "TERM", "COLORTERM",
})


# Per-session vars (HOME, USER, TERM, COLORTERM) belong to the spawning
# shell.
_PROFILE_INJECT_SKIP = frozenset({
    "HOME", "USER", "TERM", "COLORTERM",
    "PATH",
    "LD_PRELOAD", "LD_LIBRARY_PATH",
})


def read_manifest_env(container_dir: str) -> list:
    """Return image Env entries from manifest.json, or [] if absent/invalid."""
    manifest_path = os.path.join(container_dir, "manifest.json")
    try:
        with open(manifest_path) as fh:
            data = json.load(fh)
        env = (data.get("image_config") or {}).get("config", {}).get("Env") or []
        return [e for e in env if isinstance(e, str) and "=" in e]
    except (OSError, ValueError):
        return []


def inject_termux_profile(rootfs: str, env: dict) -> None:
    """Write a profile.d snippet that re-applies the login-time environment."""
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

    lines = [
        'case ":${PATH}:" in',
        f'  *":{termux_bin}:"*) ;;',
        f'  *) export PATH="${{PATH}}:{termux_bin}" ;;',
        'esac',
    ]

    for key in sorted(env):
        if key in _PROFILE_INJECT_SKIP:
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
        os.chmod(snippet, 0o644)
    except OSError:
        pass


def resolve_term(rootfs: str, term: str) -> str:
    """Verify if the terminal type term has a terminfo file inside the rootfs.

    If not found, fallback to 'xterm-256color'.
    """
    if not term:
        return "xterm-256color"

    # Terminfo folder structure is typically based on the first character.
    # Ncurses on case-insensitive filesystems or some systems may use hexadecimal ord.
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
        except OSError:
            pass

    return "xterm-256color"


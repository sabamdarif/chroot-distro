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

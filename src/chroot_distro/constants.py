import os
import platform
from importlib.metadata import PackageNotFoundError, version

PROGRAM_AUTHOR = "sabamdarif"
PROGRAM_NAME = "chroot-distro"
CANONICAL_PROGRAM_NAME = "Chroot-Distro"

try:
    PROGRAM_VERSION = version(PROGRAM_NAME)
except PackageNotFoundError:
    PROGRAM_VERSION = "rolling"

os.umask(0o022)

# ---------------------------------------------------------------------------
# Termux / Android detection
# ---------------------------------------------------------------------------

TERMUX_APP_PACKAGE = os.environ.get("TERMUX_APP__PACKAGE_NAME", "com.termux")
TERMUX_HOME = os.environ.get(
    "TERMUX__HOME", f"/data/data/{TERMUX_APP_PACKAGE}/files/home"
)
TERMUX_PREFIX = os.environ.get(
    "TERMUX__PREFIX", f"/data/data/{TERMUX_APP_PACKAGE}/files/usr"
)

def _detect_termux() -> bool:
    """Return True when at least two Termux/Android indicators are present."""
    checks = (
        ("android" in platform.platform().lower()
            or os.path.exists("/system/build.prop")
            or os.path.exists("/data/app")),
        bool(os.environ.get("TERMUX_APP__APP_VERSION_NAME")
            or os.environ.get("TERMUX_VERSION")),
        os.access(TERMUX_PREFIX, os.R_OK | os.X_OK),
    )
    return sum(checks) >= 2

IS_TERMUX: bool = _detect_termux()

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

if IS_TERMUX:
    RUNTIME_DIR = os.path.join(TERMUX_PREFIX, "var", "lib", PROGRAM_NAME)
    BASE_CACHE_DIR = os.path.join(RUNTIME_DIR, "cache")
else:
    _xdg_data = os.environ.get("XDG_DATA_HOME") or os.path.join(
        os.path.expanduser("~"), ".local", "share"
    )
    _xdg_cache = os.environ.get("XDG_CACHE_HOME") or os.path.join(
        os.path.expanduser("~"), ".cache"
    )
    RUNTIME_DIR = os.path.join(_xdg_data, PROGRAM_NAME)
    BASE_CACHE_DIR = os.path.join(_xdg_cache, PROGRAM_NAME)

CONTAINERS_DIR = os.path.join(RUNTIME_DIR, "containers")
LOCKS_DIR = os.path.join(RUNTIME_DIR, "locks")
LAYER_CACHE_DIR = os.path.join(BASE_CACHE_DIR, "oci_layers")
MANIFEST_CACHE_DIR = os.path.join(BASE_CACHE_DIR, "oci_manifests")

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

DEFAULT_PRIMARY_NS = "8.8.8.8"
DEFAULT_SECONDARY_NS = "8.8.4.4"

if IS_TERMUX:
    DEFAULT_PATH_ENV = (
        "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
        ":/usr/local/games:/usr/games"
        f":{TERMUX_PREFIX}/bin:/system/bin:/system/xbin"
    )
else:
    DEFAULT_PATH_ENV = (
        "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
        ":/usr/local/games:/usr/games"
    )

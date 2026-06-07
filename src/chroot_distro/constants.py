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
TERMUX_HOME = os.environ.get("TERMUX__HOME", f"/data/data/{TERMUX_APP_PACKAGE}/files/home")
TERMUX_PREFIX = os.environ.get("TERMUX__PREFIX", f"/data/data/{TERMUX_APP_PACKAGE}/files/usr")


def _detect_termux() -> bool:
    """Return True when at least two Termux/Android indicators are present."""
    checks = (
        (
            "android" in platform.platform().lower()
            or os.path.exists("/system/build.prop")
            or os.path.exists("/data/app")
        ),
        bool(os.environ.get("TERMUX_APP__APP_VERSION_NAME") or os.environ.get("TERMUX_VERSION")),
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
    _xdg_data = os.environ.get("XDG_DATA_HOME") or os.path.join(os.path.expanduser("~"), ".local", "share")
    _xdg_cache = os.environ.get("XDG_CACHE_HOME") or os.path.join(os.path.expanduser("~"), ".cache")
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

DEFAULT_LAYER_DOWNLOAD_WORKERS = 4
MAX_LAYER_DOWNLOAD_WORKERS = 10


def layer_download_workers() -> int:
    """Return parallel layer download worker count from ``CD_DOWNLOAD_WORKERS``.

    Values below 1 are raised to 1; values above ``MAX_LAYER_DOWNLOAD_WORKERS``
    are capped. Non-integers fall back to ``DEFAULT_LAYER_DOWNLOAD_WORKERS``.
    """
    raw = os.environ.get("CD_DOWNLOAD_WORKERS", "").strip()
    if not raw:
        return DEFAULT_LAYER_DOWNLOAD_WORKERS
    try:
        count = int(raw, 10)
    except ValueError:
        return DEFAULT_LAYER_DOWNLOAD_WORKERS
    return max(1, min(count, MAX_LAYER_DOWNLOAD_WORKERS))


# — segmented download (per-file multi-connection) —
MIN_SEGMENT_BYTES = 4 * 1024 * 1024  # 4 MiB — don't split below this per segment

DEFAULT_DOWNLOAD_MAX_RETRIES = 3
MAX_DOWNLOAD_RETRIES = 20


def download_max_retries() -> int:
    """Return max retry count from ``CD_DOWNLOAD_MAX_RETRIES``.

    Values below 0 are raised to 0; values above ``MAX_DOWNLOAD_RETRIES``
    are capped.  Non-integers fall back to ``DEFAULT_DOWNLOAD_MAX_RETRIES``.
    """
    raw = os.environ.get("CD_DOWNLOAD_MAX_RETRIES", "").strip()
    if not raw:
        return DEFAULT_DOWNLOAD_MAX_RETRIES
    try:
        count = int(raw, 10)
    except ValueError:
        return DEFAULT_DOWNLOAD_MAX_RETRIES
    return max(0, min(count, MAX_DOWNLOAD_RETRIES))


def download_rate_limit() -> int:
    """Return bandwidth cap in bytes/sec from ``CD_DOWNLOAD_RATE_LIMIT``.

    Accepts human-readable suffixes: ``K`` (KiB), ``M`` (MiB), ``G`` (GiB).
    Examples: ``"5M"`` → 5 MiB/s, ``"500K"`` → 500 KiB/s, ``"0"`` → unlimited.
    Returns ``0`` (unlimited) when unset or on parse error.
    """
    raw = os.environ.get("CD_DOWNLOAD_RATE_LIMIT", "").strip().upper()
    if not raw:
        return 0
    multipliers = {"K": 1024, "M": 1024 * 1024, "G": 1024 * 1024 * 1024}
    try:
        if raw[-1] in multipliers:
            return max(0, int(raw[:-1]) * multipliers[raw[-1]])
        return max(0, int(raw))
    except (ValueError, IndexError):
        return 0


if IS_TERMUX:
    DEFAULT_PATH_ENV = (
        "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
        ":/usr/local/games:/usr/games"
        f":{TERMUX_PREFIX}/bin:/system/bin:/system/xbin"
    )
else:
    DEFAULT_PATH_ENV = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/games:/usr/games"

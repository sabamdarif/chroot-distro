import hashlib
import os
import time
import urllib.error
import urllib.request

from chroot_distro.atomic import atomic_replace
from chroot_distro.constants import PROGRAM_NAME, PROGRAM_VERSION
from chroot_distro.message import log_error, log_info, msg
from chroot_distro.progress import clear_bar, draw_bytes_bar, fmt_size

__all__ = ("download_file", "sha256_file")


def sha256_file(path: str) -> str:
    """Compute and return the SHA-256 hex digest of *path*, with a progress bar."""
    h = hashlib.sha256()
    total = os.path.getsize(path)
    processed = 0
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
            processed += len(chunk)
            draw_bytes_bar(processed, total, noun="processed")
    clear_bar()
    return h.hexdigest()


def download_file(
    url: str, dest: str, max_retries: int = 5, retry_delay: int = 5
) -> None:
    """Download *url* to *dest* with progress output, redirects, and retries."""
    req = urllib.request.Request(
        url, headers={"User-Agent": f"{PROGRAM_NAME}/{PROGRAM_VERSION}"},
    )
    for attempt in range(max_retries):
        try:
            with atomic_replace(dest) as tmp, urllib.request.urlopen(req) as resp, open(tmp, "wb") as fh:
                total = int(resp.headers.get("Content-Length", 0))
                downloaded = 0
                while True:
                    chunk = resp.read(65536)
                    if not chunk:
                        break
                    fh.write(chunk)
                    downloaded += len(chunk)
                    draw_bytes_bar(downloaded, total, noun="downloaded")
            clear_bar()
            log_info(f"Finished downloading ({fmt_size(downloaded)}).")
            return
        except KeyboardInterrupt:
            clear_bar()
            raise
        except (urllib.error.URLError, OSError) as exc:
            clear_bar()
            if attempt < max_retries - 1:
                time.sleep(retry_delay)
                continue
            msg()
            log_error("Download failure, please check your network connection.")
            raise RuntimeError(f"Cannot download {url}: {exc}") from exc

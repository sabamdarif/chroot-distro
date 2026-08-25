# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
"""Search Docker Hub for images.

Hub's search endpoint is not part of the registry API, so this command is Hub-only by
construction and there is nothing to generalise to other registries. Read-only and
unauthenticated, which is why `cli.main` never elevates it.
"""

import json
import sys
import urllib.error
import urllib.parse
import urllib.request

from chroot_distro.constants import PROGRAM_NAME, PROGRAM_VERSION
from chroot_distro.message import C, crit_error, msg
from chroot_distro.progress import loading_line

_HUB_SEARCH_URL = "https://hub.docker.com/v2/search/repositories/"
_SOCKET_TIMEOUT = 30
_DESC_MAX = 60


def _fetch(term: str, limit: int) -> list[dict]:
    query = urllib.parse.urlencode({"query": term, "page_size": str(limit), "page": "1"})
    url = f"{_HUB_SEARCH_URL}?{query}"
    req = urllib.request.Request(url, headers={"User-Agent": f"{PROGRAM_NAME}/{PROGRAM_VERSION}"})
    with urllib.request.urlopen(req, timeout=_SOCKET_TIMEOUT) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    results = data.get("results") or []
    return results if isinstance(results, list) else []


def _truncate(text: str, width: int) -> str:
    text = " ".join(text.split())
    if len(text) <= width:
        return text
    return text[: width - 1] + "\u2026"


def command_search(args) -> None:
    """Search Docker Hub for images matching a term."""
    term = args.term
    if not term:
        crit_error("search term is not specified.")
        sys.exit(1)

    limit = getattr(args, "limit", None) or 25
    limit = max(1, min(limit, 100))

    try:
        with loading_line(f"Searching Docker Hub for '{term}'..."):
            results = _fetch(term, limit)
    except urllib.error.HTTPError as exc:
        crit_error(f"Docker Hub search failed (HTTP {exc.code}).")
        sys.exit(1)
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        crit_error(f"could not reach Docker Hub: {exc}. Check your network connection.")
        sys.exit(1)
    except (ValueError, json.JSONDecodeError):
        crit_error("Docker Hub returned an unexpected response.")
        sys.exit(1)

    msg()
    if not results:
        msg(f"{C['YELLOW']}No images found for '{term}'.{C['RST']}")
        msg()
        return

    rows = []
    for item in results:
        name = str(item.get("repo_name") or item.get("name") or "")
        if not name:
            continue
        stars = int(item.get("star_count") or 0)
        official = "[OK]" if item.get("is_official") else ""
        desc = _truncate(str(item.get("short_description") or ""), _DESC_MAX)
        rows.append((name, str(stars), official, desc))

    name_w = max(len("NAME"), *(len(r[0]) for r in rows))
    stars_w = max(len("STARS"), *(len(r[1]) for r in rows))
    off_w = max(len("OFFICIAL"), *(len(r[2]) for r in rows))

    header = f"  {C['BCYAN']}{'NAME':<{name_w}}  {'STARS':>{stars_w}}  {'OFFICIAL':<{off_w}}  {'DESCRIPTION'}{C['RST']}"
    msg(header)
    for row_name, row_stars, row_official, row_desc in rows:
        msg(
            f"  {C['GREEN']}{row_name:<{name_w}}{C['RST']}  "
            f"{C['CYAN']}{row_stars:>{stars_w}}{C['RST']}  "
            f"{C['YELLOW']}{row_official:<{off_w}}{C['RST']}  "
            f"{row_desc}"
        )
    msg()
    msg(f"{C['CYAN']}Install one with: {C['GREEN']}{PROGRAM_NAME} install <name>{C['RST']}")
    msg()


__all__ = ("command_search",)

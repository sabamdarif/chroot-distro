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
from chroot_distro.helpers.docker import is_repository_path
from chroot_distro.helpers.download import (
    MAX_METADATA_BYTES,
    NETWORK_ERRORS,
    declared_length,
    http_opener,
    new_request,
    require_complete_body,
)
from chroot_distro.message import C, crit_error, escape_controls, is_quiet, msg
from chroot_distro.progress import loading_line

_HUB_SEARCH_URL = "https://hub.docker.com/v2/search/repositories/"
_SOCKET_TIMEOUT = 30
_DESC_MAX = 60


def _fetch(term: str, limit: int) -> list:
    query = urllib.parse.urlencode({"query": term, "page_size": str(limit), "page": "1"})
    url = f"{_HUB_SEARCH_URL}?{query}"
    req = new_request(url, headers={"User-Agent": f"{PROGRAM_NAME}/{PROGRAM_VERSION}"})
    with http_opener().open(req, timeout=_SOCKET_TIMEOUT) as resp:
        body = resp.read(MAX_METADATA_BYTES + 1)
        size = declared_length(resp)
    if len(body) > MAX_METADATA_BYTES or size > MAX_METADATA_BYTES:
        raise ValueError("search response exceeds the size limit")
    require_complete_body(len(body), size, "Docker Hub search")
    data = json.loads(body.decode("utf-8"))
    results = data.get("results") if isinstance(data, dict) else None
    if not isinstance(results, list):
        raise ValueError("invalid search response")
    return results


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

    try:
        term.encode("utf-8")
    except UnicodeError:
        # A byte on the command line that is not UTF-8 arrives as a lone
        # surrogate, and urlencode() raised UnicodeEncodeError out of
        # building the request.
        crit_error("the search term is not valid text: it holds bytes that are not UTF-8.")
        sys.exit(1)

    limit = getattr(args, "limit", None) or 25
    limit = max(1, min(limit, 100))
    display_term = escape_controls(term)

    try:
        with loading_line(f"Searching Docker Hub for '{display_term}'..."):
            results = _fetch(term, limit)
    except urllib.error.HTTPError as exc:
        exc.close()
        crit_error(f"Docker Hub search failed (HTTP {exc.code}).")
        sys.exit(1)
    except NETWORK_ERRORS as exc:
        crit_error(f"could not reach Docker Hub: {escape_controls(str(exc))}. Check your network connection.")
        sys.exit(1)
    except (ValueError, RecursionError):
        crit_error("Docker Hub returned an unexpected response.")
        sys.exit(1)

    if is_quiet():
        return

    rows = []
    for item in results:
        if not isinstance(item, dict):
            continue
        name = item.get("repo_name") or item.get("name")
        # Docker's repository-name grammar: a name failing it is not addressable
        # by any client, so it is not a result worth printing.
        if not isinstance(name, str) or not is_repository_path(name):
            continue
        stars = item.get("star_count")
        if type(stars) is not int or stars < 0:
            stars = 0
        official = "[OK]" if item.get("is_official") is True else ""
        description = item.get("short_description")
        desc = _truncate(escape_controls(description), _DESC_MAX) if isinstance(description, str) else ""
        rows.append((name, str(stars), official, desc))
        if len(rows) == limit:
            break

    msg()
    if not rows:
        msg(f"{C['YELLOW']}No images found for '{display_term}'.{C['RST']}")
        msg()
        return

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

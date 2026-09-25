"""Unit tests for what the help text says about `--isolated`.

`pages.py` builds every flag description at import time from
`constants.IS_TERMUX`, so a Linux run never sees the Termux branch, which is
where the false claims lived. The fixture therefore reloads the module once per
platform instead of reading whatever this host happened to build.
"""

import importlib

import pytest

from chroot_distro import constants
from chroot_distro.commands.help import pages

# What `login` clears when it takes the maximum-isolation path
# (`commands/login/__init__.py`), with `args.bind` emptied.
IGNORED_FLAGS = ("--shared-home", "--shared-tmp", "--shared-display", "--bind")


def _strings(value):
    """Every string in a help page, whatever the nesting."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from _strings(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _strings(item)


@pytest.fixture(params=[False, True], ids=["linux", "termux"])
def help_pages(request, monkeypatch):
    """`HELP_PAGES` as built for one platform, rebuilt as Linux on teardown."""
    monkeypatch.setattr(constants, "IS_TERMUX", request.param)
    importlib.reload(pages)
    yield pages.HELP_PAGES
    monkeypatch.undo()
    importlib.reload(pages)


def test_no_page_claims_a_flag_overrides_isolated(help_pages):
    for name, page in help_pages.items():
        for text in _strings(page):
            assert "takes priority over isolated" not in text.lower(), name


def test_isolated_names_the_flags_it_ignores(help_pages):
    description = dict(help_pages["login"]["options"])["--isolated"]
    assert "ignored" in description.lower()
    for flag in IGNORED_FLAGS:
        assert flag in description


@pytest.mark.parametrize("page_name", ["login", "run"])
def test_sharing_flag_rows_mention_isolated(help_pages, page_name):
    options = dict(help_pages[page_name]["options"])
    for flag in IGNORED_FLAGS:
        (description,) = [desc for name, desc in options.items() if flag in name]
        assert "--isolated" in description

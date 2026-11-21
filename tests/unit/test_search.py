"""Docker Hub search response and terminal output regressions."""

import io
from contextlib import nullcontext
import json
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from chroot_distro.commands import search


def _response(monkeypatch, body, length=None):
    response = io.BytesIO(body)
    response.headers = {} if length is None else {"Content-Length": str(length)}
    monkeypatch.setattr(search, "http_opener", lambda: Mock(open=Mock(return_value=response)))


@pytest.mark.parametrize("payload", [[], {}, {"results": {}}, {"results": None}])
def test_search_reports_an_invalid_response(monkeypatch, capsys, payload):
    _response(monkeypatch, json.dumps(payload).encode())
    with pytest.raises(SystemExit) as exc:
        search.command_search(SimpleNamespace(term="alpine"))
    assert exc.value.code == 1
    assert "unexpected response" in capsys.readouterr().err


def test_search_refuses_a_truncated_body(monkeypatch, capsys):
    _response(monkeypatch, b'{"results":[]}', length=100)
    with pytest.raises(SystemExit):
        search.command_search(SimpleNamespace(term="alpine"))
    assert "ended after" in capsys.readouterr().err


def test_search_refuses_an_oversized_body(monkeypatch, capsys):
    monkeypatch.setattr(search, "MAX_METADATA_BYTES", 8)
    _response(monkeypatch, b'{"results":[]}')
    with pytest.raises(SystemExit):
        search.command_search(SimpleNamespace(term="alpine"))
    assert "unexpected response" in capsys.readouterr().err


def test_search_filters_rows_escapes_controls_and_enforces_limit(monkeypatch, capsys):
    _response(monkeypatch, json.dumps({"results": [
        None, {"name": "INVALID"},
        {"name": "alpine", "star_count": "bad", "is_official": "yes", "short_description": "hello\x1b[2J"},
        {"name": "second"},
    ]}).encode())
    search.command_search(SimpleNamespace(term="name\x07", limit=1))
    err = capsys.readouterr().err
    assert "alpine" in err
    assert "hello\\e[2J" in err
    assert "\x1b[2J" not in err
    assert "\x07" not in err
    assert "[OK]" not in err
    assert "second" not in err


def test_search_treats_a_wholly_filtered_page_as_empty(monkeypatch, capsys):
    _response(monkeypatch, b'{"results":[{"name":"INVALID"}]}')
    search.command_search(SimpleNamespace(term="alpine\x07"))
    assert r"No images found for 'alpine\x07'" in capsys.readouterr().err


def test_quiet_search_suppresses_success_and_keeps_errors(monkeypatch, capsys):
    monkeypatch.setattr(search, "is_quiet", lambda: True)
    monkeypatch.setattr(search, "loading_line", nullcontext)
    _response(monkeypatch, b'{"results":[{"name":"alpine"}]}')
    search.command_search(SimpleNamespace(term="alpine"))
    assert capsys.readouterr().err == ""
    _response(monkeypatch, b"[]")
    with pytest.raises(SystemExit):
        search.command_search(SimpleNamespace(term="alpine"))
    assert "unexpected response" in capsys.readouterr().err

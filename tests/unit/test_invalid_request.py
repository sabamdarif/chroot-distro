# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
"""A URL urllib cannot use is a message, not a traceback.

urllib answers much of what is wrong with a URL with a ValueError, which is
neither an OSError nor an HTTPException, so it used to walk out of `install`,
`build` and `push`. new_request() and the opener turn it into InvalidRequest.
"""

import pytest

from chroot_distro.helpers import download
from chroot_distro.helpers.docker import transport


def test_new_request_refuses_an_unparsable_url():
    with pytest.raises(download.InvalidRequest) as exc:
        download.new_request("http://[")
    text = str(exc.value)
    assert "'http://[' is not a valid URL" in text
    assert "Invalid IPv6 URL" in text


def test_new_request_builds_an_ordinary_one():
    req = download.new_request("https://example.com/x.tar", headers={"A": "b"})
    assert req.full_url == "https://example.com/x.tar"


def test_the_opener_refuses_a_string_it_cannot_parse():
    with pytest.raises(download.InvalidRequest) as exc:
        download.http_opener().open("http://[")
    assert "not a valid URL" in str(exc.value)


def test_the_opener_refuses_a_host_the_idna_codec_rejects():
    # The constructor takes this one; the resolver is where it fails.
    with pytest.raises(download.InvalidRequest) as exc:
        download.http_opener().open("http://..example/x")
    assert "cannot send a request for 'http://..example/x'" in str(exc.value)


def test_the_opener_refuses_a_path_that_is_not_ascii():
    with pytest.raises(download.InvalidRequest) as exc:
        download.http_opener().open("http://example.com/\u00e4")
    assert "cannot send a request" in str(exc.value)


def test_the_opener_refuses_a_header_a_line_break_would_split():
    req = download.new_request("http://example.com/x", headers={"X-Test": "a\nb"})
    with pytest.raises(download.InvalidRequest):
        download.http_opener().open(req)


def test_an_invalid_request_is_never_retried():
    exc = download.InvalidRequest("x")
    assert not download.is_retryable_http_error(exc)

    calls = []

    def _operation():
        calls.append(1)
        raise exc

    with pytest.raises(download.InvalidRequest):
        download.retry_http(_operation, what="t", max_retries=5, retry_delay=0)
    assert len(calls) == 1


def test_a_url_off_the_command_line_is_quoted_in_the_message():
    url = "http://[\x1b[2J"
    with pytest.raises(download.InvalidRequest) as exc:
        download.new_request(url)
    assert "\x1b" not in str(exc.value)


def test_download_file_reports_an_unusable_url_as_its_own_message(tmp_path, monkeypatch):
    monkeypatch.setattr("chroot_distro.constants.layer_download_workers", lambda: 1)
    dest = tmp_path / "out.tar"
    with pytest.raises(RuntimeError) as exc:
        download.download_file("http://[", str(dest), max_retries=3, retry_delay=0)
    assert "is not a valid URL" in str(exc.value)
    assert not dest.exists()


def test_a_token_grant_a_header_cannot_carry_is_refused():
    with pytest.raises(RuntimeError) as exc:
        transport._granted_auth({"token": "abc\ndef"}, "Authenticating repo")
    assert "characters an HTTP header cannot carry" in str(exc.value)
    assert "abc" not in str(exc.value)


def test_a_token_grant_past_latin_1_is_refused():
    with pytest.raises(RuntimeError) as exc:
        transport._granted_auth({"access_token": "\u4e2d"}, "Authenticating repo")
    assert "cannot carry" in str(exc.value)


def test_a_usable_token_grant_keeps_its_bearer_prefix():
    assert transport._granted_auth({"token": "abc123"}, "t") == "Bearer abc123"
    assert transport._granted_auth({}, "t") == ""


def test_an_unusable_registry_is_not_reachable_rather_than_a_traceback():
    assert transport._http_registry_reachable("[:5000") is False


def test_add_with_an_unusable_url_is_a_build_error():
    from chroot_distro.helpers.build_engine import copy_step
    from chroot_distro.helpers.build_engine.errors import BuildError

    with pytest.raises(BuildError) as exc:
        copy_step._copy_url("https://[", "/dir/", {}, 0, 0, None, None)
    assert "ADD https://[: not a valid URL" in str(exc.value)


def test_a_reference_holding_a_lone_surrogate_still_keys_its_cache_path():
    import hashlib

    from chroot_distro.helpers.docker.cache import _manifest_cache_path

    path = _manifest_cache_path("bad\udcff/ref:1", "amd64")
    canonical = "bad\udcff/ref:1_amd64"
    key = hashlib.sha256(canonical.encode("utf-8", "surrogatepass")).hexdigest()[:16]
    assert path.endswith(key + ".json")

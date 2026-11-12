#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
# Download: redirects off TLS or onto unsupported schemes are refused
# Needs: 00-start-server.sh (mock-registry.py on port 8097).

set -e

python3 - <<'PY'
from chroot_distro.helpers.download import http_opener, RedirectRefused, check_redirect

try:
	check_redirect("http://example.com/file", "ftp://example.com/file")
	raise AssertionError("ftp redirect was not refused")
except RedirectRefused as exc:
	assert "only http:// and https:// URLs" in str(exc)
	assert not exc.plaintext

try:
	check_redirect("https://example.com/file", "http://example.com/file", allow_plaintext=False)
	raise AssertionError("downgrade redirect was not refused")
except RedirectRefused as exc:
	assert "leaves HTTPS for plain HTTP" in str(exc)
	assert exc.plaintext

check_redirect("https://example.com/file", "http://example.com/file", allow_plaintext=True)
PY

python3 - <<'PY'
from chroot_distro.helpers.download import http_opener, NETWORK_TIMEOUT, _Opener

assert NETWORK_TIMEOUT == 120.0
opener = http_opener()
assert isinstance(opener, _Opener)
PY

echo "PASS: redirect security policy and socket timeouts enforced"

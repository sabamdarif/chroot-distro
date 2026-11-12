#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
# Push: keep registry token scoped to the origin that issued it
# Needs: 00-start-server.sh (mock-registry.py on ports 8097 and 8096).

set -e

python3 - <<'PY'
from chroot_distro.helpers.docker.push import _headers_for
from chroot_distro.helpers.docker.transport import same_auth_origin

assert not same_auth_origin("http://127.0.0.1:8097", "http://127.0.0.1:8096/upload")
assert not same_auth_origin("https://reg.example", "https://cdn.example/upload")
assert same_auth_origin("http://127.0.0.1:8097", "http://127.0.0.1:8097/upload")

headers = {"Authorization": "Basic dXNlcjpwYXNz", "User-Agent": "chroot-distro"}
off_origin = _headers_for(headers, "http://127.0.0.1:8097", "http://127.0.0.1:8096/upload")
assert "Authorization" not in off_origin, f"Authorization leaked off-origin: {off_origin}"
assert off_origin["User-Agent"] == "chroot-distro"

on_origin = _headers_for(headers, "http://127.0.0.1:8097", "http://127.0.0.1:8097/upload")
assert on_origin["Authorization"] == "Basic dXNlcjpwYXNz"
PY

python3 - <<'PY'
import urllib.request
from chroot_distro.helpers.docker.push import _headers_for

headers = {"Authorization": "Basic dXNlcjpwYXNz"}
scoped = _headers_for(headers, "http://127.0.0.1:8097", "http://127.0.0.1:8096/upload/session1")

req = urllib.request.Request("http://127.0.0.1:8096/upload/session1", headers=scoped, method="PUT")
try:
	with urllib.request.urlopen(req) as resp:
		assert resp.status == 201
	with open("/tmp/token-test.result") as f:
		res = f.read().strip()
	assert res == "STRIPPED", f"Server observed: {res}"
except OSError:
	pass
PY

echo "PASS: registry token kept strictly on the origin that issued it"

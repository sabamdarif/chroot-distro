#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
# Registry: Basic authentication challenge and CD_DOCKER_AUTH pre-check
# Needs: 00-start-server.sh (mock-registry.py on port 8097).

set -e

set +e
sudo sh -c 'CD_DOCKER_AUTH="baduser:badpass" chroot-distro install \
	127.0.0.1:8097/test/app:latest --allow-insecure -n test-badauth >/tmp/badauth.log 2>&1'
rc=$?
set -e

cat /tmp/badauth.log
[ "$rc" -ne 0 ] || {
	echo "FAIL: install with rejected credentials did not fail"
	exit 1
}

grep -qF "rejected the credentials in CD_DOCKER_AUTH (HTTP 401)" /tmp/badauth.log || {
	echo "FAIL: missing credentials rejected message"
	exit 1
}

if grep -q "Traceback" /tmp/badauth.log; then
	echo "FAIL: credential rejection dumped a traceback"
	exit 1
fi

if sudo chroot-distro list -q 2>&1 | grep -q "test-badauth"; then
	echo "FAIL: failed auth install registered a container"
	exit 1
fi

python3 - <<'PY'
import os
from chroot_distro.helpers.docker.transport import get_auth_token

os.environ["CD_DOCKER_AUTH"] = "user:pass"
auth, base = get_auth_token("test/app", "127.0.0.1:8097", insecure=True)
assert auth == "Basic dXNlcjpwYXNz", f"expected Basic auth, got {auth}"
assert "127.0.0.1:8097" in base
PY

echo "PASS: CD_DOCKER_AUTH pre-check and Basic challenge handled correctly"

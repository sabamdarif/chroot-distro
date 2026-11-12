#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
# Registry: rate limit 429 response on pull and push
# Needs: 00-start-server.sh (mock-registry.py on port 8097).

set -e

set +e
sudo sh -c 'chroot-distro install 127.0.0.1:8097/ratelimited/app:latest \
	--allow-insecure -n test-ratelim >/tmp/ratelimit-pull.log 2>&1'
rc=$?
set -e

cat /tmp/ratelimit-pull.log
[ "$rc" -ne 0 ] || {
	echo "FAIL: rate limited pull did not fail"
	exit 1
}

grep -qF "refused to serve '127.0.0.1:8097/ratelimited/app:latest' (HTTP 429 Too Many Requests): its rate limit is reached" /tmp/ratelimit-pull.log || {
	echo "FAIL: missing pull rate limit error message"
	exit 1
}

if grep -q "Traceback" /tmp/ratelimit-pull.log; then
	echo "FAIL: pull rate limit dumped a traceback"
	exit 1
fi

# The push pre-flight reads the manifest cache, which only a finished build
# fills. Seed it with the entry one would have left, so the push reaches the
# registry and the 429 is what the test exercises.
sudo python3 - <<'PY'
import hashlib
import os

from chroot_distro.arch import get_device_cpu_arch, platform_from_arch
from chroot_distro.helpers.docker.cache import layer_cache_path, save_manifest_cache
from chroot_distro.helpers.docker.media import canonical_json

ref = "127.0.0.1:8097/ratelimited/app:latest"
platform = platform_from_arch(get_device_cpu_arch())
image_config = {"os": platform.os, "architecture": platform.architecture}
if platform.variant:
	image_config["variant"] = platform.variant

blob = b"ratelimited-layer\n"
layer_digest = "sha256:" + hashlib.sha256(blob).hexdigest()
path = layer_cache_path(layer_digest)
os.makedirs(os.path.dirname(path), exist_ok=True)
with open(path, "wb") as fh:
	fh.write(blob)

manifest = {
	"schemaVersion": 2,
	"mediaType": "application/vnd.oci.image.manifest.v1+json",
	"config": {
		"mediaType": "application/vnd.oci.image.config.v1+json",
		"digest": "sha256:" + hashlib.sha256(canonical_json(image_config)).hexdigest(),
		"size": len(canonical_json(image_config)),
	},
	"layers": [
		{
			"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
			"digest": layer_digest,
			"size": len(blob),
		}
	],
}
save_manifest_cache(ref, platform, manifest, "ratelimited/app", image_config)
PY

set +e
sudo sh -c 'chroot-distro push 127.0.0.1:8097/ratelimited/app:latest \
	--allow-insecure >/tmp/ratelimit-push.log 2>&1'
rc=$?
set -e

cat /tmp/ratelimit-push.log
[ "$rc" -ne 0 ] || {
	echo "FAIL: rate limited push did not fail"
	exit 1
}

grep -qF "refused to accept '127.0.0.1:8097/ratelimited/app:latest' (HTTP 429 Too Many Requests): its rate limit is reached" /tmp/ratelimit-push.log || {
	echo "FAIL: missing push rate limit error message"
	exit 1
}

if grep -q "Traceback" /tmp/ratelimit-push.log; then
	echo "FAIL: push rate limit dumped a traceback"
	exit 1
fi

echo "PASS: rate limited pull and push reported clearly without traceback"

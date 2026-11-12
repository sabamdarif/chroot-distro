#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
# Build (failure): reference grammar refuses invalid image references

set -e

mkdir -p /tmp/badref-build
cat >/tmp/badref-build/Dockerfile <<-'EOF'
FROM alpine:latest
RUN true
EOF

set +e
sudo sh -c 'chroot-distro build /tmp/badref-build -t Ubuntu \
	--progress plain >/tmp/badref-tag.log 2>&1'
rc=$?
set -e
[ "$rc" -ne 0 ] || {
	echo "FAIL: build accepted uppercase tag 'Ubuntu'"
	exit 1
}
grep -qF "repository name must be lowercase" /tmp/badref-tag.log || {
	echo "FAIL: missing lowercase error for uppercase tag"
	exit 1
}

hex="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
set +e
sudo sh -c "chroot-distro build /tmp/badref-build -t myapp@sha256:$hex \
	--progress plain >/tmp/badref-digest.log 2>&1"
rc=$?
set -e
[ "$rc" -ne 0 ] || {
	echo "FAIL: build accepted digest in tag"
	exit 1
}
grep -qF "use a tag" /tmp/badref-digest.log || {
	echo "FAIL: missing use a tag message for digest tag"
	exit 1
}

set +e
sudo sh -c 'chroot-distro build /tmp/badref-build -t ../../x:1 \
	--progress plain >/tmp/badref-trav.log 2>&1'
rc=$?
set -e
[ "$rc" -ne 0 ] || {
	echo "FAIL: build accepted registry host traversal"
	exit 1
}
grep -qF "registry host is not valid" /tmp/badref-trav.log || {
	echo "FAIL: missing registry host error"
	exit 1
}

cat >/tmp/badref-build/Dockerfile <<-'EOF'
FROM Ubuntu
RUN true
EOF
set +e
sudo sh -c 'chroot-distro build /tmp/badref-build -t test-badfrom:latest \
	--progress plain >/tmp/badref-from.log 2>&1'
rc=$?
set -e
[ "$rc" -ne 0 ] || {
	echo "FAIL: build accepted uppercase FROM"
	exit 1
}
grep -qF "must be lowercase" /tmp/badref-from.log || {
	echo "FAIL: missing lowercase error for FROM"
	exit 1
}

cat >/tmp/badref-build/Dockerfile <<-'EOF'
FROM alpine:latest
COPY --from=Ubuntu /etc/issue /issue.txt
EOF
set +e
sudo sh -c 'chroot-distro build /tmp/badref-build -t test-badcopy:latest \
	--progress plain >/tmp/badref-copy.log 2>&1'
rc=$?
set -e
[ "$rc" -ne 0 ] || {
	echo "FAIL: build accepted uppercase COPY --from"
	exit 1
}
grep -qF "must be lowercase" /tmp/badref-copy.log || {
	echo "FAIL: missing lowercase error for COPY --from"
	exit 1
}

echo "PASS: image reference grammar enforced across build flags and instructions"

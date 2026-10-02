#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
# Login: docker-default masked and read-only proc/sys paths in default mode.
# Needs: 01-install (alpine).

set -e

# /proc/kcore is masked with a /dev/null bind: it must show as char 1,3,
# not the real kcore file.
kcore=$(sudo chroot-distro login alpine -- ls -l /proc/kcore)
echo "$kcore"
if ! echo "$kcore" | grep -q "1, *3"; then
	echo "FAIL: /proc/kcore is not masked with /dev/null"
	exit 1
fi
if echo "$kcore" | grep -qv "^c"; then
	echo "FAIL: /proc/kcore is not a character device"
	exit 1
fi
echo "PASS: /proc/kcore masked"

# /proc/sys is read-only: the ro self-bind shows in the guest's own mount table
# (touching a new name under it answers ENOENT whether or not it is masked).
line=$(sudo chroot-distro login alpine -- sh -c 'grep " /proc/sys " /proc/mounts')
echo "$line"
if ! echo "$line" | grep -qw "ro"; then
	echo "FAIL: /proc/sys is writable"
	exit 1
fi
echo "PASS: /proc/sys read-only"

# /proc/sysrq-trigger is read-only too.
out=$(sudo chroot-distro login alpine -- sh -c 'touch /proc/sysrq-trigger 2>&1' || true)
echo "$out"
if ! echo "$out" | grep -q "Read-only file system"; then
	echo "FAIL: /proc/sysrq-trigger is writable"
	exit 1
fi
echo "PASS: /proc/sysrq-trigger read-only"

# binfmt_misc still mounts after the read-only mask on /proc/sys.
out=$(sudo chroot-distro login alpine -- ls /proc/sys/fs/binfmt_misc/register 2>&1)
echo "$out"
if ! echo "$out" | grep -q "/proc/sys/fs/binfmt_misc/register"; then
	echo "FAIL: binfmt_misc did not mount under the read-only /proc/sys"
	exit 1
fi
echo "PASS: binfmt_misc mounted after masking"

#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
# Namespace: the holder reaps orphans and exits on SIGTERM
# Needs: 01-install (debian).

set -e

# A guest session that stays alive while a second guest double-forks an orphan
# and sweeps /proc for zombies. The orphan reparents to the holder (PID 1 of
# the namespace); a holder that never waits would keep it as a Z-state entry.
sudo env CD_USE_NS=1 chroot-distro login debian -- sh -c 'sleep 4' >/dev/null 2>&1 &
KEEPER=$!
sleep 0.5

out=$(sudo env CD_USE_NS=1 chroot-distro login debian -- sh -c '
	(sleep 0.3 &)
	sleep 0.9
	found=0
	for stat in /proc/[0-9]*/stat; do
		[ -r "$stat" ] || continue
		read -r _pid _comm state _rest < "$stat" || continue
		if [ "$state" = "Z" ]; then
			echo "zombie: $stat ($state)"
			found=1
		fi
	done
	exit $found
') && swept=0 || swept=$?
kill "$KEEPER" 2>/dev/null || true
wait "$KEEPER" 2>/dev/null || true

if [ "$swept" -ne 0 ]; then
	echo "FAIL: zombie found under the namespace holder"
	echo "$out"
	exit 1
fi
echo "PASS: holder reaps reparented orphans (no zombies in /proc)"

# The holder must die on SIGTERM (a bare PID 1 ignores it and every teardown
# burns the SIGKILL fallback). A detached run leaves the holder alive with no
# interactive session, which is the production state teardown acts on.
data=$(sudo chroot-distro info 2>&1 | grep -m1 "Data location:" |
	sed 's/.*Data location:[[:space:]]*//')
pid_file="$data/data/debian/holder.pid"

sudo env CD_USE_NS=1 chroot-distro run debian --detach -- sh -c 'sleep 10' >/dev/null 2>&1
sleep 0.6
holder=$(sudo head -n1 "$pid_file")
if [ -z "$holder" ]; then
	echo "FAIL: no holder pid recorded at $pid_file"
	exit 1
fi
echo "Holder pid: $holder"

sudo kill -TERM "$holder"
gone=1
for _ in $(seq 1 40); do
	if ! sudo kill -0 "$holder" 2>/dev/null; then
		gone=0
		break
	fi
	sleep 0.05
done
if [ "$gone" -ne 0 ]; then
	echo "FAIL: holder ignored SIGTERM"
	sudo kill -KILL "$holder" 2>/dev/null || true
	exit 1
fi
echo "PASS: holder exits on SIGTERM"

# The state must still self-heal: a later command clears what is left.
sudo chroot-distro unmount debian
echo "PASS: unmount after holder exit cleans state"

# The killed holder left a stale isolation mode behind; the plain login is
# what trips over it.
sudo chroot-distro login debian -- true
echo "PASS: plain login works after the killed holder is unmounted"

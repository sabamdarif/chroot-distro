# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
"""`chroot-distro kill`: stop everything in a container and tear its state down.

Where `unmount` waits for the container lock, this takes it non-blocking and carries
on without it. A container that has to be killed is one whose sessions are not
cooperating, so a busy lock cannot be a reason to stop; it is retried once the
processes are gone and released in the `finally`.

The escalation is ordered, and mounts come before signals: standard unmount, lazy
unmount, then the image's own StopSignal with SIGKILL after a grace period, then
unmount and lazy again, then MNT_FORCE. Trying the mounts first means a session that
merely finished is let go instead of killed. Only when MNT_FORCE also leaves
something behind does the command fail, naming both the mounts and the PIDs.

Every umount goes through the holder when one is alive, since a mount made inside
its namespace is not visible from here. The session count, mount options, holder and
isolation mode are cleared last, and only on success.

The positional argument may be a PID from `ps`, resolved through the session
registry, so a host PID owning no container is refused rather than signalled.
"""

import contextlib
import json
import os
import signal
import sys
import time

import chroot_distro.helpers.mount_manager as mount_manager
import chroot_distro.helpers.namespace as namespace
import chroot_distro.helpers.session as session
from chroot_distro.locking import ContainerLock
from chroot_distro.message import crit_error, log_info, warn
from chroot_distro.names import require_valid_name
from chroot_distro.paths import container_rootfs

_SIGTERM_GRACE_SECS = 1.0
_SIGKILL_WAIT_SECS = 2.0


def _read_stop_signal(container_name: str) -> int:
    """Read StopSignal from manifest, return signal number."""
    from chroot_distro.paths import container_manifest

    try:
        with open(container_manifest(container_name)) as fh:
            data = json.load(fh)
        sig_str = (data.get("image_config") or {}).get("config", {}).get("StopSignal", "")
        if not sig_str:
            return signal.SIGTERM
        if sig_str.isdigit():
            return int(sig_str)
        return getattr(signal, sig_str, signal.SIGTERM)
    except (OSError, ValueError, json.JSONDecodeError):
        return signal.SIGTERM


def _wait_until_gone(container_name: str, timeout: float) -> list[int]:
    """Poll for active chroot PIDs until none remain or *timeout* elapses."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        remaining = session.get_active_chroot_pids(container_name)
        if not remaining:
            return []
        time.sleep(0.1)
    return session.get_active_chroot_pids(container_name)


def command_kill(args) -> None:
    """Forcibly stop all processes in a container and tear it down.

    First try standard unmount, then lazy unmount. If mounts remain or processes
    are active, kill all processes and retry unmounting. If still failing,
    try forceful unmount and print a detailed error if mounts remain.

    The positional argument may be a container name **or** a numeric PID from
    ``chroot-distro ps``.  When a PID is given it is resolved to the owning
    container via the session registry; arbitrary host PIDs are rejected.
    """
    container_or_pid = args.container_or_pid

    # Resolve numeric PID to the owning container name.
    if container_or_pid.isdigit():
        from chroot_distro.helpers.session_registry import resolve_container_by_pid

        pid_value = int(container_or_pid)
        container_name = resolve_container_by_pid(pid_value)
        if container_name is None:
            crit_error(f"No running container found with PID {pid_value}.")
            sys.exit(1)
    else:
        container_name = container_or_pid

    require_valid_name(container_name)

    rootfs_dir = container_rootfs(container_name)
    stop_signal = _read_stop_signal(container_name)
    if not os.path.isdir(rootfs_dir):
        crit_error(f"container '{container_name}' is not installed.")
        sys.exit(1)

    holder = namespace.get_live_holder(container_name)

    active_pids = session.get_active_chroot_pids(container_name)
    active_mounts = mount_manager.get_active_mounts(rootfs_dir, holder=holder)
    if not active_pids and holder is None and not active_mounts:
        log_info(f"Container '{container_name}' is not running.")
        return

    def run_umount(target_path: str, *, lazy: bool = False, force: bool = False) -> bool:
        try:
            if holder is not None:
                holder.do_umount(target_path, lazy=lazy, force=force)
            else:
                from chroot_distro.syscalls.umount import native_umount

                native_umount(target_path, lazy=lazy, force=force)
            return True
        except Exception as exc:
            log_info(f"Unmount of {target_path} failed: {exc}")
            return False

    lock = ContainerLock(container_name, exclusive=True, command="kill")
    acquired = lock.acquire()
    if not acquired:
        log_info(f"Container '{container_name}' is busy (active sessions exist). Forcing cleanup...")

    try:
        active_mounts = mount_manager.get_active_mounts(rootfs_dir, holder=holder)
        if active_mounts:
            log_info("Attempting standard unmount of active mount points...")
            for m in active_mounts:
                run_umount(m)

        active_mounts = mount_manager.get_active_mounts(rootfs_dir, holder=holder)
        if active_mounts:
            log_info("Some mounts remain busy. Attempting lazy unmount...")
            for m in active_mounts:
                run_umount(m, lazy=True)

        active_pids = session.get_active_chroot_pids(container_name)
        active_mounts = mount_manager.get_active_mounts(rootfs_dir, holder=holder)
        if active_pids or active_mounts:
            if active_pids:
                log_info(
                    f"Killing {len(active_pids)} process(es) in container '{container_name}' (PIDs: {active_pids})..."
                )
                for pid in active_pids:
                    with contextlib.suppress(OSError):
                        os.kill(pid, stop_signal)

                remaining = _wait_until_gone(container_name, _SIGTERM_GRACE_SECS)
                if remaining:
                    log_info(f"Processes {remaining} did not exit; sending SIGKILL...")
                    for pid in remaining:
                        with contextlib.suppress(OSError):
                            os.kill(pid, signal.SIGKILL)
                    remaining = _wait_until_gone(container_name, _SIGKILL_WAIT_SECS)
                    if remaining:
                        warn(f"Some processes could not be killed: {remaining}")

            if not acquired:
                acquired = lock.acquire()

            active_mounts = mount_manager.get_active_mounts(rootfs_dir, holder=holder)
            if active_mounts:
                log_info("Retrying standard unmount after killing processes...")
                for m in active_mounts:
                    run_umount(m)

                active_mounts = mount_manager.get_active_mounts(rootfs_dir, holder=holder)
                if active_mounts:
                    log_info("Retrying lazy unmount after killing processes...")
                    for m in active_mounts:
                        run_umount(m, lazy=True)

        active_mounts = mount_manager.get_active_mounts(rootfs_dir, holder=holder)
        if active_mounts:
            log_info("Some mounts still remain. Attempting forceful unmount...")
            for m in active_mounts:
                run_umount(m, force=True)

            active_mounts = mount_manager.get_active_mounts(rootfs_dir, holder=holder)
            if active_mounts:
                active_pids = session.get_active_chroot_pids(container_name)
                crit_error(
                    f"Failed to kill and unmount container '{container_name}'.\n"
                    f"Remaining active mounts:\n" + "\n".join(f"  - {m}" for m in active_mounts) + "\n"
                    f"Remaining active process PIDs: {active_pids if active_pids else 'None'}"
                )
                sys.exit(1)

        session.reset(container_name)
        session.clear_mount_options(container_name)
        if holder is not None:
            namespace.release_holder(container_name)
            namespace.clear_isolation_mode(container_name)

        log_info(f"Container '{container_name}' successfully killed and unmounted.")

    finally:
        if acquired:
            lock.release()


__all__ = ("command_kill",)

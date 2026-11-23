# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
"""Pass credentials and build inputs to the root CLI without putting them in argv.

An unprivileged child keeps an anonymous file open while the original CLI
execs the elevation tool. The child's parent-death signal bounds that file's
lifetime even when authentication fails. The receiver pins and checks the
inode before reading it. Only the fixed credential names enter the root
environment. Build inputs remain a separate mapping.
"""

import json
import os
import re
import signal
import stat
import tempfile
from argparse import Namespace
from collections.abc import Iterator
from contextlib import ExitStack, contextmanager, suppress

from chroot_distro.exceptions import RootRequiredError
from chroot_distro.syscalls._constants import PR_SET_PDEATHSIG
from chroot_distro.syscalls._libc import check_syscall, libc_prctl

HANDOFF_ENV = "_CHROOT_DISTRO_ELEVATION_FD"
_SECRET_ENV_VARS = ("CD_DOCKER_AUTH", "CD_ENV")
_MAX_BYTES = 1024 * 1024
_DESCRIPTOR = re.compile(r"([1-9][0-9]{0,9}):([0-9]{1,10}):([1-9][0-9]{0,9})")


def _build_inputs(args: Namespace) -> dict[str, str]:
    names = {item for item in getattr(args, "build_args", []) if item and "=" not in item}
    for item in getattr(args, "secrets", []):
        fields = {key.strip(): value for key, _, value in (part.partition("=") for part in item.split(","))}
        if not (fields.get("src") or fields.get("source")) and (name := fields.get("id")):
            names.add(name)
    if any(not spec.partition("=")[2] for spec in getattr(args, "ssh", [])):
        names.add("SSH_AUTH_SOCK")
    return {name: os.environ[name] for name in names if name in os.environ}


def _keep_fd(fd: int, ready: int, parent: int) -> None:
    try:
        check_syscall(libc_prctl(PR_SET_PDEATHSIG, signal.SIGKILL), "prctl(PR_SET_PDEATHSIG)")
        if os.getppid() != parent:
            return
        os.setsid()
        for name in os.listdir("/proc/self/fd"):
            other = int(name)
            if other not in (fd, ready):
                with suppress(OSError):
                    os.close(other)
        os.write(ready, b"1")
        os.close(ready)
        while True:
            signal.pause()
    finally:
        os._exit(1)


@contextmanager
def send_handoff(args: Namespace) -> Iterator[str]:
    """Yield the keeper's descriptor reference until exec or launch failure."""
    secrets = {name: os.environ[name] for name in _SECRET_ENV_VARS if name in os.environ}
    build_inputs = _build_inputs(args)
    if not secrets and not build_inputs:
        yield ""
        return
    payload = json.dumps({"secrets": secrets, "build": build_inputs}).encode("ascii")
    if len(payload) > _MAX_BYTES:
        raise RootRequiredError("Elevation environment is too large.")

    with tempfile.TemporaryFile() as spool:
        fd = spool.fileno()
        os.fchmod(fd, 0o600)
        spool.write(payload)
        spool.flush()
        parent = os.getpid()
        read_fd, write_fd = os.pipe()
        try:
            keeper = os.fork()
        except BaseException:
            os.close(write_fd)
            os.close(read_fd)
            raise
        if keeper == 0:
            _keep_fd(fd, write_fd, parent)
        os.close(write_fd)
        try:
            if os.read(read_fd, 1) != b"1":
                raise RootRequiredError("Could not prepare the elevation environment.")
            yield f"{keeper}:{fd}:{os.geteuid()}"
        finally:
            os.close(read_fd)
            with suppress(ProcessLookupError):
                os.kill(keeper, signal.SIGKILL)
            os.waitpid(keeper, 0)


def _read_handoff(ref: str) -> bytes:
    match = _DESCRIPTOR.fullmatch(ref)
    if match is None:
        raise ValueError("invalid descriptor reference")
    pid, fd, uid = match.groups()
    owner = int(uid)
    with ExitStack() as stack:
        process = os.open(f"/proc/{pid}", os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW)
        stack.callback(os.close, process)
        if os.fstat(process).st_uid != owner:
            raise ValueError("invalid descriptor owner")
        inode = os.open(f"fd/{fd}", os.O_PATH, dir_fd=process)
        stack.callback(os.close, inode)
        info = os.fstat(inode)
        if (
            info.st_mode != (stat.S_IFREG | 0o600)
            or info.st_uid != owner
            or info.st_nlink != 0
            or not 0 < info.st_size <= _MAX_BYTES
        ):
            raise ValueError("invalid handoff inode")
        stream = stack.enter_context(open(f"/proc/self/fd/{inode}", "rb"))
        return stream.read(_MAX_BYTES + 1)


def _validate_env(values: object) -> dict[str, str]:
    if not isinstance(values, dict) or any(
        not isinstance(key, str) or not key or "=" in key or "\0" in key or not isinstance(value, str) or "\0" in value
        for key, value in values.items()
    ):
        raise ValueError("invalid environment mapping")
    return values


def receive_handoff() -> dict[str, str]:
    """Consume the root CLI's reference and return the caller's build inputs."""
    ref = os.environ.pop(HANDOFF_ENV, "")
    if not ref:
        return {}
    try:
        data = _read_handoff(ref)
        if len(data) > _MAX_BYTES:
            raise ValueError("oversized handoff")
        payload = json.loads(data)
        if not isinstance(payload, dict) or payload.keys() != {"secrets", "build"}:
            raise ValueError("invalid handoff payload")
        secrets = _validate_env(payload["secrets"])
        if secrets.keys() - set(_SECRET_ENV_VARS):
            raise ValueError("invalid credential name")
        build = _validate_env(payload["build"])
        for value in secrets.values():
            os.fsencode(value)
    except (OSError, ValueError, RecursionError) as exc:
        raise RootRequiredError("Could not read the environment passed by the elevation tool.") from exc
    os.environ.update(secrets)
    return build

import contextlib
import json
import os
import shlex
import subprocess
import sys

import chroot_distro.helpers.mount_manager as mount_manager
import chroot_distro.helpers.session as session
from chroot_distro.commands.login import bindings
from chroot_distro.commands.login.chroot_cmd import build_chroot_args
from chroot_distro.commands.login.env import (
    IMAGE_ENV_BLOCKED,
    inject_termux_profile,
    read_manifest_env,
    resolve_term,
)
from chroot_distro.helpers.android import ensure_data_suid, termux_home_owner_ids
from chroot_distro.commands.login.passwd import (
    align_user_to_termux_owner,
    find_passwd_by_uid,
    find_user_groups,
    read_group_gid,
    read_passwd_field,
    resolve_rootfs_path,
    resolve_host_home,
    set_passwd_uid_gid,
    sync_passwd_to_home_owner,
    sync_passwd_to_path_owner,
)
from chroot_distro.constants import (
    DEFAULT_PATH_ENV,
    IS_TERMUX,
    PROGRAM_NAME,
    TERMUX_HOME,
    TERMUX_PREFIX,
)
from chroot_distro.locking import ContainerLock
from chroot_distro.message import crit_error, warn
from chroot_distro.names import require_valid_name
from chroot_distro.paths import container_dir, container_rootfs


def command_login(args) -> None:
    """Spawn an interactive shell (or custom command) inside the container."""
    container_name = args.container_name
    require_valid_name(container_name)

    # We use non-exclusive lock for concurrent login sessions
    with ContainerLock(
        container_name, exclusive=False, command="login"
    ):
        _command_login_inner(container_name, args)


def _detect_dist_type(rootfs: str) -> str:
    termux_usr = rootfs + TERMUX_PREFIX
    if os.path.isfile(os.path.join(termux_usr, "bin", "login")):
        return "termux"
    return "normal"


def _resolve_login_user(rootfs: str, container_name: str, user_arg: str) -> dict:
    if ":" in user_arg:
        user_spec, group_spec = user_arg.split(":", 1)
        if not user_spec or not group_spec:
            crit_error("'--user' with ':' separator requires "
                       "both user and group to be non-empty.")
            sys.exit(1)
    else:
        user_spec = user_arg
        group_spec = None

    passwd_available = False
    try:
        passwd_path = resolve_rootfs_path(rootfs, "/etc/passwd")
        passwd_available = os.path.isfile(passwd_path)
    except OSError:
        pass

    if passwd_available:
        if user_spec.isdigit():
            uid = user_spec
            home, shell, primary_gid = find_passwd_by_uid(rootfs, user_spec)
            home = home or "/"
            shell = shell or "/bin/sh"
        else:
            try:
                with open(passwd_path) as fh:
                    user_found = any(
                        line.startswith(f"{user_spec}:") for line in fh
                    )
            except OSError:
                user_found = False
            if not user_found:
                crit_error(f"no user '{user_spec}' defined in /etc/passwd.")
                sys.exit(1)

            uid = read_passwd_field(rootfs, user_spec, 2)
            primary_gid = read_passwd_field(rootfs, user_spec, 3)
            home = read_passwd_field(rootfs, user_spec, 5) or "/"
            shell = read_passwd_field(rootfs, user_spec, 6) or "/bin/sh"

            if not uid:
                crit_error(f"failed to retrieve UID for user '{user_spec}'.")
                sys.exit(1)

        if group_spec is None:
            gid = primary_gid or uid
        elif group_spec.isdigit():
            gid = group_spec
        else:
            gid = read_group_gid(rootfs, group_spec)
            if not gid:
                crit_error(
                    f"no group '{group_spec}' defined in /etc/group."
                )
                sys.exit(1)
    else:
        if user_spec == "root":
            uid = "0"
        elif user_spec.isdigit():
            uid = user_spec
        else:
            crit_error(f"container '{container_name}' has no /etc/passwd; "
                       f"'--user' only accepts a numeric UID in this case.")
            sys.exit(1)
        if group_spec is None:
            gid = uid
        elif group_spec.isdigit():
            gid = group_spec
        else:
            crit_error(f"container '{container_name}' has no /etc/group; "
                       f"'--user' only accepts a numeric GID in group "
                       f"specification.")
            sys.exit(1)
        home = "/"
        shell = "/bin/sh"

    # Fetch supplementary groups
    gids = find_user_groups(rootfs, user_spec, gid)

    return {
        "name": user_spec,
        "uid": uid,
        "gid": gid,
        "groups": gids,
        "home": home,
        "shell": shell,
    }


def _build_termux_env(rootfs, extra_env, minimal):
    env: dict = {}
    termux_home_inner = TERMUX_HOME
    if not minimal:
        env["HOME"] = termux_home_inner
        env["PATH"] = f"{TERMUX_PREFIX}/bin"
        env["PREFIX"] = TERMUX_PREFIX
        env["TMPDIR"] = f"{TERMUX_PREFIX}/tmp"
    for entry in extra_env:
        key, _, val = entry.partition("=")
        if key:
            env[key] = val
    host_term = env.get("TERM") or os.environ.get("TERM", "")
    env["TERM"] = resolve_term(rootfs, host_term)
    host_colorterm = os.environ.get("COLORTERM", "")
    if host_colorterm:
        env["COLORTERM"] = host_colorterm
    return env


def _build_normal_env(rootfs, container_path, login_user, login_home,
                      extra_env, minimal, isolated):
    env: dict = {}

    if minimal:
        for entry in extra_env:
            key, _, val = entry.partition("=")
            if key:
                env[key] = val
        host_term = env.get("TERM") or os.environ.get("TERM", "")
        env["TERM"] = resolve_term(rootfs, host_term)
        host_colorterm = os.environ.get("COLORTERM", "")
        if host_colorterm:
            env["COLORTERM"] = host_colorterm
        return env

    env["PATH"] = DEFAULT_PATH_ENV
    if IS_TERMUX:
        env["MOZ_FAKE_NO_SANDBOX"] = "1"
        env["PULSE_SERVER"] = "127.0.0.1"

    for entry in read_manifest_env(container_path):
        key, _, val = entry.partition("=")
        if key and key not in IMAGE_ENV_BLOCKED:
            env[key] = val

    if IS_TERMUX and not isolated:
        for var in (
            "ANDROID_ART_ROOT", "ANDROID_DATA", "ANDROID_I18N_ROOT",
            "ANDROID_ROOT", "ANDROID_RUNTIME_ROOT",
            "ANDROID_TZDATA_ROOT",
            "BOOTCLASSPATH", "DEX2OATBOOTCLASSPATH", "EXTERNAL_STORAGE",
        ):
            val = os.environ.get(var, "")
            if val:
                env[var] = val

    for entry in extra_env:
        key, _, val = entry.partition("=")
        if key:
            env[key] = val

    env["HOME"] = login_home
    env["USER"] = login_user
    host_term = env.get("TERM") or os.environ.get("TERM", "")
    env["TERM"] = resolve_term(rootfs, host_term)
    host_colorterm = os.environ.get("COLORTERM", "")
    if host_colorterm:
        env["COLORTERM"] = host_colorterm
    return env


def _check_shell_available(rootfs, container_path, login_shell, container_name):
    try:
        shell_found = os.path.isfile(
            resolve_rootfs_path(rootfs, login_shell)
        )
    except OSError:
        shell_found = False
    if shell_found:
        return

    has_ep_or_cmd = False
    try:
        with open(os.path.join(container_path, "manifest.json")) as fh:
            data = json.load(fh)
        cfg = (data.get("image_config") or {}).get("config", {})
        has_ep_or_cmd = bool(
            (cfg.get("Entrypoint") or []) or (cfg.get("Cmd") or [])
        )
    except (OSError, ValueError):
        pass

    if has_ep_or_cmd:
        crit_error(f"shell '{login_shell}' is not available in container "
                   f"'{container_name}'. The image defines an Entrypoint or "
                   f"Cmd; use '{PROGRAM_NAME} run {container_name}' instead.")
    else:
        crit_error(f"shell '{login_shell}' is not available in container "
                   f"'{container_name}' and the image has no Entrypoint or "
                   f"Cmd defined.")
    sys.exit(1)





def _command_login_inner(container_name: str, args) -> None:
    rootfs = container_rootfs(container_name)
    if not os.path.isdir(rootfs):
        crit_error(f"container '{container_name}' is not installed.")
        sys.exit(1)

    dist_type = _detect_dist_type(rootfs)
    container_path = container_dir(container_name)

    login_user = getattr(args, "user", "root") or "root"
    login_wd = getattr(args, "work_dir", "") or ""
    isolated = getattr(args, "isolated", False)
    minimal = getattr(args, "minimal", False)
    use_shared_home = getattr(args, "shared_home", False)
    shared_tmp = getattr(args, "shared_tmp", False)
    shared_x11 = getattr(args, "shared_x11", False)
    custom_binds = getattr(args, "bind", []) or []
    extra_env = getattr(args, "env", []) or []
    login_cmd = getattr(args, "login_cmd", []) or []
    run_inner = getattr(args, "_run_inner", None)

    if dist_type == "termux":
        if not login_wd:
            login_wd = TERMUX_HOME
        child_env = _build_termux_env(rootfs, extra_env, minimal)

        if run_inner is not None:
            inner = run_inner
        else:
            inner = [f"{TERMUX_PREFIX}/bin/login"]
            if login_cmd:
                inner += ["-c", shlex.join(login_cmd)]
        login_uid = login_gid = login_home = groups = None
    else:
        user = _resolve_login_user(rootfs, container_name, login_user)
        login_user = user["name"]
        login_uid = user["uid"]
        login_gid = user["gid"]
        groups = user["groups"]
        login_home = user["home"]
        login_shell = user["shell"]
        passwd_home = login_home

        if use_shared_home and not minimal:
            try:
                if IS_TERMUX:
                    termux_owner_uid, termux_owner_gid = termux_home_owner_ids()
                    aligned = align_user_to_termux_owner(
                        rootfs,
                        login_user,
                        termux_owner_uid,
                        termux_owner_gid,
                    )
                else:
                    host_home = resolve_host_home(login_user)
                    if not host_home or not os.path.isdir(host_home):
                        crit_error(
                            f"cannot determine host home for --shared-home "
                            f"with user '{login_user}'. Run via sudo from your "
                            f"normal user account (so SUDO_USER is set), or add "
                            f"--bind HOST_HOME:{login_home}."
                        )
                        sys.exit(1)
                    if login_user == "root":
                        set_passwd_uid_gid(rootfs, "root", 0, 0)
                        aligned = True
                    else:
                        aligned = sync_passwd_to_path_owner(
                            rootfs, login_user, host_home,
                        )
                        if not aligned:
                            crit_error(
                                f"refusing to map user '{login_user}' to root for "
                                f"--shared-home (host home resolved to '{host_home}'). "
                                f"Run via sudo from your normal user account."
                            )
                            sys.exit(1)
                if aligned:
                    user = _resolve_login_user(
                        rootfs, container_name, login_user,
                    )
                    login_uid = user["uid"]
                    login_gid = user["gid"]
                    groups = user["groups"]
            except OSError as exc:
                warn(f"cannot align user for shared home: {exc}")
        elif not use_shared_home and not minimal and login_home:
            if sync_passwd_to_home_owner(rootfs, login_user, login_home):
                user = _resolve_login_user(
                    rootfs, container_name, login_user,
                )
                login_uid = user["uid"]
                login_gid = user["gid"]
                groups = user["groups"]

        if login_home and login_home != "/" and login_home == passwd_home:
            try:
                host_home_path = resolve_rootfs_path(rootfs, login_home)
                home_exists = os.path.isdir(host_home_path)
            except OSError:
                home_exists = False
                host_home_path = os.path.join(rootfs, login_home.lstrip("/"))

            if not home_exists:
                try:
                    os.makedirs(host_home_path, exist_ok=True)
                    uid_int = int(login_uid) if login_uid is not None else 0
                    gid_int = int(login_gid) if login_gid is not None else 0
                    os.chown(host_home_path, uid_int, gid_int)
                    os.chmod(host_home_path, 0o755)
                except Exception as e:
                    warn(f"failed to create home directory {login_home}: {e}")

        if not login_wd:
            login_wd = login_home

        child_env = _build_normal_env(
            rootfs, container_path, login_user, login_home,
            extra_env, minimal, isolated,
        )

        if run_inner is not None:
            inner = run_inner
        else:
            _check_shell_available(rootfs, container_path, login_shell, container_name)
            inner = [login_shell, "-c", shlex.join(login_cmd)] if login_cmd else [login_shell, "-l"]

    if IS_TERMUX and not isolated and not minimal:
        termux_bin = f"{TERMUX_PREFIX}/bin"
        components = [
            c for c in child_env.get("PATH", "").split(":")
            if c and c != termux_bin
        ]
        components.append(termux_bin)
        child_env["PATH"] = ":".join(components)

    if dist_type == "normal" and IS_TERMUX and not isolated and not minimal:
        inject_termux_profile(rootfs, child_env)

    # 1. Resolve all bind mounts
    resolved_binds = bindings.get_bindings(
        rootfs=rootfs,
        minimal=minimal,
        isolated=isolated,
        shared_home=use_shared_home,
        shared_tmp=shared_tmp,
        shared_x11=shared_x11,
        custom_binds=custom_binds,
        login_home=login_home or "/root",
        login_user=login_user,
        dist_type=dist_type,
    )

    # 2. Increment session counter and mount if first session
    sess_count = session.increment(container_name)
    if sess_count == 1:
        if IS_TERMUX and not isolated and not minimal:
            ensure_data_suid()
        # Pre-clean stale mounts if any
        with contextlib.suppress(Exception):
            mount_manager.unmount_all(rootfs)
        # Phase 1: bind mounts
        for src, dst in resolved_binds:
            try:
                mount_manager.safe_mount(src, dst)
            except Exception as e:
                # Clean up and rollback
                mount_manager.unmount_all(rootfs)
                session.decrement(container_name)
                crit_error(f"Failed to mount bindings: {e}")
                sys.exit(1)

        # Phase 2: special filesystem mounts
        try:
            specials = bindings.get_special_mounts(
                rootfs,
                enable_usb=not minimal,
                enable_binfmt=not minimal,
                enable_docker_cgroup=not minimal,
                enable_shm=not minimal,
            )
            for sm in specials:
                mount_manager.apply_special_mount(rootfs, sm)
        except Exception as e:
            # Clean up and rollback
            mount_manager.unmount_all(rootfs)
            session.decrement(container_name)
            crit_error(f"Failed to apply special mounts: {e}")
            sys.exit(1)



    chroot_args = build_chroot_args(
        rootfs=rootfs,
        login_uid=login_uid,
        login_gid=login_gid,
        groups=groups,
        workdir=login_wd,
        inner_cmd=inner,
    )

    if getattr(args, "get_chroot_cmd", False):
        # Print command line representation
        parts = ["env", "-i"]
        for k, v in child_env.items():
            # escape values
            parts.append(f"{k}={shlex.quote(v)}")
        parts.extend(shlex.quote(a) for a in chroot_args)
        print(" \\\n  ".join(parts))

        # Decrement counter since we didn't actually login
        sess_count = session.decrement(container_name)
        if sess_count == 0:
            mount_manager.unmount_all(rootfs)
        sys.exit(0)

    # 4. Run the chroot process using subprocess.run, preserving the environment
    # child_env is passed directly to env parameter of subprocess.run
    try:
        subprocess.run(chroot_args, env=child_env, check=False)
    finally:
        # Decrement session counter and unmount if last session
        sess_count = session.decrement(container_name)
        if sess_count == 0:
            mount_manager.unmount_all(rootfs)


__all__ = ("command_login",)

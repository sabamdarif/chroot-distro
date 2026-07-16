import contextlib
import json
import logging
import os
import shlex
import signal
import subprocess
import sys
from collections.abc import Callable

import chroot_distro.helpers.mount_manager as mount_manager
import chroot_distro.helpers.namespace as namespace
import chroot_distro.helpers.session as session
from chroot_distro.commands.login import bindings
from chroot_distro.commands.login.chroot_cmd import ChrootConfig, build_chroot_args, build_chroot_config
from chroot_distro.commands.login.env import (
    ANDROID_HOST_ENV_VARS,
    IMAGE_ENV_BLOCKED,
    inject_termux_profile,
    read_cd_env,
    read_manifest_env,
    read_manifest_exposed_ports,
    read_manifest_shell,
    read_manifest_user,
    read_manifest_volumes,
    read_manifest_workdir,
    resolve_override,
    resolve_term,
)
from chroot_distro.commands.login.passwd import (
    align_user_to_termux_owner,
    find_passwd_by_uid,
    find_user_groups,
    read_group_gid,
    read_passwd_field,
    reown_home_tree_for_uid,
    resolve_host_home,
    resolve_rootfs_path,
    set_passwd_uid_gid,
    sync_passwd_to_home_owner,
    sync_passwd_to_path_owner,
)
from chroot_distro.constants import (
    DEFAULT_PATH_ENV,
    IS_TERMUX,
    PROGRAM_NAME,
    TERMUX_APP_PACKAGE,
    TERMUX_HOME,
    TERMUX_PREFIX,
)
from chroot_distro.helpers import gpu as gpu_helper
from chroot_distro.helpers import isolation
from chroot_distro.helpers.android import ensure_data_suid, termux_home_owner_ids
from chroot_distro.helpers.display import (
    resolve_display_env,
    resolve_display_socket_binds,
)
from chroot_distro.helpers.isolation import resolve_isolated, safe_hostname
from chroot_distro.helpers.namespace import NamespaceError
from chroot_distro.helpers.nvidia import (
    detect_nvidia_gpu,
    nvidia_env_vars,
    run_ldconfig_in_chroot,
)
from chroot_distro.helpers.rootfs import ensure_hosts_entry
from chroot_distro.helpers.session_registry import register_session
from chroot_distro.helpers.x11 import (
    guest_can_read_auth,
    provision_guest_xauthority,
    resolve_invoking_uid,
    x11_auth_bind_path,
)
from chroot_distro.locking import ContainerLock
from chroot_distro.message import crit_error, warn
from chroot_distro.names import require_valid_name
from chroot_distro.paths import container_dir, container_log_path, container_rootfs
from chroot_distro.syscalls.chroot import chroot_and_run
from chroot_distro.syscalls.nsenter import enter_and_run_with_pty

log = logging.getLogger(__name__)


# Canonical hostname sanitiser now lives in helpers.isolation so login and the
# isolated build path share one policy; keep the private name for local callers.
_safe_hostname = safe_hostname


def command_login(args) -> None:
    """Spawn an interactive shell (or custom command) inside the container."""
    container_name = args.container_name
    require_valid_name(container_name)

    # We use non-exclusive lock for concurrent login sessions
    with ContainerLock(container_name, exclusive=False, command="login"):
        _command_login_inner(container_name, args)


def _detect_dist_type(rootfs: str) -> str:
    termux_usr = rootfs + TERMUX_PREFIX
    login_path = os.path.join(termux_usr, "bin", "login")
    if os.path.isfile(login_path):
        # Guard against false positives caused by bind-mounted /data.
        # When a prior session bind-mounts host /data into rootfs, the
        # host Termux login binary appears at the checked path even for
        # normal Linux distros (Ubuntu, Debian, etc.).
        # Disambiguate: every normal distro ships /usr/bin as part of its
        # own filesystem (FHS standard).  No bind mount creates /usr/bin,
        # and Termux containers do not have it.
        if os.path.isdir(os.path.join(rootfs, "usr", "bin")):
            return "normal"
        return "termux"
    return "normal"


def _resolve_login_user(rootfs: str, container_name: str, user_arg: str) -> dict:
    if ":" in user_arg:
        user_spec, group_spec = user_arg.split(":", 1)
        if not user_spec or not group_spec:
            crit_error("'--user' with ':' separator requires both user and group to be non-empty.")
            sys.exit(1)
    else:
        user_spec = user_arg
        group_spec = None

    passwd_available = False
    passwd_path = ""
    try:
        passwd_path = resolve_rootfs_path(rootfs, "/etc/passwd")
        passwd_available = os.path.isfile(passwd_path)
    except OSError as exc:
        log.warning("Failed to check if passwd file is available: %s", exc)

    if passwd_available:
        if user_spec.isdigit():
            uid = user_spec
            home, shell, primary_gid = find_passwd_by_uid(rootfs, user_spec)
            home = home or "/"
            shell = shell or "/bin/sh"
        else:
            try:
                with open(passwd_path) as fh:
                    user_found = any(line.startswith(f"{user_spec}:") for line in fh)
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
                crit_error(f"no group '{group_spec}' defined in /etc/group.")
                sys.exit(1)
    else:
        if user_spec == "root":
            uid = "0"
        elif user_spec.isdigit():
            uid = user_spec
        else:
            crit_error(
                f"container '{container_name}' has no /etc/passwd; '--user' only accepts a numeric UID in this case."
            )
            sys.exit(1)
        if group_spec is None:
            gid = uid
        elif group_spec.isdigit():
            gid = group_spec
        else:
            crit_error(
                f"container '{container_name}' has no /etc/group; "
                f"'--user' only accepts a numeric GID in group "
                f"specification."
            )
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


def _merge_image_path(image_path: str, system_path: str) -> str:
    """Merge image PATH with system PATH — image dirs win (prepended).

    Directories from the image come first so that image-specific binaries
    are found before system-wide defaults.  System dirs that are not already
    present in the image PATH are appended so standard tools remain available.
    """
    image_dirs = [d for d in image_path.split(":") if d]
    system_dirs = [d for d in system_path.split(":") if d]
    seen: set[str] = set()
    merged: list[str] = []
    for d in image_dirs + system_dirs:
        if d not in seen:
            merged.append(d)
            seen.add(d)
    return ":".join(merged)


def _check_arch_mismatch(container_path: str) -> None:
    """Warn if the image architecture does not match the host CPU."""
    from chroot_distro.arch import get_device_cpu_arch, normalize_arch

    try:
        with open(os.path.join(container_path, "manifest.json")) as fh:
            data = json.load(fh)
        img_arch_raw = data.get("arch") or (data.get("image_config") or {}).get("architecture", "")
        if not img_arch_raw:
            return
        img_arch = normalize_arch(img_arch_raw) or img_arch_raw
        host_arch = get_device_cpu_arch()
        if img_arch == host_arch:
            return
        # Check binfmt_misc for cross-arch execution support.
        binfmt_dir = "/proc/sys/fs/binfmt_misc"
        if os.path.isdir(binfmt_dir):
            for entry in os.listdir(binfmt_dir):
                if entry in ("register", "status"):
                    continue
                try:
                    with open(os.path.join(binfmt_dir, entry)) as fh:
                        if "enabled" in fh.read():
                            return  # binfmt handler present
                except OSError:
                    continue
        warn(
            f"Image architecture '{img_arch}' does not match host "
            f"architecture '{host_arch}'. Binaries may fail to execute. "
            f"Install qemu-user-static and register binfmt_misc handlers "
            f"for cross-architecture support."
        )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        log.warning("Could not check container/host architecture mismatch: %s", exc)


def _build_termux_env(rootfs, container_path, extra_env, minimal, isolated, container_name=""):
    env: dict = {}
    if not minimal:
        env["HOME"] = TERMUX_HOME
        env["PATH"] = f"{TERMUX_PREFIX}/bin"
        env["PREFIX"] = TERMUX_PREFIX
        env["TMPDIR"] = f"{TERMUX_PREFIX}/tmp"
        env["LANG"] = "en_US.UTF-8"
        env["ANDROID_DATA"] = "/data"
        env["ANDROID_ROOT"] = "/system"
        env["HOSTNAME"] = _safe_hostname(container_name)

    # Image manifest Env applies in every mode (including isolated and minimal).
    for entry in read_manifest_env(container_path):
        key, _, val = entry.partition("=")
        if key and key not in IMAGE_ENV_BLOCKED:
            if key == "PATH":
                env["PATH"] = _merge_image_path(val, env.get("PATH", ""))
            else:
                env[key] = val

    # Android system vars are inherited from the host only in the default
    # mode; isolated and minimal sessions keep just the image's values.
    if IS_TERMUX and not isolated and not minimal:
        for var in ANDROID_HOST_ENV_VARS:
            val = os.environ.get(var, "")
            if val:
                env[var] = val

    for entry in extra_env:
        key, _, val = entry.partition("=")
        if key:
            env[key] = val
    host_term = env.get("TERM") or os.environ.get("TERM", "")
    env["TERM"] = resolve_term(rootfs, host_term)
    host_colorterm = os.environ.get("COLORTERM", "")
    if host_colorterm:
        env["COLORTERM"] = host_colorterm
    # Never carry the *host* Termux dynamic-linker preloads into the guest:
    # a stale host libtermux-exec / LD_LIBRARY_PATH points at host paths that
    # do not exist inside the chroot, making the Termux linker emit
    # "This is <prog>, the helper program for dynamic executables" instead
    # of executing the binary.
    env.pop("LD_LIBRARY_PATH", None)
    # Never carry a libtermux-exec exec-shim into the guest via LD_PRELOAD.
    # chroot with `env -i` and no
    # preload, and the working manual recipe explicitly does `unset
    # LD_PRELOAD`. A stale or host-prefixed LD_PRELOAD that the guest linker
    # cannot resolve makes it print "This is <prog>, the helper program for
    # dynamic executables" instead of running the binary. The guest's own
    # $PREFIX/etc/profile (sourced via `login -l`) sets up the environment.
    env.pop("LD_PRELOAD", None)
    return env


def _build_normal_env(rootfs, container_path, login_user, login_home, extra_env, minimal, isolated, container_name=""):
    env: dict = {}

    if not minimal:
        env["PATH"] = DEFAULT_PATH_ENV
        env["HOSTNAME"] = _safe_hostname(container_name)
        if IS_TERMUX:
            env["MOZ_FAKE_NO_SANDBOX"] = "1"
            env["PULSE_SERVER"] = "127.0.0.1"

    # Image manifest Env applies in every mode (including isolated and minimal).
    for entry in read_manifest_env(container_path):
        key, _, val = entry.partition("=")
        if key and key not in IMAGE_ENV_BLOCKED:
            if key == "PATH":
                env["PATH"] = _merge_image_path(val, env.get("PATH", ""))
            else:
                env[key] = val

    # Android system vars are inherited from the host only in the default
    # mode; isolated and minimal sessions keep just the image's values.
    if IS_TERMUX and not isolated and not minimal:
        for var in ANDROID_HOST_ENV_VARS:
            val = os.environ.get(var, "")
            if val:
                env[var] = val

    for entry in extra_env:
        key, _, val = entry.partition("=")
        if key:
            env[key] = val

    if not minimal:
        env["HOME"] = login_home
        env["USER"] = login_user
    host_term = env.get("TERM") or os.environ.get("TERM", "")
    env["TERM"] = resolve_term(rootfs, host_term)
    host_colorterm = os.environ.get("COLORTERM", "")
    if host_colorterm:
        env["COLORTERM"] = host_colorterm
    return env


def _check_shell_available(rootfs, container_path, login_shell, container_name):
    """Verify *login_shell* exists in rootfs; return a fallback if found.

    Returns the original *login_shell* when it exists, or the image's
    ``Shell[0]`` when that is available as a fallback.  Exits with an
    error message if no usable shell can be found.
    """
    try:
        shell_found = os.path.isfile(resolve_rootfs_path(rootfs, login_shell))
    except OSError:
        shell_found = False
    if shell_found:
        return login_shell

    # Try the image manifest's Shell as a fallback before giving up.
    manifest_shell = read_manifest_shell(container_path)
    if manifest_shell:
        try:
            if os.path.isfile(resolve_rootfs_path(rootfs, manifest_shell)):
                log.info(
                    "Shell '%s' unavailable; falling back to image Shell '%s'.",
                    login_shell,
                    manifest_shell,
                )
                return manifest_shell
        except OSError as exc:
            log.debug("Failed to check if manifest shell is available: %s", exc)

    has_ep_or_cmd = False
    try:
        with open(os.path.join(container_path, "manifest.json")) as fh:
            data = json.load(fh)
        cfg = (data.get("image_config") or {}).get("config", {})
        has_ep_or_cmd = bool((cfg.get("Entrypoint") or []) or (cfg.get("Cmd") or []))
    except (OSError, ValueError) as exc:
        log.debug("Failed to read image Entrypoint/Cmd config from manifest: %s", exc)

    if has_ep_or_cmd:
        crit_error(
            f"shell '{login_shell}' is not available in container "
            f"'{container_name}'. The image defines an Entrypoint or "
            f"Cmd; use '{PROGRAM_NAME} run {container_name}' instead."
        )
    else:
        crit_error(
            f"shell '{login_shell}' is not available in container "
            f"'{container_name}' and the image has no Entrypoint or "
            f"Cmd defined."
        )
    sys.exit(1)


class _MaxIsolationFallback(Exception):  # noqa: N818
    """Internal signal: max isolation failed mid-setup and the login should be
    retried in the old isolated mode (host binds + host /proc, namespaces
    where supported). Raised on Android where SELinux denies the fresh
    pseudo-filesystems and kills the chrooted holder."""


def _can_fall_back_to_old_isolated(max_isolation: bool, args) -> bool:
    """Return True if a failed max-isolation setup may degrade to old isolated.

    Only on Android/Termux and only once: the retry sets
    ``args._disable_max_isolation`` so a second failure is reported normally
    instead of looping. On a real Linux host we keep refusing, since the user
    explicitly asked for the strong, escape-proof mode and it should work.
    """
    if not (max_isolation and IS_TERMUX):
        return False
    return not getattr(args, "_disable_max_isolation", False)


def _command_login_inner(container_name: str, args) -> None:
    """Run the login, degrading max isolation to the old isolated mode once if
    it cannot be set up on this (Android) kernel."""
    try:
        _command_login_inner_once(container_name, args)
    except _MaxIsolationFallback as exc:
        warn(
            "Maximum isolation could not be set up on this Android kernel "
            f"({exc}). Falling back to the standard isolated mode (host /dev, "
            "/sys and /proc are bound, with namespaces where the kernel "
            "supports them). This is the pre-existing --isolated behaviour and "
            "is NOT fully escape-proof on Android. Use a Linux host whose "
            "kernel supports namespaces for maximum isolation."
        )
        args._disable_max_isolation = True
        _command_login_inner_once(container_name, args)


def _translate_host_path_to_guest(host_path: str, rootfs: str, resolved_binds: list[tuple[str, str]]) -> str:
    """Translate a host path to its corresponding guest path based on the resolved bind mounts."""
    host_path = os.path.normpath(host_path)

    best_match_src = None
    best_match_dst = None

    for src, dst in resolved_binds:
        src_norm = os.path.normpath(src)
        # Check if host_path starts with src_norm.
        match = host_path == src_norm or host_path.startswith(src_norm + os.sep)

        if match and (best_match_src is None or len(src_norm) > len(best_match_src)):
            best_match_src = src_norm
            best_match_dst = dst

    if best_match_src is not None and best_match_dst is not None:
        rel_to_rootfs = os.path.relpath(best_match_dst, rootfs)
        guest_base = "/" if rel_to_rootfs == "." else "/" + rel_to_rootfs.lstrip("/")

        rel_from_src = os.path.relpath(host_path, best_match_src)
        if rel_from_src == ".":
            return guest_base
        return os.path.normpath(os.path.join(guest_base, rel_from_src))

    return host_path


def _command_login_inner_once(container_name: str, args) -> None:
    rootfs = container_rootfs(container_name)
    if not os.path.isdir(rootfs):
        crit_error(f"container '{container_name}' is not installed.")
        sys.exit(1)

    dist_type = _detect_dist_type(rootfs)
    container_path = container_dir(container_name)

    # Warn early if the image architecture doesn't match the host CPU.
    _check_arch_mismatch(container_path)

    # Fold the CD_* env-var overrides in before the image-config fallbacks so
    # precedence stays CLI flag > CD_* env > image default. On the `run` path
    # these are already resolved by command_run, so these are no-ops there.
    if getattr(args, "user", None) is None:
        args.user = resolve_override(None, "CD_USER")
    if not getattr(args, "work_dir", None):
        args.work_dir = resolve_override(None, "CD_WORKDIR")

    # Resolve login user: explicit --user (or CD_USER) wins, then image
    # manifest User, then fall back to "root".
    _explicit_user = getattr(args, "user", None)
    if _explicit_user is not None:
        login_user = _explicit_user
    else:
        manifest_user = read_manifest_user(container_path)
        login_user = manifest_user if manifest_user else "root"
    login_wd = getattr(args, "work_dir", "") or ""
    # `--isolated`/`--isolate` OR `CD_USE_ISOLATION=1` (env forces it on even
    # without the flag). `CD_USE_NS` is handled separately (namespace-only).
    isolated = resolve_isolated(args)
    minimal = getattr(args, "minimal", False)
    # `--isolated` skips the extra Android/host mounts AND uses namespaces.
    # `CD_USE_NS` only turns on namespace isolation, keeping every mount.
    # `skip_extra_mounts` therefore tracks only the real `--isolated` flag,
    # while namespace setup is decided separately by should_use_namespaces().
    skip_extra_mounts = isolated
    use_ns_requested = namespace.should_use_namespaces(isolated)
    # `--isolated` is the maximum-isolation tier: it binds NOTHING from the
    # host (not even /dev or /sys), so the container cannot reach the host
    # filesystem (e.g. via `chroot /proc/1/root`). Any flag that only works by
    # exposing a host path is therefore inert and must be reported + disabled.
    #
    # `_disable_max_isolation` is an internal opt-out set when max isolation
    # fails mid-setup on Android (SELinux denies the fresh tmpfs /dev and then
    # kills the chrooted holder, so nsenter can no longer open its ns/mnt).
    # In that case we re-enter with max isolation off, which keeps the old
    # `--isolated` behaviour: fewer host mounts plus namespaces where the
    # kernel supports them, but the host /dev, /sys and /proc are bound again
    # so the session can actually come up. `--isolated` therefore degrades to
    # the old isolated mode on Android instead of aborting.
    max_isolation = isolated and not getattr(args, "_disable_max_isolation", False)
    use_shared_home = getattr(args, "shared_home", False)
    shared_tmp = getattr(args, "shared_tmp", False)
    shared_display = getattr(args, "shared_display", False)

    if max_isolation:
        disabled = []
        if use_shared_home:
            disabled.append("--shared-home")
        if shared_tmp:
            disabled.append("--shared-tmp")
        if shared_display:
            disabled.append("--shared-display")
        if getattr(args, "bind", None):
            disabled.append("--bind")
        if disabled:
            warn(
                "--isolated provides maximum isolation and does not bind any "
                "host paths into the container; the following "
                f"flag(s) are ignored: {', '.join(disabled)}. "
                "Drop --isolated (or use CD_USE_NS=1 for namespace isolation "
                "that keeps the default mounts) if you need them."
            )
        # Force every host-path-sharing option off so nothing is exposed.
        use_shared_home = False
        shared_tmp = False
        shared_display = False
        args.bind = []
    # Effective hostname is the container name.
    # Sanitised to a valid hostname token by the env builders / UTS setter.
    hostname_arg = container_name

    # sudo and friends reverse-resolve the running hostname; ensure guest
    # /etc/hosts maps both the effective container hostname (seen under
    # --isolated) and the live kernel UTS name (seen without --isolated) to
    # 127.0.0.1, so they do not fail with "unable to resolve host <name>".
    if not minimal:
        try:
            live_nodename = os.uname().nodename
        except OSError:
            live_nodename = ""
        ensure_hosts_entry(rootfs, _safe_hostname(hostname_arg), live_nodename)
    raw_custom_binds = getattr(args, "bind", []) or []
    # The third ":options" field (e.g. ro) is parsed out here; get_bindings
    # only understands host:guest specs.
    bind_options_map = bindings.parse_bind_options(raw_custom_binds)
    custom_binds = bindings.strip_bind_options(raw_custom_binds)
    # CD_ENV entries are layered first so a matching --env override wins.
    extra_env = read_cd_env() + (getattr(args, "env", []) or [])
    login_cmd = getattr(args, "login_cmd", []) or []
    run_inner = getattr(args, "_run_inner", None)

    # Auto-detect NVIDIA GPU on the host (not relevant for Termux). Skipped
    # under --isolated: GPU integration binds host device nodes and libraries,
    # which would defeat maximum isolation.
    has_nvidia = False
    if not IS_TERMUX and not minimal and not max_isolation:
        has_nvidia = detect_nvidia_gpu()

    # AMD/Intel/Mesa GPUs work via the /dev bind, but the container needs the
    # host's Vulkan/EGL/OpenCL ICD descriptors to enumerate the GPU. Bind
    # those config dirs read-only, unless the user already bound the same
    # guest path explicitly.
    if not IS_TERMUX and not minimal and not max_isolation:
        existing_guest = {"/" + dst.strip("/") for dst in bind_options_map} | {
            "/" + bindings._split_bind_spec(spec)[1].strip("/") for spec in raw_custom_binds
        }
        # AMD/Intel: bind only the host's ICD / loader-config descriptors so
        # the container's own Mesa stack can enumerate /dev/dri. The driver
        # .so files are intentionally NOT bound: shadowing a container's own
        # apt/dpkg-managed Mesa libraries corrupts its loader.
        for src, dst in gpu_helper.find_gpu_icd_binds(rootfs):
            norm_dst = "/" + dst.strip("/")
            if norm_dst in existing_guest:
                continue
            custom_binds.append(f"{src}:{dst}")
            bind_options_map[norm_dst] = "ro"
            existing_guest.add(norm_dst)

    if dist_type == "termux":
        if not login_wd:
            login_wd = TERMUX_HOME
        child_env = _build_termux_env(
            rootfs,
            container_path,
            extra_env,
            minimal,
            skip_extra_mounts,
            container_name=hostname_arg,
        )

        # A termux-type guest still needs its own cache dir to exist; create
        # it inside the rootfs (never bound from the host).
        if IS_TERMUX and not skip_extra_mounts:
            os.makedirs(
                os.path.join(rootfs, "data", "data", TERMUX_APP_PACKAGE, "cache"),
                exist_ok=True,
            )

        if run_inner is not None:
            inner = run_inner
        else:
            inner = [f"{TERMUX_PREFIX}/bin/login"]
            if login_cmd:
                inner += ["-c", shlex.join(login_cmd)]
        # Resolve user/group from the owner of the Termux home directory inside the rootfs.
        # This ensures we match the ownership of the files in the container (e.g., UID 1000
        # on standard Linux, or the Termux app UID on Android), which is required because
        # Termux executables are often restricted to 700 permissions.
        termux_home_path = os.path.join(rootfs, TERMUX_HOME.lstrip("/"))
        try:
            st = os.stat(termux_home_path)
            login_uid = str(st.st_uid)
            login_gid = str(st.st_gid)
        except OSError:
            login_uid = str(resolve_invoking_uid())
            login_gid = login_uid

        login_home = TERMUX_HOME

        # Resolve supplementary groups from the invoking user to ensure proper group permissions
        invoking_uid = resolve_invoking_uid()
        try:
            import pwd

            username = pwd.getpwuid(invoking_uid).pw_name
            primary_gid = pwd.getpwuid(invoking_uid).pw_gid
            groups = [str(g) for g in os.getgrouplist(username, primary_gid)]
        except Exception:
            groups = [login_gid, "3003", "9997"] if IS_TERMUX else [login_gid]
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
                            rootfs,
                            login_user,
                            host_home,
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
                        rootfs,
                        container_name,
                        login_user,
                    )
                    login_uid = user["uid"]
                    login_gid = user["gid"]
                    groups = user["groups"]
            except OSError as exc:
                warn(f"cannot align user for shared home: {exc}")
        elif (
            not use_shared_home
            and not minimal
            and login_home
            and sync_passwd_to_home_owner(rootfs, login_user, login_home)
        ):
            user = _resolve_login_user(
                rootfs,
                container_name,
                login_user,
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
                    os.chmod(host_home_path, 0o700)
                except Exception as e:
                    warn(f"failed to create home directory {login_home}: {e}")

        if not login_wd:
            login_wd = login_home
            # If login home doesn't exist, try image WorkingDir as fallback.
            if login_wd and login_wd != "/":
                wd_host = os.path.join(rootfs, login_wd.lstrip("/"))
                if not os.path.isdir(wd_host):
                    manifest_wd = read_manifest_workdir(container_path)
                    if manifest_wd:
                        manifest_wd_host = os.path.join(rootfs, manifest_wd.lstrip("/"))
                        if os.path.isdir(manifest_wd_host):
                            login_wd = manifest_wd

        child_env = _build_normal_env(
            rootfs,
            container_path,
            login_user,
            login_home,
            extra_env,
            minimal,
            skip_extra_mounts,
            container_name=hostname_arg,
        )

        if run_inner is not None:
            inner = run_inner
        else:
            login_shell = _check_shell_available(rootfs, container_path, login_shell, container_name)
            inner = [login_shell, "-c", shlex.join(login_cmd)] if login_cmd else [login_shell, "-l"]

    # Android paranoid-network: the kernel only allows socket() for processes
    # that belong to AID_INET (3003) / AID_NET_RAW (3004). Without these in the
    # guest's supplementary groups, DNS and all networking fail inside the
    # chroot ("Temporary failure resolving"). Grant them on Termux unless the
    # session is isolated or minimal.
    if IS_TERMUX and not skip_extra_mounts and not minimal:
        groups = list(groups)
        for net_gid in ("3003", "3004"):
            if net_gid not in groups:
                groups.append(net_gid)

    # Strip the host Termux $PREFIX/bin from PATH for normal distros only:
    # a termux-type container's own binaries live exactly at $PREFIX/bin
    # inside its rootfs, so removing it would leave the guest with no
    # usable PATH (chmod/mkdir/cp/ls/apt "command not found" at login).
    if IS_TERMUX and dist_type != "termux" and not skip_extra_mounts and not minimal:
        termux_bin = f"{TERMUX_PREFIX}/bin"
        components = [c for c in child_env.get("PATH", "").split(":") if c and c != termux_bin]
        child_env["PATH"] = ":".join(components)

    if dist_type == "normal" and IS_TERMUX and not skip_extra_mounts and not minimal:
        profile_uid = int(login_uid) if login_uid is not None else 0
        profile_gid = int(login_gid) if login_gid is not None else profile_uid
        inject_termux_profile(
            rootfs,
            child_env,
            owner_uid=profile_uid,
            owner_gid=profile_gid,
        )

    x11_auth_binds: list[str] = []
    display_socket_binds: list[str] = []
    if not IS_TERMUX and dist_type == "normal" and not minimal and shared_display:
        if not use_shared_home and login_user != "root" and login_uid is not None:
            invoking_uid = resolve_invoking_uid()
            if int(login_uid) != invoking_uid:
                host_home = resolve_host_home(login_user)
                if host_home and os.path.isdir(host_home):
                    old_uid = int(login_uid)
                    if sync_passwd_to_path_owner(rootfs, login_user, host_home):
                        user = _resolve_login_user(
                            rootfs,
                            container_name,
                            login_user,
                        )
                        login_uid = user["uid"]
                        login_gid = user["gid"]
                        groups = user["groups"]
                        if login_home and login_home != "/":
                            reown_home_tree_for_uid(
                                rootfs,
                                login_home,
                                old_uid,
                                int(login_uid),
                                int(login_gid),
                            )

        x11_env, resolved_x11_binds = resolve_display_env()
        user_env_keys = {entry.partition("=")[0] for entry in extra_env if "=" in entry}
        for key, val in x11_env.items():
            if key not in user_env_keys:
                child_env[key] = val

        # The session D-Bus daemon authenticates the connecting peer by its
        # SO_PEERCRED UID and refuses uid 0 (root) because it does not match
        # the bus owner (the host user). The socket is bound and the env is
        # forwarded correctly, but root still gets "Connection reset by peer"
        # from notify-send and other session-bus clients. Warn and point at
        # --user, which works because the UID then matches. The system bus is
        # unaffected and continues to work for root.
        if login_user == "root" and child_env.get("DBUS_SESSION_BUS_ADDRESS"):
            invoking_uid = resolve_invoking_uid()
            if invoking_uid != 0:
                warn(
                    "Logging in as root: the session D-Bus bus rejects uid 0, so "
                    "session-bus apps (notify-send, portals, etc.) fail with "
                    "'Connection reset by peer'. Log in as a UID-matched normal "
                    f"user with '--user <name>' (host uid {invoking_uid}) for a "
                    "working session bus. The system bus still works for root."
                )

        # Only the specific runtime sockets are bound, not the whole host /run.
        display_socket_binds = resolve_display_socket_binds(child_env)

        x11_auth_binds = list(resolved_x11_binds)
        xauth = child_env.get("XAUTHORITY", "")
        bind_path = x11_auth_bind_path(xauth)
        if bind_path and bind_path not in x11_auth_binds:
            x11_auth_binds.append(bind_path)

        if xauth and login_uid is not None and not guest_can_read_auth(int(login_uid), xauth):
            guest_xauth = provision_guest_xauthority(
                rootfs,
                host_xauthority=xauth,
                display=child_env.get("DISPLAY", ""),
                guest_uid=int(login_uid),
                guest_gid=int(login_gid) if login_gid is not None else int(login_uid),
            )
            if guest_xauth and "XAUTHORITY" not in user_env_keys:
                child_env["XAUTHORITY"] = guest_xauth
                x11_auth_binds = [p for p in x11_auth_binds if os.path.realpath(p) != os.path.realpath(xauth)]
            else:
                warn(
                    f"X authority file '{xauth}' is not readable by guest UID "
                    f"{login_uid}; could not copy cookie with xauth. GUI apps may "
                    f"fail. Install xauth on the host, or try --shared-home, "
                    f"'xhost +SI:localuser:{login_user}', or a UID-matched user."
                )

    # Decide the effective namespace state up front so it can gate both the
    # bind set and the special mounts below.  We use a tiered approach:
    # only mount namespace is truly mandatory; everything else warns and
    # proceeds with whatever the kernel supports.
    use_namespaces = use_ns_requested and not minimal
    has_userns = False  # Track whether user namespace is active for cap drop.
    if use_namespaces:
        # Probes and warns about missing recommended/enhancement namespaces
        # (shared with build); the mandatory-mount-namespace fallback below is
        # login-specific because its messaging differs for max isolation.
        probe_result = isolation.probe_isolation()
        if probe_result.missing_mandatory:
            # Mount namespace is the minimum for any kind of isolation.
            if max_isolation:
                warn(
                    "Mount namespace (CLONE_NEWNS) is not supported on this "
                    "kernel. This is the minimum requirement for namespace "
                    "isolation. Falling back to chroot-only maximum isolation "
                    "(no host paths bound, but without namespace isolation the "
                    "container is NOT fully escape-proof, e.g. via "
                    "/proc/<pid>/root)."
                )
            else:
                warn(
                    "Mount namespace unavailable on this kernel (missing: --mount). Falling back to non-isolated login."
                )
            use_namespaces = False
        else:
            has_userns = probe_result.has_userns

    # 1. Resolve all bind mounts
    resolved_binds, rslave_targets = bindings.get_bindings(
        rootfs=rootfs,
        minimal=minimal,
        isolated=skip_extra_mounts,
        max_isolation=max_isolation and use_namespaces,
        use_namespaces=use_namespaces,
        use_userns=has_userns,
        shared_home=use_shared_home,
        shared_tmp=shared_tmp,
        shared_display=shared_display,
        display_auth_binds=x11_auth_binds,
        display_socket_binds=display_socket_binds,
        custom_binds=custom_binds,
        login_home=login_home or "/root",
        login_user=login_user,
        dist_type=dist_type,
        nvidia_integration=has_nvidia,
    )

    # Translate login_wd from host path to guest path if applicable
    if login_wd:
        login_wd = _translate_host_path_to_guest(login_wd, rootfs, resolved_binds)

    # Merge NVIDIA env vars into child_env (before user overrides)
    if has_nvidia:
        user_env_keys_all = {entry.partition("=")[0] for entry in extra_env if "=" in entry}
        for key, val in nvidia_env_vars().items():
            if key not in user_env_keys_all:
                child_env[key] = val

    holder = None
    pipe_w = None
    chroot_args = None
    chroot_config: ChrootConfig | None = None

    try:
        host_mounts_exist = bool(mount_manager.get_active_mounts(rootfs))
        namespace.check_isolation_conflicts(
            container_name,
            use_namespaces=use_namespaces,
            host_mounts_exist=host_mounts_exist,
        )
    except NamespaceError as exc:
        crit_error(str(exc))
        sys.exit(1)

    # 2. Increment session counter and mount if first session
    with session.lock(container_name) as lock_fh:
        sess_count = session.increment(container_name, lock_fh=lock_fh)
        if sess_count == 1:
            from chroot_distro.helpers.rootfs import write_resolv_conf

            write_resolv_conf(rootfs)
            if use_namespaces:
                try:
                    # A detached run must use a plain holder and reach the
                    # command via nsenter; the synchronized foreground holder
                    # (which execs the command itself) cannot be backgrounded.
                    #
                    # A max-isolation run must ALSO use the plain holder: the
                    # foreground holder execs `chroot <rootfs> ...` itself and
                    # therefore can never chroot into the rootfs first, leaving
                    # the `chroot /proc/1/root` escape open. The plain holder is
                    # created chrooted (rootfs= below) and reached via nsenter,
                    # so `run --isolated`/`CD_USE_ISOLATION` gets true maximum
                    # isolation just like `login`.
                    _detach_run = getattr(args, "detach", False) and run_inner is not None
                    if run_inner is not None and not _detach_run and not max_isolation:
                        chroot_args = build_chroot_args(
                            rootfs=rootfs,
                            login_uid=login_uid,
                            login_gid=login_gid,
                            groups=groups,
                            workdir=login_wd,
                            inner_cmd=inner,
                            is_run=True,
                        )
                        pipe_r, pipe_w = os.pipe()
                        try:
                            holder = namespace.acquire_holder(
                                container_name,
                                holder_cmd=chroot_args,
                                pipe_r=pipe_r,
                                env=child_env,
                            )
                        finally:
                            os.close(pipe_r)
                    else:
                        # Under maximum isolation the holder chroots into the
                        # rootfs before sleeping, so PID 1 (and therefore every
                        # namespace PID reachable via /proc/<pid>/root) has its
                        # root inside the container and cannot reach the host.
                        holder = namespace.acquire_holder(
                            container_name,
                            rootfs=rootfs if (max_isolation and use_namespaces) else None,
                        )
                    # Record the mode, make mounts private, and give the UTS
                    # namespace the container hostname (shared with build).
                    isolation.finalize_holder(holder, container_name, hostname=hostname_arg)
                except NamespaceError as exc:
                    if pipe_w is not None:
                        with contextlib.suppress(OSError):
                            os.close(pipe_w)
                    with contextlib.suppress(Exception):
                        mount_manager.unmount_all(rootfs, holder=holder)
                    if holder is not None:
                        with contextlib.suppress(Exception):
                            namespace.release_holder(container_name)
                        namespace.clear_isolation_mode(container_name)
                    session.decrement(container_name, lock_fh=lock_fh)
                    # The chrooted max-isolation holder can die immediately on
                    # Android (SELinux). Fall back to the old isolated mode
                    # instead of failing outright.
                    if _can_fall_back_to_old_isolated(max_isolation, args):
                        raise _MaxIsolationFallback(str(exc)) from exc
                    crit_error(str(exc))
                    sys.exit(1)
            else:
                namespace.write_isolation_mode(container_name, namespace.ISOLATION_MODE_HOST)

            if IS_TERMUX and not skip_extra_mounts and not minimal:
                ensure_data_suid()
            # Pre-clean stale mounts if any
            with contextlib.suppress(Exception):
                mount_manager.unmount_all(rootfs, holder=holder)
            # Resolve {guest_path: options} into {resolved_target: options}
            # so per-bind mount options can be matched in the loop below.
            resolved_bind_options: dict[str, str] = {}
            for guest_dst, opts in bind_options_map.items():
                try:
                    resolved_target = resolve_rootfs_path(rootfs, guest_dst)
                except OSError:
                    resolved_target = os.path.join(rootfs, guest_dst.lstrip("/"))
                resolved_bind_options[os.path.realpath(resolved_target)] = opts

            # Phase 1: bind mounts
            run_root = os.path.realpath(os.path.join(rootfs, "run"))
            dev_root = os.path.realpath(os.path.join(rootfs, "dev"))
            for src, dst in resolved_binds:
                try:
                    dst_real = os.path.realpath(dst)
                    mount_options = resolved_bind_options.get(os.path.realpath(dst), "")
                    mount_manager.safe_mount(
                        src,
                        dst,
                        holder=holder,
                        # Recurse for /run subtrees, WSL, and Android system
                        # partitions (nested mounts) — shared with build.
                        recursive=isolation.bind_is_recursive(src, dst_real, run_root, use_userns=has_userns),
                        options=mount_options,
                        # A stale, unremovable (MNT_LOCKED) mount can shadow
                        # /dev without providing ptmx; detect and mount over.
                        required_child="ptmx" if dst_real == dev_root else "",
                    )
                except Exception as e:
                    if pipe_w is not None:
                        with contextlib.suppress(OSError):
                            os.close(pipe_w)
                    mount_manager.unmount_all(rootfs, holder=holder)
                    if holder is not None:
                        namespace.release_holder(container_name)
                        namespace.clear_isolation_mode(container_name)
                    session.decrement(container_name, lock_fh=lock_fh)
                    crit_error(f"Failed to mount bindings: {e}")
                    sys.exit(1)

            # Phase 1a: apply rslave propagation for display socket forwarding
            for rslave_path in rslave_targets:
                mount_manager.make_rslave(rslave_path, holder=holder)

            # Phase 1b: fix /tmp permissions when shared from Termux
            # Termux's $PREFIX/tmp is owned by the app UID with mode 700,
            # which prevents guest users like _apt from creating temp files.
            # apt's gpgv needs a world-writable /tmp to function correctly.
            if IS_TERMUX and shared_tmp and dist_type != "termux":
                chroot_tmp = os.path.join(rootfs, "tmp")
                if os.path.isdir(chroot_tmp):
                    with contextlib.suppress(OSError):
                        # /tmp is world-writable with the sticky bit (0o1777) by
                        # design — the sticky bit prevents users from removing
                        # each other's files. This matches the host /tmp.
                        os.chmod(chroot_tmp, 0o1777)  # lgtm[py/overly-permissive-file]

            # Phase 2: special filesystem mounts — /proc, /sys, and (under max
            # isolation) a fresh private tmpfs /dev + device nodes + ptmx
            # symlink. Shared with the isolated build path.
            try:
                isolation.apply_special_mounts(
                    rootfs,
                    holder,
                    isolated=use_namespaces,
                    max_isolation=max_isolation and use_namespaces,
                    minimal=minimal,
                    use_userns=has_userns,
                )
            except Exception as e:
                if pipe_w is not None:
                    with contextlib.suppress(OSError):
                        os.close(pipe_w)
                mount_manager.unmount_all(rootfs, holder=holder)
                if holder is not None:
                    namespace.release_holder(container_name)
                    namespace.clear_isolation_mode(container_name)
                session.decrement(container_name, lock_fh=lock_fh)
                # On Android the fresh pseudo-filesystems (tmpfs /dev, proc,
                # sysfs) are frequently denied by SELinux, which also kills the
                # chrooted holder so nsenter can no longer open its ns/mnt.
                # Rather than abort the whole login, degrade once to the old
                # `--isolated` mode (host binds + host /proc, namespaces where
                # supported) by re-entering with max isolation disabled.
                if _can_fall_back_to_old_isolated(max_isolation, args):
                    raise _MaxIsolationFallback(str(e)) from e
                crit_error(f"Failed to apply special mounts: {e}")
                sys.exit(1)

            # Phase 3: NVIDIA ldconfig refresh
            if has_nvidia:
                run_ldconfig_in_chroot(rootfs)

            # Phase 4: Auto-create image-declared Volume directories
            for vol_path in read_manifest_volumes(container_path):
                vol_host = os.path.join(rootfs, vol_path.lstrip("/"))
                if not os.path.exists(vol_host):
                    try:
                        os.makedirs(vol_host, exist_ok=True)
                        uid_v = int(login_uid) if login_uid is not None else 0
                        gid_v = int(login_gid) if login_gid is not None else 0
                        os.chown(vol_host, uid_v, gid_v)
                    except OSError:
                        log.debug("Could not create volume dir %s", vol_path)

            # Phase 5: Inform about image-declared exposed ports
            exposed = read_manifest_exposed_ports(container_path)
            if exposed:
                from chroot_distro.message import log_info

                log_info(f"Image declares exposed ports: {', '.join(exposed)}")

            # Phase 6: Persist the mount options used by this first session.
            session.save_mount_options(
                container_name,
                {
                    "shared_display": shared_display,
                    "shared_tmp": shared_tmp,
                    "shared_home": use_shared_home,
                    "custom_binds": sorted(custom_binds),
                    "use_namespaces": use_namespaces,
                    "isolated": max_isolation,
                },
            )

            # Trigger the holder to start execution by closing the pipe
            if pipe_w is not None:
                try:
                    os.write(pipe_w, b"\n")
                    os.close(pipe_w)
                    pipe_w = None
                except OSError as exc:
                    log.warning("Failed to trigger mount namespace holder process: %s", exc)
        else:
            # Not the first session: bind mounts are NOT re-applied.
            # Compare the current mount options against the first session's
            # options and only warn/error when they actually differ.
            stored = session.load_mount_options(container_name)
            current_opts = {
                "shared_display": shared_display,
                "shared_tmp": shared_tmp,
                "shared_home": use_shared_home,
                "custom_binds": sorted(custom_binds),
                "use_namespaces": use_namespaces,
                "isolated": max_isolation,
            }
            if stored is not None and stored != current_opts:
                # Isolation-level mismatches are incompatible.
                if current_opts["isolated"] != stored.get("isolated", False):
                    session.decrement(container_name, lock_fh=lock_fh)
                    crit_error(
                        f"Container '{container_name}' has an active session "
                        f"{'with' if stored.get('isolated') else 'without'} "
                        f"--isolated. Cannot mix isolation levels. "
                        f"Run '{PROGRAM_NAME} unmount {container_name}' first."
                    )
                    sys.exit(1)
                if current_opts["use_namespaces"] != stored.get("use_namespaces", False):
                    warn(
                        f"Container '{container_name}' has an active session "
                        f"{'with' if stored.get('use_namespaces') else 'without'} "
                        f"namespace isolation (CD_USE_NS). The new session's "
                        f"namespace mode differs and will be ignored."
                    )
                # Mount option differences: warn with specifics.
                diff_flags: list[str] = []
                for key, flag in (
                    ("shared_display", "--shared-display"),
                    ("shared_tmp", "--shared-tmp"),
                    ("shared_home", "--shared-home"),
                ):
                    cur = current_opts.get(key, False)
                    old = stored.get(key, False)
                    if cur and not old:
                        diff_flags.append(f"{flag} (requested but not in active session)")
                    elif not cur and old:
                        diff_flags.append(f"{flag} (active session has it, this one doesn't)")
                _cur_raw = current_opts.get("custom_binds")
                _old_raw = stored.get("custom_binds")
                cur_binds: set[str] = set(_cur_raw) if isinstance(_cur_raw, list) else set()
                old_binds: set[str] = set(_old_raw) if isinstance(_old_raw, list) else set()
                if cur_binds != old_binds:
                    diff_flags.append("--bind (different bind mounts)")
                if diff_flags:
                    warn(
                        f"Container '{container_name}' is already mounted; "
                        f"the following options differ from the active session "
                        f"and are ignored: {', '.join(diff_flags)}. "
                        f"Run '{PROGRAM_NAME} unmount {container_name}' and "
                        f"log in again to apply them."
                    )
            if use_namespaces:
                holder = namespace.get_live_holder(container_name)
                if holder is None:
                    session.decrement(container_name, lock_fh=lock_fh)
                    crit_error(
                        f"Namespace holder for '{container_name}' is not running. "
                        f"Run '{PROGRAM_NAME} unmount {container_name}' and try again."
                    )
                    sys.exit(1)
                # Under maximum isolation, never reuse a holder that was not
                # created chrooted (e.g. a stale host-rooted holder left by an
                # older version or a non-isolated session). Entering it would
                # re-open the `chroot /proc/1/root` escape.
                if max_isolation and not namespace.holder_is_max_isolation(container_name):
                    session.decrement(container_name, lock_fh=lock_fh)
                    crit_error(
                        f"Container '{container_name}' already has an active, "
                        f"non-isolated session/holder. Run "
                        f"'{PROGRAM_NAME} unmount {container_name}' first, then "
                        f"log in again with --isolated."
                    )
                    sys.exit(1)

    if chroot_args is None:
        chroot_args = build_chroot_args(
            rootfs=rootfs,
            login_uid=login_uid,
            login_gid=login_gid,
            groups=groups,
            workdir=login_wd,
            inner_cmd=inner,
            is_run=run_inner is not None,
        )
        chroot_config = build_chroot_config(
            rootfs=rootfs,
            login_uid=login_uid,
            login_gid=login_gid,
            groups=groups,
            workdir=login_wd,
            inner_cmd=inner,
            is_run=run_inner is not None,
        )

    exec_argv = chroot_args
    if holder is not None:
        exec_argv = holder.run_argv(chroot_args)

    if getattr(args, "get_chroot_cmd", False):
        parts = ["env", "-i"]
        for k in child_env:
            parts.append(f"{k}={shlex.quote('<redacted>')}")
        parts.extend(shlex.quote(a) for a in exec_argv)
        print(" \\\n  ".join(parts))

        with session.lock(container_name) as lock_fh:
            sess_count = session.decrement(container_name, lock_fh=lock_fh)
            if sess_count == 0:
                mount_manager.unmount_all(rootfs, holder=holder)
                session.clear_mount_options(container_name)
                if holder is not None:
                    namespace.release_holder(container_name)
                    namespace.clear_isolation_mode(container_name)
        sys.exit(0)

    # Record this session for `ps`. Best-effort; the returned handle holds
    # an inheritable flock that tracks liveness. Keep the reference alive
    # for the duration of the session so the lock is not released early.
    _sess_handle = register_session(
        container=container_name,
        kind="run" if run_inner is not None else "login",
        command_argv=inner,
        user=login_user,
        isolated=isolated,
        minimal=minimal,
        detached=bool(getattr(args, "detach", False) and run_inner is not None),
    )

    if getattr(args, "detach", False) and run_inner is not None:
        _run_detached(
            container_name,
            chroot_args=chroot_args,
            child_env=child_env,
            holder=holder,
            session_handle=_sess_handle,
        )
        return

    # Exit code of the inner command, propagated to our own exit status so
    # `login NAME -- cmd` is usable in shell conditionals (like ssh/docker).
    exit_code = 0

    if holder is not None and holder.proc is not None:
        try:
            if getattr(holder, "master_fd", -1) >= 0:
                from chroot_distro.syscalls.chroot import _pty_relay

                exit_code = _pty_relay(holder.master_fd, holder.proc.pid)
            else:
                exit_code = holder.proc.wait()
        except KeyboardInterrupt:
            exit_code = 130
            with contextlib.suppress(OSError):
                holder.proc.send_signal(signal.SIGINT)
            try:
                holder.proc.wait(timeout=5)
            except (subprocess.TimeoutExpired, KeyboardInterrupt):
                with contextlib.suppress(OSError):
                    holder.proc.kill()
                with contextlib.suppress(OSError):
                    holder.proc.wait()
        finally:
            if _sess_handle is not None:
                _sess_handle.close()
            with session.lock(container_name) as lock_fh:
                sess_count = session.decrement(container_name, lock_fh=lock_fh)
                if sess_count == 0:
                    mount_manager.unmount_all(rootfs, holder=holder)
                    session.clear_mount_options(container_name)
                    if holder is not None:
                        namespace.release_holder(container_name)
                        namespace.clear_isolation_mode(container_name)
    else:
        try:
            if chroot_config is not None and holder is None:
                # Native path: chroot + exec without spawning the chroot binary.
                exit_code = chroot_and_run(
                    chroot_config.rootfs,
                    chroot_config.command,
                    uid=chroot_config.uid,
                    gid=chroot_config.gid,
                    groups=chroot_config.groups,
                    workdir=chroot_config.workdir,
                    env=child_env,
                    drop_caps=not has_userns,
                ).returncode
            elif holder is not None:
                # Namespace path: enter namespaces via native setns(2) + PTY.
                exit_code = enter_and_run_with_pty(
                    holder.pid,
                    holder._live_ns_flags(),
                    chroot_args,
                    env=child_env,
                    drop_caps=not has_userns,
                )
            else:
                # Fallback: should not normally be reached.
                import subprocess as _sp

                exit_code = _sp.run(chroot_args, env=child_env, check=False).returncode
        finally:
            if _sess_handle is not None:
                _sess_handle.close()
            with session.lock(container_name) as lock_fh:
                sess_count = session.decrement(container_name, lock_fh=lock_fh)
                if sess_count == 0:
                    mount_manager.unmount_all(rootfs, holder=holder)
                    session.clear_mount_options(container_name)
                    if holder is not None:
                        namespace.release_holder(container_name)
                        namespace.clear_isolation_mode(container_name)

    if exit_code:
        # Popen.wait() reports signal death as a negative code; map it to
        # the shell convention (128 + signal) before exiting.
        sys.exit(128 - exit_code if exit_code < 0 else exit_code)


def _run_detached(
    container_name: str,
    *,
    chroot_args: list,
    child_env: dict,
    holder,
    session_handle=None,
) -> None:
    """Launch the resolved command in the background and return immediately.

    The command is started in a new session (detached from the controlling
    terminal) with stdin from /dev/null and stdout/stderr appended to the
    container's run log. The session counter is intentionally NOT decremented:
    the container stays mounted while the detached process runs, and the
    process is discoverable via /proc/<pid>/root so 'kill' and 'unmount' tear
    it down like any other session.

    When a namespace holder is present, the child enters namespaces via
    native setns(2) before exec'ing the chroot command — no nsenter binary
    is needed.
    """
    log_path = container_log_path(container_name)
    try:
        log_fh = open(log_path, "ab")  # noqa: SIM115 — handed to the child.
    except OSError as exc:
        with session.lock(container_name) as lock_fh:
            sess_count = session.decrement(container_name, lock_fh=lock_fh)
            if sess_count == 0:
                mount_manager.unmount_all(container_rootfs(container_name), holder=holder)
                if holder is not None:
                    namespace.release_holder(container_name)
                    namespace.clear_isolation_mode(container_name)
        crit_error(f"cannot open run log '{log_path}': {exc}")
        sys.exit(1)

    try:
        devnull = open(os.devnull, "rb")  # noqa: SIM115 — handed to the child.
    except OSError as exc:
        log_fh.close()
        crit_error(f"cannot open {os.devnull}: {exc}")
        sys.exit(1)

    # If a session handle exists, pass its fd to the child so the flock
    # (and the session's liveness signal) is inherited by the detached
    # process. The parent closes its copy after Popen returns.
    extra_fds: tuple = ()
    if session_handle is not None:
        extra_fds = (session_handle.fileno(),)

    # Build the actual argv to exec. When a namespace holder is present,
    # enter namespaces via native setns(2) in a preexec_fn instead of
    # trying to exec the nsenter binary.
    exec_argv = chroot_args
    preexec: Callable[[], None] | None = None
    if holder is not None:
        from chroot_distro.syscalls.nsenter import enter_namespaces

        ns_flags = holder._live_ns_flags()
        holder_pid = holder.pid

        def _preexec_fn() -> None:
            enter_namespaces(holder_pid, ns_flags)

        preexec = _preexec_fn

    try:
        proc = subprocess.Popen(
            exec_argv,
            env=child_env,
            stdin=devnull,
            stdout=log_fh,
            stderr=log_fh,
            start_new_session=True,
            pass_fds=extra_fds,
            preexec_fn=preexec,  # noqa: PLW1509
        )
    except OSError as exc:
        log_fh.close()
        devnull.close()
        if session_handle is not None:
            session_handle.close()
        with session.lock(container_name) as lock_fh:
            sess_count = session.decrement(container_name, lock_fh=lock_fh)
            if sess_count == 0:
                mount_manager.unmount_all(container_rootfs(container_name), holder=holder)
                session.clear_mount_options(container_name)
                if holder is not None:
                    namespace.release_holder(container_name)
                    namespace.clear_isolation_mode(container_name)
        crit_error(f"failed to start detached command for '{container_name}': {exc}")
        sys.exit(1)
    finally:
        # The child holds its own copies of these descriptors.
        log_fh.close()
        devnull.close()
        # The child inherited the session flock fd via pass_fds; close the
        # parent's copy so only the child keeps the lock alive.
        if session_handle is not None:
            session_handle.close()

    from chroot_distro.message import log_info

    log_info(f"Container '{container_name}' started in background (PID {proc.pid}).")
    log_info(f"Output is being written to: {log_path}")
    log_info(f"Stop it with: {PROGRAM_NAME} kill {container_name}")


__all__ = ("command_login",)

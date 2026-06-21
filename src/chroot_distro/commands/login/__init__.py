import contextlib
import json
import logging
import os
import shlex
import signal
import subprocess
import sys

import chroot_distro.helpers.mount_manager as mount_manager
import chroot_distro.helpers.namespace as namespace
import chroot_distro.helpers.session as session
from chroot_distro.commands.login import bindings
from chroot_distro.commands.login.chroot_cmd import build_chroot_args
from chroot_distro.commands.login.env import (
    ANDROID_HOST_ENV_VARS,
    IMAGE_ENV_BLOCKED,
    inject_termux_profile,
    read_manifest_env,
    read_manifest_exposed_ports,
    read_manifest_shell,
    read_manifest_user,
    read_manifest_volumes,
    read_manifest_workdir,
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
from chroot_distro.helpers.android import ensure_data_suid, termux_home_owner_ids
from chroot_distro.helpers.display import (
    resolve_display_env,
    resolve_display_socket_binds,
)
from chroot_distro.helpers.namespace import NamespaceError
from chroot_distro.helpers.nvidia import (
    detect_nvidia_gpu,
    nvidia_env_vars,
    run_ldconfig_in_chroot,
)
from chroot_distro.helpers.rootfs import ensure_hosts_entry
from chroot_distro.helpers.x11 import (
    guest_can_read_auth,
    provision_guest_xauthority,
    resolve_invoking_uid,
    x11_auth_bind_path,
)
from chroot_distro.locking import ContainerLock
from chroot_distro.message import crit_error, warn
from chroot_distro.names import require_valid_name
from chroot_distro.paths import container_dir, container_rootfs

log = logging.getLogger(__name__)


def _safe_hostname(name: str) -> str:
    """Return *name* if it is a safe hostname token, else "localhost".

    Container names allow underscores (see names.is_valid_name), which are
    not valid in hostnames and are rejected by some consuming tools. Accept
    only alphanumerics, '-' and '.', with each dot-separated label at most
    63 characters; otherwise fall back to a safe default.
    """
    if not name:
        return "localhost"
    for label in name.split("."):
        if not label or len(label) > 63:
            return "localhost"
        if not all(ch.isalnum() or ch == "-" for ch in label):
            return "localhost"
    return name


def _rootfs_has_script(rootfs: str) -> bool:
    """Return True if util-linux `script` is available inside the rootfs."""
    for guest_bin in ("/usr/bin/script", "/bin/script"):
        host_path = os.path.join(rootfs, guest_bin.lstrip("/"))
        try:
            if os.path.isfile(host_path) or (os.path.islink(host_path) and os.path.exists(host_path)):
                return True
        except OSError:
            continue
    return False


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
    except (OSError, ValueError, json.JSONDecodeError):
        pass


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
        except OSError:
            pass

    has_ep_or_cmd = False
    try:
        with open(os.path.join(container_path, "manifest.json")) as fh:
            data = json.load(fh)
        cfg = (data.get("image_config") or {}).get("config", {})
        has_ep_or_cmd = bool((cfg.get("Entrypoint") or []) or (cfg.get("Cmd") or []))
    except (OSError, ValueError):
        pass

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


def _command_login_inner(container_name: str, args) -> None:
    rootfs = container_rootfs(container_name)
    if not os.path.isdir(rootfs):
        crit_error(f"container '{container_name}' is not installed.")
        sys.exit(1)

    dist_type = _detect_dist_type(rootfs)
    container_path = container_dir(container_name)

    # Warn early if the image architecture doesn't match the host CPU.
    _check_arch_mismatch(container_path)

    # Resolve login user: explicit --user wins, then image manifest User,
    # then fall back to "root".
    _explicit_user = getattr(args, "user", None)
    if _explicit_user is not None:
        login_user = _explicit_user
    else:
        manifest_user = read_manifest_user(container_path)
        login_user = manifest_user if manifest_user else "root"
    login_wd = getattr(args, "work_dir", "") or ""
    isolated = getattr(args, "isolated", False)
    minimal = getattr(args, "minimal", False)
    # `--isolated` skips the extra Android/host mounts AND uses namespaces.
    # `CD_USE_NS` only turns on namespace isolation, keeping every mount.
    # `skip_extra_mounts` therefore tracks only the real `--isolated` flag,
    # while namespace setup is decided separately by should_use_namespaces().
    skip_extra_mounts = isolated
    use_ns_requested = namespace.should_use_namespaces(isolated)
    use_shared_home = getattr(args, "shared_home", False)
    shared_tmp = getattr(args, "shared_tmp", False)
    shared_display = getattr(args, "shared_display", False)
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
    extra_env = getattr(args, "env", []) or []
    login_cmd = getattr(args, "login_cmd", []) or []
    run_inner = getattr(args, "_run_inner", None)

    # Auto-detect NVIDIA GPU on the host (not relevant for Termux)
    has_nvidia = False
    if not IS_TERMUX and not minimal:
        has_nvidia = detect_nvidia_gpu()

    # AMD/Intel/Mesa GPUs work via the /dev bind, but the container needs the
    # host's Vulkan/EGL/OpenCL ICD descriptors to enumerate the GPU. Bind
    # those config dirs read-only, unless the user already bound the same
    # guest path explicitly.
    if not IS_TERMUX and not minimal:
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

    if IS_TERMUX and not skip_extra_mounts and not minimal:
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

    # 1. Resolve all bind mounts
    resolved_binds, rslave_targets = bindings.get_bindings(
        rootfs=rootfs,
        minimal=minimal,
        isolated=skip_extra_mounts,
        use_namespaces=use_ns_requested and not minimal,
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

    # Merge NVIDIA env vars into child_env (before user overrides)
    if has_nvidia:
        user_env_keys_all = {entry.partition("=")[0] for entry in extra_env if "=" in entry}
        for key, val in nvidia_env_vars().items():
            if key not in user_env_keys_all:
                child_env[key] = val

    use_namespaces = use_ns_requested and not minimal
    holder = None
    pipe_w = None
    chroot_args = None

    # Namespace isolation is all-or-nothing: probe the full requested set
    # before touching the session counter or any mount. If any namespace is
    # unsupported on this kernel, acquire none of them and fall back fully to
    # host mode, rather than leaving a half-isolated session behind.
    if use_namespaces:
        missing = namespace.probe_namespace_support()
        if missing:
            warn(
                "Namespace isolation unavailable on this kernel "
                f"(missing: {' '.join(missing)}). Falling back to non-isolated login."
            )
            use_namespaces = False

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
            if use_namespaces:
                try:
                    if run_inner is not None:
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
                        holder = namespace.acquire_holder(container_name)
                    namespace.write_isolation_mode(container_name, namespace.ISOLATION_MODE_NAMESPACE)
                    if not namespace.make_mount_private(holder):
                        # Many Android kernels already provide an isolated
                        # propagation in the new mount namespace, so failing to
                        # set it explicitly is benign. Keep it out of the
                        # user-facing output to avoid alarming warnings.
                        log.debug("Could not set mount propagation to private in isolated namespace.")
                    # Give the isolated UTS namespace its own hostname so
                    # `uname -n` reflects the container name. Cosmetic only:
                    # never fail the login if no hostname binary exists.
                    namespace.set_namespace_hostname(holder, _safe_hostname(hostname_arg))
                except NamespaceError as exc:
                    if pipe_w is not None:
                        with contextlib.suppress(OSError):
                            os.close(pipe_w)
                    session.decrement(container_name, lock_fh=lock_fh)
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
            for src, dst in resolved_binds:
                try:
                    dst_real = os.path.realpath(dst)
                    # Recurse for /run and anything under it (e.g. the bound
                    # /run/user/<uid> runtime dir) so nested socket submounts
                    # come along.
                    is_run = dst_real == run_root or dst_real.startswith(run_root + os.sep)
                    is_wsl = src == "/usr/lib/wsl"
                    mount_options = resolved_bind_options.get(os.path.realpath(dst), "")
                    mount_manager.safe_mount(
                        src,
                        dst,
                        holder=holder,
                        recursive=(is_run or is_wsl),
                        options=mount_options,
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
                        os.chmod(chroot_tmp, 0o1777)

            # Phase 2: special filesystem mounts
            try:
                specials = bindings.get_special_mounts(
                    rootfs,
                    isolated=use_namespaces,
                    enable_usb=not minimal,
                    enable_binfmt=not minimal,
                    enable_docker_cgroup=not minimal,
                    enable_shm=not minimal,
                )
                for sm in specials:
                    mount_manager.apply_special_mount(rootfs, sm, holder=holder)
            except Exception as e:
                if pipe_w is not None:
                    with contextlib.suppress(OSError):
                        os.close(pipe_w)
                mount_manager.unmount_all(rootfs, holder=holder)
                if holder is not None:
                    namespace.release_holder(container_name)
                    namespace.clear_isolation_mode(container_name)
                session.decrement(container_name, lock_fh=lock_fh)
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

            # Trigger the holder to start execution by closing the pipe
            if pipe_w is not None:
                try:
                    os.write(pipe_w, b"\n")
                    os.close(pipe_w)
                    pipe_w = None
                except OSError:
                    pass
        else:
            # Not the first session: bind mounts are NOT re-applied, so any
            # mount-affecting flag passed now is silently ignored because the
            # container is already mounted from an earlier login. Warn so the
            # user knows to unmount first (e.g. --shared-display added after a
            # plain login -> no display/audio/D-Bus sockets, Wayland and
            # notify-send fail to connect).
            if shared_display or shared_tmp or use_shared_home or custom_binds:
                warn(
                    f"Container '{container_name}' is already mounted from an "
                    f"earlier session; mount options (--shared-display, "
                    f"--shared-tmp, --shared-home, --bind) are ignored for this "
                    f"login. Run '{PROGRAM_NAME} unmount {container_name}' and "
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

    # On Termux, Android's /dev/pts nodes use device major 88 while live ptys
    # use major 136, so the inherited login pty has no matching /dev/pts entry
    # and glibc ttyname() fails. Running the interactive shell under util-linux
    # `script` allocates a fresh pty from the newinstance devpts as the child's
    # controlling terminal, which has a matching node -> ttyname() succeeds.
    # Only wrap genuine interactive logins (not `run`, not explicit -c).
    if IS_TERMUX and run_inner is None and not login_cmd and not minimal:
        if _rootfs_has_script(rootfs):
            # script(1) forks the command onto a freshly allocated pty (from the
            # chroot's newinstance devpts via /dev/ptmx) as its controlling
            # terminal, so ttyname()/isatty() succeed. Explicit flags are more
            # portable than the bundled "-qec" form across util-linux versions.
            inner = ["script", "-q", "-e", "-c", shlex.join(inner), "/dev/null"]
        else:
            log.debug(
                "`script` not found in rootfs %s; skipping pty wrapper. "
                "ttyname() may fail on Android (major 88 vs 136 devpts).",
                rootfs,
            )

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
                if holder is not None:
                    namespace.release_holder(container_name)
                    namespace.clear_isolation_mode(container_name)
        sys.exit(0)

    if holder is not None and holder.proc is not None:
        try:
            holder.proc.wait()
        except KeyboardInterrupt:
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
            with session.lock(container_name) as lock_fh:
                sess_count = session.decrement(container_name, lock_fh=lock_fh)
                if sess_count == 0:
                    mount_manager.unmount_all(rootfs, holder=holder)
                    if holder is not None:
                        namespace.release_holder(container_name)
                        namespace.clear_isolation_mode(container_name)
    else:
        try:
            subprocess.run(exec_argv, env=child_env, check=False)
        finally:
            with session.lock(container_name) as lock_fh:
                sess_count = session.decrement(container_name, lock_fh=lock_fh)
                if sess_count == 0:
                    mount_manager.unmount_all(rootfs, holder=holder)
                    if holder is not None:
                        namespace.release_holder(container_name)
                        namespace.clear_isolation_mode(container_name)


__all__ = ("command_login",)

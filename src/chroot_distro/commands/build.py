# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
"""`chroot-distro build`: validate the request, run the engine, publish the result.

Everything the command can refuse is refused before anything is created or
fetched: an unreadable or unparsable Dockerfile, an unknown `--architecture` or
`--platform`, a FROM that does not resolve to a platform this program builds for,
an `--install-as` name already in use or naming no platform this host can run, a
malformed tag, an output file that already exists. A build that was going to be
rejected therefore leaves behind no scratch tree, no cache entry and no
half-written archive.

`_resolve_target_platforms` settles what is built: `--platform`, repeatable and
comma-separated, or the one platform `--architecture` names, or the host's own.
`--architecture` is the single-platform spelling this program shipped with, so the
two together have to name the same one platform.

`plan_stages` then settles the stage platforms of each of them, and the emulator
question follows from its answer: a handler is only required for a stage whose
platform this host cannot execute *and* which carries a RUN, so the cross-compile
shape (a native builder stage, a foreign stage that only assembles files) needs
no emulator.

What is validated here becomes one `BuildRequest`, and
`build_engine/solve.solve_platforms` turns it into one `PlatformResult` per
requested target platform: everything an engine run mutates belongs to one solve,
so the publishing below reads a finished manifest and config and never a live
stage.

Every tag records every platform: one manifest cache entry per (tag, platform),
which is what `install <tag>` and `push -a` each resolve one of. An `--output`
archive is the only place a whole matrix stands as one document, an OCI image
index over every platform. `--install-as` installs one container, so among several
platforms it takes the host's own and refuses a matrix holding nothing this host
runs.

One exclusive `BuildLock` per (tag, platform) is held for the whole build, taken
in lock-path order so two concurrent builds with overlapping but differently
spelled tag sets cannot deadlock each other.

`--cache-from` is imported inside those locks and before the solve, so every step
that can be served from the directory is; `--cache-to` is written afterwards, out
of the recipe hashes the results carry. Only `type=local` exists, and
`_parse_cache_specs` says why the type is spelled out rather than assumed.

A `BuildError` or an `OSError` out of the solve is a build failure and ends as
one quoted line rather than a traceback: the engine's walks report a per-entry
failure and carry on, so an OSError that reaches here is a walk losing its
footing, not a bug. Anything else is left to `cli.main`.

`_make_build_tmp` is where this file's care goes and its own docstring says why.
It returns the scratch root's path plus descriptors on the root and on the
directory holding it. What the build itself owns lives there, a `--secret`
spooled out of the environment and one directory per solve, while the stage
trees, the ADD spool and every `COPY --from` tree are the solve's own; the
teardown removes the root under the parent descriptor rather than resolving
`build-tmp` again.

RUN steps have no isolation flag here: the mode comes from `CD_USE_ISOLATION` or
`CD_USE_NS` alone.
"""

import contextlib
import os
import re
import sys
import typing
from contextlib import ExitStack
from types import SimpleNamespace

from chroot_distro import dirfd
from chroot_distro.arch import (
    Platform,
    get_device_platform,
    needs_emulation,
    normalize_arch,
    parse_platform,
    platform_from_arch,
)
from chroot_distro.commands.install import command_install
from chroot_distro.constants import (
    PROGRAM_NAME,
    RUNTIME_DIR,
)
from chroot_distro.helpers import namespace
from chroot_distro.helpers.binfmt import ensure_handler
from chroot_distro.helpers.build_cache_io import export_cache, import_cache
from chroot_distro.helpers.build_engine import (
    BuildError,
    BuildRequest,
    PlatformResult,
    StagePlan,
    plan_stages,
    solve_platforms,
)
from chroot_distro.helpers.dockerfile import (
    DockerfileSyntaxError,
    parse_dockerfile,
)
from chroot_distro.helpers.isolation import use_isolation_env_enabled
from chroot_distro.helpers.oci_writer import (
    store_in_cache,
    write_oci_archive,
)
from chroot_distro.locking import BuildLock
from chroot_distro.message import C, crit_error, log_error, log_info, msg, quote_path, warn
from chroot_distro.names import is_valid_name, require_valid_name
from chroot_distro.paths import container_is_installed
from chroot_distro.progress import fmt_size


def command_build(args: typing.Any) -> None:
    """Implements `chroot-distro build`."""

    build_path = getattr(args, "path", None) or "."
    dockerfile_path = getattr(args, "dockerfile", None)
    tags = list(getattr(args, "tags", []) or [])
    build_args = _parse_build_args(getattr(args, "build_args", None) or [])
    override_arch = getattr(args, "override_arch", None) or ""
    target_stage = getattr(args, "target_stage", None) or None
    emulator = getattr(args, "emulator", None) or ""
    outputs = list(getattr(args, "outputs", []) or [])
    install_as = getattr(args, "install_as", None)
    cache_from = _parse_cache_specs(getattr(args, "cache_from", None) or [], "--cache-from", "src")
    cache_to = _parse_cache_specs(getattr(args, "cache_to", None) or [], "--cache-to", "dest")

    if dockerfile_path is not None and not dockerfile_path:
        crit_error("Dockerfile path cannot be empty.")
        sys.exit(1)

    for out_file in outputs:
        if not out_file:
            crit_error("output file path cannot be empty.")
            sys.exit(1)

    if install_as is not None and not install_as:
        crit_error("--install-as value cannot be empty.")
        sys.exit(1)

    install_as = install_as or ""
    no_cache = bool(getattr(args, "no_cache", False))
    verbose = bool(getattr(args, "verbose", False))
    quiet = bool(getattr(args, "quiet", False))

    build_dir = os.path.abspath(os.path.expanduser(build_path))
    if dockerfile_path is None:
        dockerfile = os.path.join(build_dir, "Dockerfile")
    elif dockerfile_path == "-":
        dockerfile = "-"
    else:
        dockerfile = os.path.abspath(os.path.expanduser(dockerfile_path))

    if not os.path.isdir(build_dir):
        crit_error(f"build context '{build_dir}' is not a directory.")
        sys.exit(1)

    if dockerfile != "-" and not os.path.isfile(dockerfile):
        crit_error(f"required file '{dockerfile}' does not exist.")
        sys.exit(1)

    try:
        if dockerfile == "-":
            text = sys.stdin.read()
        else:
            with open(dockerfile, "rb") as fh:
                text = fh.read().decode("utf-8", errors="replace")
    except OSError as exc:
        crit_error(f"cannot read Dockerfile: {exc}")
        sys.exit(1)

    try:
        _directives, instructions = parse_dockerfile(text)
    except DockerfileSyntaxError as exc:
        crit_error(f"syntax error in Dockerfile: {exc}")
        sys.exit(1)

    _warn_foreign_frontend(_directives)

    if not instructions:
        crit_error("no instructions in Dockerfile.")
        sys.exit(1)

    target_platforms = _resolve_target_platforms(
        list(getattr(args, "platforms", None) or []),
        override_arch,
    )
    build_platform = get_device_platform()

    # What every FROM resolves to, settled before the locks and the scratch tree:
    # a Dockerfile whose stages do not resolve for one of the requested platforms
    # is refused here, and the engine reads the same plan back rather than
    # resolving one of its own.
    stage_plans: list[StagePlan] = []
    for platform in target_platforms:
        try:
            plans, _global_args = plan_stages(
                instructions,
                target_platform=platform,
                build_platform=build_platform,
                user_build_args=build_args,
            )
        except BuildError as exc:
            crit_error(quote_path(_qualify(str(exc), platform, target_platforms)))
            sys.exit(1)
        stage_plans.extend(plans)

    # Every RUN step chroots into its own stage's rootfs, so a stage built for a
    # foreign platform needs the same handler a foreign login does. A stage that
    # runs nothing never execs a guest binary, so there it is only a warning.
    for platform, runs in _foreign_platforms(stage_plans):
        interpreter, reason = ensure_handler(platform.to_arch())
        if interpreter is not None:
            continue
        detail = f"Building for '{platform}' on a '{build_platform}' host, and no emulator was registered ({reason})."
        if runs:
            crit_error(f"{detail} RUN steps cannot execute.")
            sys.exit(1)
        warn(detail)

    install_platform = target_platforms[0]
    if install_as:
        require_valid_name(install_as, kind="--install-as value")

        if container_is_installed(install_as):
            crit_error(
                f"container '{install_as}' defined by --install-as already "
                f"exists. Use '{PROGRAM_NAME} remove {install_as}' first or "
                f"'{PROGRAM_NAME} reset {install_as}' to rebuild."
            )
            sys.exit(1)

        install_platform = _install_platform(target_platforms)

    if not tags:
        derived = _derive_tag_from_path(build_dir, dockerfile)
        if not derived:
            crit_error("cannot derive a tag from the build path. Pass '--tag' explicitly (e.g. --tag myapp:latest).")
            sys.exit(1)
        tags = [derived]

    for t in tags:
        if not _is_valid_tag(t):
            crit_error(
                f"tag '{t}' is not valid. A tag must start with an "
                f"alphanumeric character and contain only letters, "
                f"digits, underscores, dots, hyphens, slashes, or a "
                f"single colon for the version."
            )
            sys.exit(1)

    tags = [_with_explicit_tag(t) for t in tags]
    primary_tag = tags[0]

    for out_file in outputs:
        out_abs = os.path.abspath(os.path.expanduser(out_file))
        if os.path.exists(out_abs):
            crit_error(f"file '{out_abs}' already exists. Please specify a different name.")
            sys.exit(1)

    for dest in cache_to:
        if os.path.exists(dest) and not os.path.isdir(dest):
            crit_error(f"--cache-to dest '{dest}' exists and is not a directory.")
            sys.exit(1)

    # Acquire one exclusive BuildLock per (tag, platform) for the duration of the
    # build: the manifest cache entry a build publishes is per pair, so that is
    # what two of them can collide on. Sorted by lock path so two concurrent
    # builds with overlapping but differently-ordered tag sets can't deadlock.
    build_locks = sorted(
        [BuildLock(t, p.to_arch(), command="build") for t in tags for p in target_platforms],
        key=lambda lock: lock.lock_path,
    )

    with ExitStack() as lock_stack:
        for lock in build_locks:
            lock_stack.enter_context(lock)

        if cache_from and no_cache:
            warn("--no-cache leaves no step to serve from cache, so --cache-from is not imported.")
        elif cache_from:
            _import_cache_dirs(cache_from, quiet)

        tmp_root, tmp_parent_fd, tmp_root_fd = _make_build_tmp()

        try:
            secrets = _parse_secret_opts(getattr(args, "secrets", None) or [], tmp_root)
            ssh_sockets = _parse_ssh_opts(getattr(args, "ssh", None) or [])

            request = BuildRequest(
                build_dir=build_dir,
                instructions=instructions,
                target_platform=target_platforms[0],
                build_platform=build_platform,
                scratch_dir=tmp_root,
                scratch_fd=tmp_root_fd,
                user_build_args=build_args,
                target_stage=target_stage,
                verbose=verbose,
                quiet=quiet,
                no_cache=no_cache,
                emulator=emulator,
                # build has no isolation CLI flag; both modes are env-var opt-in.
                isolation_mode=_resolve_build_isolation_mode(),
                secrets=secrets,
                ssh_sockets=ssh_sockets,
                progress=getattr(args, "progress", "auto") or "auto",
            )

            try:
                results = solve_platforms(request, target_platforms)
            except BuildError as exc:
                # A BuildError builds its message by interpolation and the
                # names it reports on are not the author's: a member of an
                # ADD'd archive (copy_step._materialise_files), an entry of a
                # base image, the output of a RUN step's own tooling.
                log_error(f"Build failed: {quote_path(str(exc))}")
                sys.exit(1)
            except OSError as exc:
                # The engine's walks report a per-entry failure and carry on, so
                # one that gets this far is a walk losing its footing: a
                # directory a step's leftovers moved out from under it, which
                # `dirfd.Levels` answers with ESTALE rather than reopening a
                # level somewhere else. A build, not an unexpected error.
                log_error(f"Build failed: {quote_path(exc.strerror or str(exc))}")
                sys.exit(1)

            # One manifest cache entry per tag and platform, so each can be
            # installed or pushed offline by name and architecture.
            for t in tags:
                for result in results:
                    try:
                        store_in_cache(t, result.platform, result.manifest, result.image_config)
                    except OSError as exc:
                        log_error(f"Cannot write manifest cache for '{t}' ({result.platform}): {exc}")
                        sys.exit(1)

            for out_file in outputs:
                out_abs = os.path.abspath(os.path.expanduser(out_file))
                try:
                    if not quiet:
                        log_info(f"Writing OCI archive to '{out_abs}'...")
                    write_oci_archive(out_abs, results, primary_tag)
                except (OSError, RuntimeError) as exc:
                    log_error(f"Cannot write '{out_file}': {exc}")
                    sys.exit(1)

            _export_cache_dirs(cache_to, results, quiet)

            if not quiet:
                log_info("Build complete.")
                msg()
                msg(f"{C['CYAN']}Tag(s): {C['GREEN']}{', '.join(tags)}{C['RST']}")
                for result in results:
                    label = f"Layers ({result.platform})" if len(results) > 1 else "Layers"
                    total_size = sum(layer["size"] for layer in result.layers)
                    msg(
                        f"{C['CYAN']}{label}: {C['GREEN']}{len(result.layers)} "
                        f"({fmt_size(total_size)} total){C['RST']}"
                    )
                msg()

            if install_as:
                _install_as_container(install_as, primary_tag, install_platform.to_arch(), quiet)

            if not outputs and not install_as and not quiet:
                msg(f"{C['CYAN']}Install with: {C['GREEN']}{PROGRAM_NAME} install {primary_tag}{C['RST']}")
                msg()
        except KeyboardInterrupt:
            log_error("Aborted by user.")
            sys.exit(1)
        finally:
            with contextlib.suppress(OSError):
                os.close(tmp_root_fd)
            _remove_build_tmp(tmp_root, tmp_parent_fd)


# The frontend this program's own reading of a Dockerfile answers for. Every
# `# syntax=` in the wild names it, with or without a registry and a channel tag.
_STOCK_FRONTENDS = frozenset({"docker/dockerfile", "docker.io/docker/dockerfile"})


def _warn_foreign_frontend(directives: dict[str, str]) -> None:
    """Say so when `# syntax=` names a frontend other than the stock one.

    The directive tells BuildKit to build the file with another program
    entirely, and this one can neither fetch nor run it: what gets built is this
    program's own reading of the file, which is a Dockerfile. Naming the stock
    frontend is what nearly every Dockerfile does and says nothing about the
    instruction set, so only a different one is worth a line. `escape` and
    `check` need none: the parser acts on the first, and the second only turns
    off build checks this program does not make.
    """
    ref = directives.get("syntax", "")
    if not ref:
        return
    repo = ref.split("@", 1)[0].rsplit(":", 1)[0].strip("/")
    if repo in _STOCK_FRONTENDS:
        return
    warn(
        f"this Dockerfile asks to be built by '{ref}', a frontend {PROGRAM_NAME} cannot run; "
        f"reading it as an ordinary Dockerfile."
    )


def _resolve_target_platforms(raw: list[str], override_arch: str) -> list[Platform]:
    """The ordered, deduplicated platforms this build produces.

    `--platform` is repeatable and every occurrence may itself be a
    comma-separated list, which are the two spellings buildx accepts. Two
    spellings of one platform are one entry and the first mention keeps its place,
    since that order is what an image index describes and a platform named twice
    is not a valid index. `--architecture` names one platform, and the two options
    together have to agree on it: silently letting one win would build something
    the command line does not say.
    """
    ordered: list[Platform] = []
    for value in raw:
        for part in value.split(","):
            try:
                ordered.append(parse_platform(part))
            except ValueError as exc:
                crit_error(f"invalid --platform value: {exc}.")
                sys.exit(1)
    ordered = list(dict.fromkeys(ordered))

    if override_arch:
        arch = normalize_arch(override_arch)
        if arch is None:
            crit_error(f"unknown architecture '{override_arch}'.")
            sys.exit(1)
        named = platform_from_arch(arch)
        if ordered and ordered != [named]:
            crit_error(
                f"--architecture {override_arch} and --platform "
                f"{','.join(str(p) for p in ordered)} name different platforms. "
                f"Pass one of the two."
            )
            sys.exit(1)
        return [named]
    return ordered or [get_device_platform()]


def _parse_cache_specs(raw: list[str], option: str, key: str) -> list[str]:
    """Parse `type=local,<key>=DIR` items into the directories, in order.

    `type=local` is spelled out rather than assumed. A bare value names a registry
    reference to buildx, so taking one here as a directory would give the same
    command line two readings the day a registry type exists. Repeats and
    duplicates behave like `--output`'s: every distinct directory once, in the
    order it was first named.
    """
    out: list[str] = []
    for item in raw:
        fields: dict[str, str] = {}
        for part in item.split(","):
            name, _, value = part.partition("=")
            fields[name.strip()] = value
        kind = fields.pop("type", "")
        path = fields.pop(key, "")
        if kind != "local":
            crit_error(f"{option} type '{kind}' is not supported; the only cache this program moves is 'type=local'.")
            sys.exit(1)
        if not path or fields:
            crit_error(f"invalid {option} '{item}' (expected type=local,{key}=DIR).")
            sys.exit(1)
        resolved = os.path.abspath(os.path.expanduser(path))
        if resolved not in out:
            out.append(resolved)
    return out


def _import_cache_dirs(dirs: list[str], quiet: bool) -> None:
    """Merge every `--cache-from` directory into this machine's build cache.

    A directory that is not there yet is the first build in a fresh checkout,
    which is the case a shared cache directory exists for, so it is reported and
    not refused. One that is there and is not a cache directory ends the build,
    since it was named on the command line. An entry that cannot be verified is
    dropped and its step rebuilds, which is worth a line and not a failure.
    """
    for path in dirs:
        try:
            added, refused = import_cache(path)
        except (OSError, ValueError) as exc:
            crit_error(f"cannot import the build cache at '{path}': {quote_path(str(exc))}.")
            sys.exit(1)
        if refused:
            warn(f"Ignored {refused} cache entr{'y' if refused == 1 else 'ies'} in '{path}' that could not be verified.")
        if not quiet:
            log_info(f"Imported {added} cached step(s) from '{path}'.")


def _export_cache_dirs(dirs: list[str], results: list[PlatformResult], quiet: bool) -> None:
    """Write every `--cache-to` directory from the steps this build dispatched.

    One set across the whole matrix: two platforms sharing a step share its entry,
    and a directory describing it twice is not a thing this format can hold.
    Failure ends the command the way a `--output` that cannot be written does; the
    image is already published, so what is lost is the next build's head start,
    and a CI job that asked for a cache has to hear that it has none.
    """
    if not dirs:
        return
    recipes = {recipe for result in results for recipe in result.step_recipes}
    for path in dirs:
        try:
            steps, size = export_cache(path, recipes)
        except (OSError, ValueError) as exc:
            log_error(f"Cannot export the build cache to '{path}': {quote_path(str(exc))}.")
            sys.exit(1)
        if not quiet:
            log_info(f"Exported {steps} cached step(s) ({fmt_size(size)}) to '{path}'.")


def _install_platform(platforms: list[Platform]) -> Platform:
    """Which of the requested platforms `--install-as` installs.

    One platform answers for itself, foreign or not: `-a aarch64 --install-as`
    has always installed what it built, and an emulator is what makes that work.
    Among several, a container is still one rootfs, so this program takes the
    host's own platform and a platform the host runs natively (32-bit userspace on
    a 64-bit CPU of the same family) after it, rather than guessing which foreign
    one was meant.
    """
    if len(platforms) == 1:
        return platforms[0]
    host = get_device_platform()
    runnable = [p for p in platforms if p == host] or [p for p in platforms if not needs_emulation(p.to_arch())]
    if not runnable:
        crit_error(
            f"--install-as cannot pick one of the platforms this build produces "
            f"({', '.join(str(p) for p in platforms)}): none of them runs on this "
            f"'{host}' host. Build one platform, or install one afterwards with "
            f"'{PROGRAM_NAME} install <tag> --architecture <arch>'."
        )
        sys.exit(1)
    return runnable[0]


def _qualify(message: str, platform: Platform, platforms: list[Platform]) -> str:
    """Name the platform a message belongs to, where more than one was asked for.

    The line `solve_platforms` draws for the same reason: with one platform there
    is nothing to tell apart, so a single-platform build's errors are what they
    were.
    """
    return f"target platform '{platform}': {message}" if len(platforms) > 1 else message


def _foreign_platforms(plans: list[StagePlan]) -> list[tuple[Platform, bool]]:
    """The stage platforms this host cannot execute, and whether one of them runs.

    One entry per platform, in the order the plans mention it, so a Dockerfile
    that builds a native stage for the host and a foreign one for the image asks
    for an emulator for the second alone, and a matrix whose platforms share a
    foreign stage asks once.
    """
    runs: dict[Platform, bool] = {}
    for plan in plans:
        if not needs_emulation(plan.platform.to_arch()):
            continue
        runs[plan.platform] = runs.get(plan.platform, False) or plan.runs
    return list(runs.items())


def _make_build_tmp() -> tuple[str, int, int]:
    """Create the scratch root a build works under.

    Returns (path, a descriptor on the directory holding it, a descriptor on the
    root itself). The second is what the build addresses its own tree through:
    each solve's directory is made off it, and the stage directories, the ADD
    spool and the COPY --from rootfs are made off that, so none of them is
    reached by resolving `tmp_root` again. `build-tmp` is a predictable name
    inside the runtime tree, which on Termux sits under the $TERMUX_PREFIX bound
    read-write into every non-isolated container, and
    `tempfile.mkdtemp(dir=...)` resolved it: a guest that left
    `build-tmp -> <host dir>` behind had every stage rootfs, every spooled ADD
    and every packed layer assembled inside that host directory. The name is
    walked down to with O_NOFOLLOW instead and this run's own root created with
    mkdirat off the descriptor that walk validated. What is made *inside* that
    root needs no walk of its own: the name is fresh and the mode is 0700.

    Both descriptors are kept for the length of the build: the removal at the end
    names the directory this created the root in rather than resolving
    `build-tmp` a second time, and the root's own descriptor outlives every solve
    that was made off it.

    A runtime tree that cannot hold the directory falls back to /tmp, as it
    always did.
    """
    build_tmp = os.path.join(RUNTIME_DIR, "build-tmp")
    with contextlib.suppress(OSError):
        os.makedirs(RUNTIME_DIR, exist_ok=True)
    dir_fd = dirfd.opendir_under(RUNTIME_DIR, ("build-tmp",), create=True)
    if dir_fd is None:
        warn(f"Failed to create build temporary directory '{build_tmp}', falling back to '/tmp'.")
        build_tmp = "/tmp"
        dir_fd = dirfd.opendir(build_tmp)
    try:
        name = f"cd-build-{os.getpid()}.{os.urandom(4).hex()}"
        os.mkdir(name, 0o700, dir_fd=dir_fd)
        root_fd = dirfd.opendir_at(dir_fd, name)
    except OSError:
        os.close(dir_fd)
        raise
    return os.path.join(build_tmp, name), dir_fd, root_fd


def _remove_build_tmp(tmp_root: str, dir_fd: int) -> None:
    """Remove the build's scratch root under the descriptor it was created in.

    Going back to the name would resolve `build-tmp` again, and a guest that
    replaces it while the build runs would have the removal delete whatever the
    link points at. Removing under the descriptor also gets out a tree
    `shutil.rmtree(ignore_errors=True)` could not: it swallowed an OSError but
    not the RecursionError a deep one raised, and it could not chmod its way
    into a directory a build left sealed.
    """
    try:
        dirfd.rmtree_at(dir_fd, os.path.basename(tmp_root), force=True, on_error=lambda _rel, _exc: None)
    finally:
        os.close(dir_fd)


_SECRET_ID_RE = re.compile(r"^[A-Za-z0-9._-]+$")


def _resolve_build_isolation_mode() -> str:
    """Isolation mode for RUN steps: CD_USE_ISOLATION (max) wins over CD_USE_NS (ns)."""
    if use_isolation_env_enabled():
        return "max"
    if namespace.use_ns_env_enabled():
        return "ns"
    return "none"


def _parse_secret_opts(raw: list[str], tmp_root: str) -> dict[str, str]:
    """Parse --secret id=NAME[,src=PATH] items into {id: host_file_path}.

    Without src=, the secret value is taken from the environment variable
    named after the id and written to a 0400 file under tmp_root.
    """
    out: dict[str, str] = {}
    for item in raw:
        kv: dict[str, str] = {}
        for part in item.split(","):
            k, _, v = part.partition("=")
            kv[k.strip()] = v
        sid = kv.pop("id", "")
        src = kv.pop("src", None) or kv.pop("source", None)
        if not sid or kv or not _SECRET_ID_RE.match(sid):
            crit_error(f"invalid --secret '{item}' (expected id=NAME[,src=PATH]).")
            sys.exit(1)
        if src:
            path = os.path.abspath(os.path.expanduser(src))
            if not os.path.isfile(path):
                crit_error(f"--secret id={sid}: file '{src}' does not exist.")
                sys.exit(1)
        else:
            value = os.environ.get(sid)
            if value is None:
                crit_error(f"--secret id={sid}: no src= given and environment variable '{sid}' is not set.")
                sys.exit(1)
            path = os.path.join(tmp_root, f"cli-secret-{sid}")
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o400)
            with os.fdopen(fd, "w") as fh:
                fh.write(value)
        out[sid] = path
    return out


def _parse_ssh_opts(raw: list[str]) -> dict[str, str]:
    """Parse --ssh [ID[=SOCK]] items into {id: socket_path}."""
    out: dict[str, str] = {}
    for item in raw:
        sid, _, sock = (item or "default").partition("=")
        sid = sid or "default"
        sock = sock or os.environ.get("SSH_AUTH_SOCK", "")
        if not sock:
            crit_error(f"--ssh {sid}: no socket path given and SSH_AUTH_SOCK is not set.")
            sys.exit(1)
        out[sid] = os.path.abspath(os.path.expanduser(sock))
    return out


def _parse_build_args(raw: list[str]) -> dict[str, str]:
    out = {}
    for item in raw:
        if "=" in item:
            k, _, v = item.partition("=")
            v = v.strip()
            if len(v) >= 2 and ((v.startswith('"') and v.endswith('"')) or (v.startswith("'") and v.endswith("'"))):
                v = v[1:-1]
        else:
            k, v = item, os.environ.get(item, "")
        if k:
            out[k] = v
    return out


def _derive_tag_from_path(build_dir: str, dockerfile: str) -> str:
    """Pick a default tag based on the build context basename."""
    base = os.path.basename(os.path.abspath(build_dir).rstrip("/"))
    if (not base or base in (".", "..")) and dockerfile and dockerfile != "-":
        base = os.path.basename(os.path.dirname(os.path.abspath(dockerfile)))
    base = base.lower()
    base = re.sub(r"[^a-z0-9_.\-]", "-", base).strip("-")
    base = re.sub(r"-+", "-", base)
    if not base or not is_valid_name(base):
        return ""
    return f"{base}:latest"


def _with_explicit_tag(tag: str) -> str:
    """Append ':latest' if `tag`'s last path component lacks a tag part."""
    last = tag.rsplit("/", maxsplit=1)[-1]
    return tag if ":" in last else tag + ":latest"


def _is_valid_tag(tag: str) -> bool:
    if not tag:
        return False
    if ":" in tag:
        name_part, tag_part = tag.rsplit(":", 1)
        if not tag_part:
            return False
        # Tag part: starts with alphanumeric, then word chars + dot/dash.
        if not re.match(r"^[A-Za-z0-9][\w.\-]*$", tag_part):
            return False
    else:
        name_part = tag
    last = name_part.split("/")[-1]
    return is_valid_name(last)


def _install_as_container(install_name: str, image_ref: str, target_arch: str, quiet: bool) -> None:
    """Run the install command for `image_ref` aliased as `install_name`."""
    if not quiet:
        log_info(f"Installing built image as '{install_name}'...")

    command_install(
        SimpleNamespace(
            image_ref=image_ref,
            custom_container_name=install_name,
            override_arch=target_arch,
        )
    )

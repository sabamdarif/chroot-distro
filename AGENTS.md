# AGENTS.md

Guidance for coding agents working in this repository. `CLAUDE.md` is a symlink
to this file, so Claude Code and other agents read the same instructions.

## Project Overview

**chroot-distro** is a lightweight Linux container management utility that runs real Linux distributions inside Termux (rooted Android) or regular Linux using native kernel features (`chroot`, `mount`, namespaces). It downloads Docker/OCI images, builds images from Dockerfiles, and manages container lifecycles, all without Docker or Podman.

**Requirements:**
- Python 3.10+ (CI tests 3.10 through 3.14; `.python-version` pins 3.12 for local dev)
- No third-party runtime dependencies (except `backports-zstd` for Python < 3.14)
- Linux or Linux-based system (Termux on rooted Android)
- Root access required

**Key characteristics:**
- Requires root (uses kernel `chroot`/`mount` syscalls directly via ctypes/libc)
- Dual platform: Termux (Android with root) and regular Linux
- Privilege elevation: Termux uses `su`, Linux uses a passwordless daemon (socket-based) or `sudo`
- Native speed: no emulation, containers share the host kernel

## Build, Test, Lint
```bash
# Before committing or installing: run all checks
./check-before-commit.sh
# This script runs: ruff check, pyright, mypy, and pytest with coverage
# All checks must pass before committing changes

uv sync                                  # create/refresh .venv with dev deps
uv run pytest tests/unit/test_cli.py     # one test file
uv run pytest tests/unit/test_cli.py::test_name -x   # one test
uv run ruff check --fix src/chroot_distro

# Install locally for testing
pip install -e .
```

Lint and type checks target `src/chroot_distro` only; `tests/` is not checked.
Unit tests never need root: they monkeypatch syscalls and filesystem paths, and
`tests/conftest.py` stubs Linux-only modules (`fcntl`, `pwd`, `grp`, `termios`)
so the suite also runs on non-Linux. Real end-to-end coverage (actual installs,
logins, builds under `sudo`) lives in `.github/workflows/e2e-tests.yml` and does
not run locally via pytest.

## Architecture

Three layers, each depending only on the ones above it:

`commands/` (CLI behaviour) -> `helpers/` (policy, orchestration) -> `syscalls/` (raw kernel calls)

Kernel operations go through the ctypes wrappers in `syscalls/` rather than
external binaries. External `unshare`, `nsenter` and `chroot` binaries survive
only as explicit fallbacks in a few paths (`helpers/namespace.py`
`_create_holder_subprocess`, `commands/login/chroot_cmd.build_chroot_args`).

### Entry point and dispatch
- `cli.py` `main()`: environment sanity, per-command help, unknown-command
  rejection, required-arg checks, root policy, then dispatch.
- `parser.py`: argparse tree plus `ALIAS_TO_CANONICAL` (short aliases such as
  `ls`, `sh`, `rm`) and `REQUIRED_ARGS` (positional checks enforced by `cli.py`,
  not argparse, so the custom help page can be shown).
- `cli._COMMAND_HANDLERS` maps a canonical command to a `"module:function"`
  string, imported on dispatch. Startup latency matters, so imports stay lazy
  (`constants.__getattr__` defers the `importlib.metadata` version lookup, help
  pages are imported only when rendered). Keep new code out of import time.
- Root policy lives in `cli.main`: `help`/`search`/`daemon` never elevate, and
  on Termux `list`/`ps` are exempt too (`info` elevates only if root is available).

### Root and elevation
`elevate.py` `elevate_or_die()` tries, in order: already root, sufficient file
capabilities, Termux `su`, the Linux daemon socket, then `sudo`/`doas`/`pkexec`/`su`.
Notes that matter when touching it:
- Many sudoers policies drop the environment, so runtime `CD_*` and display vars
  are re-applied explicitly through an `env VAR=value` prefix
  (`_FORWARDED_ENV_VARS`, `_FORWARDED_DISPLAY_VARS`). A new `CD_*` var that must
  work post-elevation has to be added to one of those tuples.
- Secrets (`CD_DOCKER_AUTH`, `CD_ENV`) travel in a 0600 tempfile referenced by
  `CD_SECRET_FILE`, never in argv, which is world-readable via `/proc/*/cmdline`.
- `_CHROOT_DISTRO_ELEVATING=1` is the elevation-loop sentinel.
- `daemon.py` holds both the client and the server: a root-owned Unix socket at
  `/run/chroot-distro.sock`, group-gated on `chroot-distro`, peers authenticated
  with `SO_PEERCRED`, client stdio passed via `SCM_RIGHTS` so interactive
  `login` works. `commands/setup.py` creates the group and installs the service
  for systemd, OpenRC, runit, dinit, or sysvinit.

### Session lifecycle (`login`, `run`, `build`)
Four independent pieces of state, all under the runtime dir:
- `locking.py`: `flock`-based `ContainerLock` / `BuildLock` / `RunCacheLock`. The
  lock file's first line is `PID command` so a conflict can name the holder;
  exclusive locks are re-entrant within one process.
- `helpers/session.py`: per-container session refcount, self-healing by scanning
  `/proc/*/root` for processes actually chrooted into the rootfs.
- `helpers/session_registry.py`: one JSON file per session, kept alive by an
  exclusive `flock`. `ps` probes liveness with a shared non-blocking lock and
  prunes dead files.
- `helpers/mount_manager.py`: bind/special mounts, `/dev` node creation,
  propagation changes, and teardown (including a deep sweep for leaked mounts).

### Isolation modes
`helpers/isolation.py` is the single place that composes namespaces plus chroot,
shared by `login`, `run` and `build`:
- default: shared mounts, no namespaces;
- `CD_USE_NS`: namespaces on, default mount set kept;
- `--isolated` / `CD_USE_ISOLATION`: maximum isolation, bind nothing from the host.

`helpers/namespace.py` owns `NamespaceHolder`, a long-lived holder process that
keeps the namespaces alive between sessions (pid/flags state under
`data/<name>/`), plus kernel capability probes and tiered flag fallbacks.
`helpers/max_iso_holder.py` is executed as PID 1 *inside* the new namespace
(`python3 -m chroot_distro.helpers.max_iso_holder`); it chroots itself and mounts
a fresh procfs (`hidepid=2`), read-only sysfs, tmpfs `/dev` and devpts from the
inside, so the parent never has to `nsenter` back in.
`syscalls/capabilities.py` drops dangerous bounding-set capabilities when user
namespaces are unavailable (opt out with `CD_NO_CAP_DROP=1`).

### Image pull and install
`helpers/docker/`: `refs.py` (parse image refs, arch mapping) -> `transport.py`
(auth tokens, retries, TLS error messages) -> `pull.py` (manifest/platform
resolution) -> `layers.py` + `download.py` (parallel, segmented, resumable,
rate-limited blob downloads) -> `cache.py` (content-addressed layer/manifest
cache). Layers land in the rootfs through `helpers/tar_extract.py`, which
enforces path-escape and whiteout safety. `commands/install_local.py` handles
plain tarballs and OCI archive layouts.

Every install writes `containers/<name>/manifest.json` with `image_ref`, `arch`,
`manifest`, and `image_config`. That file is the source of truth for `reset`,
`run` (Entrypoint/Cmd), `push`, and the guest env defaults read by
`commands/login/env.py`.

### Build pipeline
`helpers/dockerfile.py` parses to instruction dicts (heredocs, flags, escape
directive, variable expansion). `helpers/build_engine/` executes them:
`engine.py` drives one `stage.Stage` per `FROM`, `handlers.py` implements the
metadata instructions, `run_step.py` runs `RUN` under chroot (optionally inside
an isolation holder), `copy_step.py` implements `COPY`/`ADD`, `run_mounts.py`
implements `RUN --mount` (BuildKit syntax; unsupported flags are rejected, never
silently ignored), `events.py` renders progress (`--progress plain|tty|rawjson`).
`helpers/layer_diff.py` snapshots and diffs the rootfs into layer tars,
`helpers/oci_writer.py` writes the manifest/config into the cache so `push` and
`install` can consume the result, and `helpers/build_cache.py` caches steps by
recipe hash.

### Cross-cutting
- `atomic.py`: every state file write goes through `atomic_write` /
  `atomic_replace` (tempfile, fsync, rename) so a crash never leaves half a file.
- `message.py` (colors, `--quiet`) and `progress.py` (byte/count bars, spinners)
  for all user-facing output. `build_engine/events.py` is the exception, since
  build output has its own reporters.
- `exceptions.py`: raise a `ChrootDistroError` subclass for expected failures.
  `cli.main` turns it into a clean one-line error and exit code 1.
- `helpers/display.py` aggregates X11/Wayland/audio/D-Bus passthrough
  (`x11.py`, `wayland.py`, `sound.py`, `xauthority.py` implements the
  `.Xauthority` format so no `xauth` binary is needed).
  `helpers/nvidia.py` and `helpers/gpu.py` auto-detect GPU drivers and ICDs.
- `helpers/android.py`, `arch.py`, `names.py`, `rate_limit.py` are small focused
  utilities (Termux ownership/`/data` remount, CPU arch detection and ELF probing,
  container-name validation, shared token-bucket bandwidth limiter).
- Python < 3.14 gets `tarfile`/zstd from `backports.zstd`. Follow the existing
  `if sys.version_info >= (3, 14):` import pattern when adding a tar user.

### Adding or changing a command
Four places, all required:
1. a sub-builder in `parser.py` (plus `ALIAS_TO_CANONICAL` / `REQUIRED_ARGS`),
2. an entry in `cli._COMMAND_HANDLERS` pointing at `commands/<name>.py`,
3. a hand-written help page in `commands/help/pages.py` (argparse help text is
   never shown to users; `commands/help/render.py` renders the pages),
4. the three completion scripts in `src/chroot_distro/completions/`.

## Storage Layout
**Termux**: `$PREFIX/var/lib/chroot-distro/` (cache nested inside it)
**Linux**: `~/.local/share/chroot-distro/` with cache in `~/.cache/chroot-distro/`
(root's home when elevated; both follow `XDG_DATA_HOME` / `XDG_CACHE_HOME`)
```
containers/<name>/rootfs/          # container filesystem
containers/<name>/manifest.json    # image metadata (for reset, run, push)
data/<name>/                       # session count, mount_opts.json, holder pid/flags, run.log
sessions/                          # active session records (one JSON per live session, for ps)
locks/                             # lock files (prevent concurrent operations)
cache/oci_layers/                  # downloaded image layers
cache/oci_manifests/               # downloaded manifests
cache/build_cache_index.json       # build step cache index
```
Paths come from `constants.py`; per-container paths come from `paths.py`. Never
build these paths by hand.

## Platform Differences
**Termux (Android):**
- Uses `su` from root manager (Magisk/KernelSU/APatch)
- No daemon, every command elevates via `su`
- The root side needs a Termux-aware prelude (PATH, `LD_PRELOAD=/data/data/com.termux/files/usr/lib/libtermux-exec-ld-preload.so`,
  writable HOME, TMPDIR); see `elevate._termux_root_env_exports`
- Prefix: `$PREFIX` (usually `/data/data/com.termux/files/usr`)
- Home: `$HOME` (usually `/data/data/com.termux/files/home`)
- Extra binds for Android integration (`/apex`, `/system`, `/vendor`, dalvik
  cache, storage) live in `commands/login/bindings.py`

**Regular Linux:**
- Daemon-based (socket `/run/chroot-distro.sock`) after `setup`
- Falls back to `sudo` if daemon not running
- Containers live in root's XDG dirs
- GPU passthrough auto-detected (NVIDIA/AMD/Intel)

## Type Checking
Type checking is enforced via mypy, ruff and pyright. Run `./check-before-commit.sh` to verify types before committing. `cli.py`, `paths.py` and `constants.py` are held to stricter mypy settings (`disallow_untyped_defs`); keep them fully annotated.

## Environment Variables
Key runtime variables (see README.md for full list):
- `CD_DOCKER_AUTH`: registry credentials (`username:password`)
- `CD_USE_NS`: force namespace isolation for all sessions
- `CD_USE_ISOLATION`: force maximum isolation (`--isolated`)
- `CD_DOWNLOAD_WORKERS`: parallel layer downloads (default 4)

Debug/escape hatches that are intentionally not in README.md:
`CD_NO_DAEMON=1` (skip the daemon socket), `CD_NO_CAP_DROP=1` (keep the full
capability bounding set), `CD_SU_PATH` / `CD_SU_MOUNT_MASTER=1` (Termux `su`
selection and namespace), `CD_SUBID_BASE` (user-namespace subid base),
`CD_PUSH_CHUNK_SIZE`, `CD_SECRET_FILE` (internal, set by `elevate.py`).

## Coding Rules
- Always follow YAGNI: don't build for a need that doesn't exist yet. Before adding an abstraction, config option, dependency, or generalized code path, check whether something simpler (stdlib, an existing helper already in the repo, one plain line) already covers it: build for the requirement in front of you, not a hypothetical future one.
- Keep the runtime dependency-free (stdlib only, plus `backports-zstd` below Python 3.14).
- Be careful with unrequested destructive actions (deletions, force-pushes, overwrites).
- Comments: minimal, only atop a function/class, never inline. Add only if the name/existing comments don't already cover it; keep them in sync with the code.
- When referencing anything in comments or commits, make sure the thing you're referencing is valid in a way that other users/contributors seeing this on their own system can understand and access: don't reference anything that only exists on your system or is only accessible to you.
- Tests: focused, not slop. Skip smoke/regression tests that only confirm a deletion.
- Untrusted input is everywhere: image layers, tar members, Dockerfiles, `name:path` specs. Resolve paths against the rootfs with the existing helpers (`paths.resolve_container_path`, `tar_extract._safe_resolve`, `login/passwd.resolve_rootfs_path`) instead of joining strings, and never let a symlink decide where a write lands.
- Indentation follows `.editorconfig`: tabs in shell scripts and completions, 4 spaces in Python, YAML and Markdown.

## Output style
No narration: don't explain what you're checking, why, or what you found;
no reasoning trace, no tool-call list. Work silently: speak only for a
blocking question or a 1-2 line status, e.g.:
`tasks 1-5 (engine) done, tasks 6-13 (commands, tests, frontend) remain.`

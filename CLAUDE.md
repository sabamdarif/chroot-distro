# CLAUDE.md

Guidance for coding agents working in this repository. `AGENTS.md` is a symlink
to this file, so Claude Code and other agents read the same instructions.

## Project Overview

**chroot-distro** is a lightweight Linux container management utility that runs
real Linux distributions inside Termux (rooted Android) or regular Linux using
native kernel features (`chroot`, `mount`, namespaces). It downloads Docker/OCI
images, builds images from Dockerfiles, and manages container lifecycles, all
without Docker or Podman. It needs Python 3.10+ (CI tests 3.10 through 3.14;
`.python-version` pins 3.12 for local dev), a Linux kernel, and root access.

### Hard requirements

These are not preferences. A change that breaks one of them is wrong even if it
works:

- **Pure Python, no binary calls.** Every kernel operation goes through the
  ctypes/libc wrappers in `syscalls/`. Never shell out to a binary to do work
  this program can do itself: not as a primary path, not as a fallback, not
  "just for this one case". Where a binary call is still in the tree it is a
  debt to remove, not a pattern to copy: prefer deleting the call over keeping
  it alive. `shutil.which` for a *capability report* (`commands/info.py`) is
  fine; `shutil.which` to then exec the thing is not.
- **No third-party runtime dependencies.** Stdlib only, plus `backports-zstd`
  below Python 3.14. Dev-only tooling (ruff, mypy, pyright, pytest) does not
  count.
- **Both platforms, always.** Termux on rooted Android and regular Linux are
  equal targets; a feature that only works on one is incomplete. See
  [Platform Differences](#platform-differences).
- **Root is assumed.** The program elevates itself (`elevate.py`) rather than
  degrading to an unprivileged mode.

## How to Work Here
### Output style
No narration: don't explain what you're checking, why, or what you found;
no reasoning trace, no tool-call list. Work silently: speak only for a
blocking question or a 1-2 line status, e.g.:
`tasks 1-5 (engine) done, tasks 6-13 (commands, tests, frontend) remain.`

Never use an em dash (or `--` standing in for one) in a sentence, anywhere:
replies, comments, commit messages, docs. A comma, a colon, parentheses or two
sentences always say it.

### YAGNI

Default to the laziest solution that actually works, and write nothing that is
not needed. This governs code, comments and commit messages alike.

Stop at the first rung that holds:
1. does this need to exist at all (skip speculative work);
2. does this repo already have a helper or pattern for it;
3. does the stdlib do it;
4. does a kernel feature cover it (`syscalls/` already wraps most of them);
5. can it be one line;
6. only then, the minimum new code.

No unrequested abstractions: no interface for one implementation, no config
option for a value that never changes, no scaffolding "for later". Write it
when there is a reason to, not because the shape of the file suggests it.

If it takes a paragraph to justify, do not do it. A workaround that needs a
long explanation to look acceptable is the wrong workaround, so fix the code
instead. The length of the justification is the signal.

**Comments.** A comment exists to save the next contributor time. Write one
only when the code cannot say it itself: an invariant, a reason a safe-looking
line is not safe, a kernel or platform quirk. Keep it atop the function or
class, never inline. Never restate what the line does, never narrate a change,
never add one because a function looks bare. Deleting a comment that says
nothing is an improvement.

**Commit messages.** A subject line, and a short body only if the change needs
one, saying what changed and why in a few sentences. Not an essay: no
bullet-by-bullet tour of the diff, no restating the code in prose, no recap of
the reasoning that got there. If the body runs long, the change is too big for
one commit or the message is padded. Someone has to read it.

Never skimp on: input validation at trust boundaries, error handling that
prevents data loss, security, or anything explicitly requested. Being lazy is
about not adding; it is never about dropping a check.

### Coding rules
- Keep the runtime dependency-free (stdlib only, plus `backports-zstd` below Python 3.14).
- Be careful with unrequested destructive actions (deletions, force-pushes, overwrites).
- Keep comments in sync with the code they sit on; a stale comment is worse than none.
- When referencing anything in comments or commits, make sure the thing you're referencing is valid in a way that other users/contributors seeing this on their own system can understand and access: don't reference anything that only exists on your system or is only accessible to you.
- Tests: focused, not slop. Skip smoke/regression tests that only confirm a deletion.
- Untrusted input is everywhere: image layers, tar members, Dockerfiles, `name:path` specs. Resolve paths against the rootfs with the existing helpers (`paths.resolve_container_path`, `tar_extract._safe_resolve`, `login/passwd.resolve_rootfs_path`) instead of joining strings, and never let a symlink decide where a write lands.
- Indentation follows `.editorconfig`: tabs in shell scripts and completions, 4 spaces in Python, YAML and Markdown.
- Commits follow [Conventional Commits](https://www.conventionalcommits.org):
  `type(scope): subject`, e.g. `fix(build): ...`, `feat(clear-cache): ...`,
  `test(e2e): ...`. Pick the type from what the commit does (`fix`, `feat`,
  `test`, `refactor`, `docs`, `chore`) and the scope from the subsystem touched
  (`build`, `build-cache`, `run`, `locking`, `atomic`, `tar-extract`, or several
  comma-separated). A bare `scope: subject` with no type is not acceptable.

### Build, test, lint
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

`cli.py`, `paths.py` and `constants.py` are held to stricter mypy settings
(`disallow_untyped_defs`); keep them fully annotated.

## What Is Already Documented

`README.md` is the user-facing reference, and it is the source of truth for
anything a user can see. Read it there instead of re-deriving it, and update it
in the same change when behaviour moves:

- [Commands reference](README.md#commands-reference): every command, its flags
  and its examples.
- [Storage layout](README.md#storage-layout): the data and cache folders per
  platform.
- [Environment variables](README.md#environment-variables): every supported
  `CD_*`, `TERMUX_*` and `XDG_*` variable.
- [Limitations](README.md#limitations): what the program deliberately does not
  do.

Two things live only here, because a user has no use for them.

**Data-folder paths README omits:** `data/<name>/` (session count,
`mount_opts.json`, holder pid/flags, `run.log`) and
`cache/build_cache_index.json` (build step cache index). Paths come from
`constants.py`; per-container paths come from `paths.py`. Never build these
paths by hand.

**Debug/escape hatches, deliberately undocumented:**
`CD_NO_DAEMON=1` (skip the daemon socket), `CD_NO_CAP_DROP=1` (keep the full
capability bounding set), `CD_SU_PATH` / `CD_SU_MOUNT_MASTER=1` (Termux `su`
selection and namespace), `CD_SUBID_BASE` (user-namespace subid base),
`CD_PUSH_CHUNK_SIZE`, `CD_SECRET_FILE` (internal, set by `elevate.py`).

## Architecture

Three layers, each depending only on the ones above it:

`commands/` (CLI behaviour) -> `helpers/` (policy, orchestration) -> `syscalls/` (raw kernel calls)

Kernel operations go through the ctypes wrappers in `syscalls/`; `nsenter(1)`
and `unshare(1)` are fully reimplemented there (`syscalls/nsenter.py`,
`syscalls/unshare.py`) and nothing new may exec a binary to reach the kernel.

No container work execs a binary. A chroot is described by a `ChrootConfig`
(`commands/login/chroot_cmd.build_chroot_config`) and entered by
`syscalls.chroot.enter_chroot` / `chroot_and_run` in the child itself, after
setns(2) and the capability drop, so the holder is handed a config rather than a
command line and `build_engine/run_step.py` forks the step the same way. The
argv forms that remain (`chroot_display_argv`, `NamespaceHolder.nsenter_flags`)
are only ever printed, for `--get-chroot-cmd`.

The exception is host administration, not container work: `elevate.py`
(`sudo`/`doas`/`pkexec`/`su`) and `commands/setup.py` (`groupadd`/`usermod` and
the init-system tools) drive other programs' own state, which no syscall
replaces. `commands/info.py` calling `shutil.which` to *report* whether a tool
exists is a capability probe, not a call.

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
  exclusive locks are re-entrant within one process. Every lock file is addressed
  as `(dir_fd, name)`: `locks/` is guest-writable on Termux and its names are
  predictable, so `_locks_dir_fd` walks down from `RUNTIME_DIR` with `O_NOFOLLOW`
  and `open_lock_file_at` refuses anything that is not a plain file. Nothing else
  writes there, so a planted entry is dropped and the real lock made in its
  place; one that cannot be dropped fails closed (`_HostileLockError`) instead of
  proceeding unlocked.
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
The holder is forked and unshared in this process
(`syscalls/unshare.create_holder_process`, returning a `HolderPids`, and the
holder is a grandchild under `CLONE_NEWPID` so it can be PID 1); given a
*rootfs* it chroots itself, which closes the `chroot /proc/1/root` escape. Under
max isolation the hardened mount set `login/bindings.py` names (procfs with
`hidepid=2`, read-only sysfs, tmpfs `/dev`, devpts, `/dev/shm`) is made from
inside that namespace, `mount_manager` reaching it through `holder.call` and
`holder.do_*`, so nothing execs a tool in the guest and no mount is set up from
the host's view. `helpers/max_iso_holder.py` is the old standalone PID 1 for
this, run as `python3 -m`; nothing in `src/` executes or imports it any more.
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
recipe hash (index and lock reached by an `O_NOFOLLOW` walk down to the cache
directory, so a planted entry under either fixed name is refused rather than
read, and a lock name that cannot be cleared records the step unlocked instead
of failing the build). How much of the index a build will read is its own
choice too: the file holds one record per cached step, so the read is capped at
`_MAX_INDEX_BYTES` (16 MiB) counted off the bytes actually drawn, and an entry
holding more raises rather than yielding a prefix, because half a JSON document
parses as no index at all, and `record()` would then write over entries it had merely
declined to finish reading. A finished layer is renamed into the cache through
`atomic.publish_file`, and the scratch root a build assembles its stages in is
created with `mkdirat` off an `O_NOFOLLOW` walk down to `RUNTIME_DIR/build-tmp`
(falling back to `/tmp`), then removed under that same descriptor, so neither a
planted `oci_layers` nor a planted `build-tmp` can redirect a build's output.
A `RUN --mount` scratch copy goes the same way at the end of the step
(`run_mounts._remove_scratch`, recording the names below the scratch root rather
than a path): the tree is what the step wrote, so its depth and its modes are
the step's choice, and `shutil.rmtree(ignore_errors=True)` swallowed an OSError
but not the RecursionError a deep tree raises, in a teardown that runs after the
step has already succeeded.
Both halves of a step address the stage rootfs by descriptor rather than by the
name they resolved: `tar_extract.safe_resolve_parts` says where a `COPY`/`ADD`
entry belongs and `copy_step._materialise_entry` re-walks those components with
`O_NOFOLLOW` to write it as `(dir_fd, name)`, while `layer_diff.snapshot` walks
on descriptors and `_add_entry` takes its parent from `_ParentFds` and sizes a
file from the fstat of the descriptor it reads.
The stage rootfs itself is pinned the same way. `commands/build._make_build_tmp`
hands back the scratch root's path *and* a descriptor on it, `engine`
`_make_stage_dirs` makes `stage-N/rootfs` off that descriptor, and a `Stage`
carries both fds (its own directory and its rootfs) for the length of the build.
Every consumer takes one as an optional keyword (`snapshot`, `write_layer_tar`,
`_materialise_files`, `_copy_from_rootfs`, `resolve_chown`,
`resolve_user_for_chroot`, `do_workdir`, `write_resolv_conf`/`write_hosts`),
so production always passes it and a test working on a tree it made itself keeps
the path form. `RUN` closes the last of it in the forked child
(`run_step._fork_step`): it fchdirs onto the pinned descriptor and hands
`enter_chroot` `os.curdir`, so chroot(2) resolves its argument against the inode
the build validated, and it happens after the namespaces are joined and before
the exec. The path stays for what only a path can express: messages, bind
sources, and the `--mount=from=` bind that reaches mount(2) as a string anyway.
The rest of the scratch root goes with it, being the same class of name: the ADD
spool (`copy_step._Spool`, creating each file `O_EXCL` off the directory's fd)
and a `COPY --from` image's throwaway tree are both made and read through
descriptors from `_open_scratch_dir`.
The *source* side is the same bargain: `copy_step._SourceTree` is the one way a
`COPY`/`ADD` source is located, resolving the spec beneath the build context or
the stage rootfs with `safe_resolve_parts` (so `..` is refused and a symlink out
re-anchors at the tree root), and a `file` entry then carries the tree it was
found under plus the components below it. Both consumers open it through
`layer_diff.MapSources`, which re-walks those components with `O_NOFOLLOW`, so
nothing reads a source by name a second time. `_add_directory_tree` walks an
explicit stack of directory descriptors bounded by `dirfd.Levels` instead of
`os.walk`, and `ADD`'s auto-extract sniffs and unpacks through one descriptor on
the archive (`parsing.is_tar_header` takes the bytes, not a name). A directory is
descended without a `.dockerignore` check on purpose: `dockerignore._match`
prefix-matches, so a pattern on a directory already covers its children, and a
`!` line re-including one of them only survives if the walk goes in.
An `ADD <url>` is held to the length its response declared: there is no digest to
check a download against here, so a body ending short of its `Content-Length`
used to be published as the whole file, and `_copy_url` refuses it (the header
itself is read by `_declared_length`, which answers "none declared" for one it
cannot parse, as http.client does). `_Spool.stream` returns the byte count for
that comparison. The same net catches `http.client.HTTPException`, since the
family http.client raises for a body cut mid-chunk is not an `OSError` and left
`build` as a traceback.

A base image's config is a document this program did not write, and every field
is read back as the type OCI says it is (`User` and `Shell` decide what a RUN
step runs and who as, `WorkingDir` becomes its cwd, `OnBuild` is parsed as
Dockerfile lines, the rest are merged into by their handlers and published in
the produced image). `engine._adopt_image_config` is the one place a pulled
config is taken on: it holds each field to its shape and refuses a wrong type
with a `BuildError` naming it, treats a null as absent rather than as a value,
rewrites `ExposedPorts`/`Volumes` down to their key sets, reads a null label as
`""`, and takes a non-int layer `size` in the manifest as 0. The environment a
RUN step is handed goes the same way: `constants.is_host_exec_var` names what a
loader reads out of it (the `LD_*` prefix) and both Dockerfile-owned sources are
refused it: an `ENV` line or a declared `ARG`'s value never reaches
`run_step._build_child_env`'s output, and an `ENV` fired by the base image's
ONBUILD triggers (`engine.firing_onbuild`, checked in `handlers.do_env`) is
dropped outright, being a stranger's line rather than the author's. What the
user's own environment says still reaches the exec, since they chose this command
line; a value the Dockerfile set still stands in the image config, which is what
it was a statement about. The step's own exec happens after chroot(2), so this is
provenance and not a host-loader escape: what the Dockerfile's author wrote
about the image is not a line the image's own base or a stranger's ONBUILD gets
to add to the loader's environment.

### Cross-cutting
- `atomic.py`: every state file write goes through `atomic_write` /
  `atomic_replace` (tempfile, fsync, rename) so a crash never leaves half a file.
  A destination inside `RUNTIME_DIR` or `BASE_CACHE_DIR` has the components below
  that root walked one at a time with `O_NOFOLLOW` and its temporary created
  `O_EXCL` off the descriptor, so a `cache/oci_layers -> <host dir>` a guest left
  behind cannot redirect the write; a path the *user* named (`backup -o`,
  `build --output`) keeps the plain behaviour. Which is why an archive is packed
  into the descriptor `atomic_write` staged rather than into a second open of the
  temporary's name (`oci_writer.write_oci_archive`): the name is this program's,
  but the directory is the user's, and between the create and a reopen the
  temporary can be unlinked and replaced with a symlink that the rename then
  publishes over whatever it pointed at. `atomic_replace` yields the path, so it
  is for a destination whose writer needs one.
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

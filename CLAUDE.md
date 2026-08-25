## chroot-distro

**chroot-distro** is a lightweight Linux container management utility that runs
real Linux distributions inside Termux (rooted Android) or regular Linux using
native kernel features (`chroot`, `mount`, namespaces). It downloads Docker/OCI
images, builds images from Dockerfiles, and manages container lifecycles, all
without Docker or Podman. It needs Python 3.10+ (CI tests 3.10 through 3.14;
`.python-version` pins 3.12 for local dev), a Linux kernel, and root access.
GPL-3.0-only; the files ported from
[proot-distro](https://github.com/termux/proot-distro) say so in their docstring,
and a new port must too.

### Hard requirements

These are not preferences. A change that breaks one of them is wrong even if it
works:

- **Pure Python, no binary calls.** Every kernel operation goes through the
  ctypes/libc wrappers in `syscalls/`. Never shell out to a binary to do work
  this program can do itself: not as a primary path, not as a fallback, not
  "just for this one case". Where a binary call is still in the tree it is a
  debt to remove, not a pattern to copy: prefer deleting the call over keeping
  it alive. `shutil.which` for a _capability report_ (`commands/info.py`) is
  fine; `shutil.which` to then exec the thing is not.
- **No third-party runtime dependencies.** Stdlib only, plus `backports-zstd`
  below Python 3.14. Dev-only tooling (ruff, mypy, pyright, pytest) does not
  count.
- **Both platforms, always.** Termux on rooted Android and regular Linux are
  equal targets; a feature that only works on one is incomplete. See
  [Platform Differences](#platform-differences).
- **Root is assumed.** The program elevates itself (`elevate.py`) rather than
  degrading to an unprivileged mode. In Linux it depend on chroot-distro.socket for root privileges
  or if it isn't enabled then it must be run with sudo else it will show an error.
  And it case of termux it uses su, also that's the only binary it called.

## How to Work Here

### Output style

No narration: don't explain what you're checking and why.
No reasoning trace, no tool-call list. Work silently: speak only for a
blocking questions or or any important finding that might need users attention
or user should know about it, in a 1-2 line status, e.g.:
`tasks 1-5 (engine) done, tasks 6-13 (commands, tests, frontend) remain.`

Never use an em dash (or `--` standing in for one) in a sentence, anywhere:
replies, comments, commit messages, docs. A comma, a colon, parentheses or two
sentences always say it. Older code predates the rule; fix what you touch, don't
sweep the tree.

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

Never skimp on: input validation at trust boundaries, error handling that
prevents data loss, security, or anything explicitly requested. Being lazy is
about not adding; it is never about dropping a check.

#### Comments

A comment exists to save the next contributor time. Write one only when the
code cannot say it itself: an invariant, a reason a safe-looking line is not
safe, a kernel or platform quirk. Keep it atop the function or class, never
inline. Never restate what the line does, never narrate a change, never add
one because a function looks bare. Deleting a comment that says nothing is an
improvement.

#### Commit messages

A subject line, and a short body only if the change needs one, saying what
changed and why in a few sentences. Not an essay: no bullet-by-bullet tour of
the diff, no restating the code in prose, no recap of the reasoning that got
there. If the body runs long, the change is too big for one commit or the
message is padded. Someone has to read it.

#### This file

Same rules, and it is loaded into every request, so a line that does not
change what an agent does is pure cost. Record the invariant, not the bug that
taught it: why one commit did what it did belongs in that commit, and why a
line is the way it is belongs on the line. Hard cap 1000 lines, and going near
it means something has been described that the code already says.

### Coding rules

- Be careful with unrequested destructive actions (deletions, force-pushes, overwrites).
- Keep comments in sync with the code they sit on; a stale comment is worse than none.
- When referencing anything in comments or commits, make sure the thing you're referencing is valid in a way that other users/contributors seeing this on their own system can understand and access: don't reference anything that only exists on your system or is only accessible to you.
- Tests: focused, not slop. Skip smoke/regression tests that only confirm a deletion.
- Untrusted input is everywhere: image layers, tar members, Dockerfiles, `name:path` specs. Resolve a guest path with the existing helpers (`paths.resolve_container_path`, `tar_extract.safe_resolve_parts`, `login/passwd.resolve_rootfs_path`) instead of joining strings, and see [Paths and descriptors](#paths-and-descriptors) for what to do with the result.
- License header on every Python file in the package: an SPDX line, a copyright
  line, then the module docstring. `plans/module-headers.md` has the exact form.
- The module docstring is where a file's own documentation lives: what it owns,
  the invariants a caller must not break, the quirk that shaped it. It is part of
  the code, so a change that moves behaviour updates it in the same commit; a
  header describing what the file used to do is worse than none.
- Fix a wrong header whenever you are in the file, even where your change did not
  touch what it got wrong. Reading enough of a file to change it is the only thing
  that catches a header that has drifted, so a stale line found there is repaired
  there, not left for a commit that happens to need it.
- Indentation follows `.editorconfig`: tabs in shell scripts and completions, 4 spaces in Python, YAML and Markdown.
- Commits follow [Conventional Commits](https://www.conventionalcommits.org):
  `type(scope): subject`, e.g. `fix(build): ...`, `feat(clear-cache): ...`,
  `test(e2e): ...`. Pick the type from what the commit does (`fix`, `feat`,
  `test`, `refactor`, `docs`, `chore`) and the scope from the subsystem touched
  (`build`, `build-cache`, `run`, `locking`, `atomic`, `tar-extract`, or several
  comma-separated). A bare `scope: subject` with no type is not acceptable.

### Build, test, lint

```bash
./check-before-commit.sh                 # ruff, pyright, mypy, pytest+coverage; all must pass
uv sync                                  # create/refresh .venv with dev deps
uv run pytest tests/unit/test_cli.py     # one test file
uv run pytest tests/unit/test_cli.py::test_name -x   # one test
uv run ruff check --fix src/chroot_distro
pip install -e .                         # install locally for testing
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

Three layers, each depending only on the ones to its right:

`commands/` (CLI behaviour) -> `helpers/` (policy, orchestration) -> `syscalls/` (raw kernel calls)

Every `.py` file under `src/chroot_distro/` carries a license header and a module
docstring saying what that file owns, the invariants a caller must not break, and
the platform quirks that shaped it. The tables below are only the index into those
headers, one row per file: find the files a task touches, read their headers, then
change them.

Kernel operations go through the ctypes wrappers in `syscalls/`; `chroot(1)`,
`mount(1)`, `umount(1)`, `unshare(1)` and `nsenter(1)` are fully reimplemented
there and nothing new may exec a binary to reach the kernel.

No container work execs a binary. A chroot is described by a `ChrootConfig`
(`commands/login/chroot_cmd.build_chroot_config`) and entered by
`syscalls.chroot.enter_chroot` / `chroot_and_run` in the child itself, after
setns(2) and the capability drop, so the holder is handed a config rather than a
command line and `build_engine/run_step.py` forks the step the same way. The argv
forms that remain (`chroot_display_argv`, `NamespaceHolder.nsenter_flags`) are only
ever printed, for `--get-chroot-cmd`.

The exception is host administration, not container work: `elevate.py`
(`sudo`/`doas`/`pkexec`/`su`) and `commands/setup.py` (`groupadd`/`usermod` and the
init-system tools) drive other programs' own state, which no syscall replaces.
`commands/info.py` calling `shutil.which` to _report_ whether a tool exists is a
capability probe, not a call.

### Entry point and dispatch

| File                        | Owns                                                     |
| --------------------------- | -------------------------------------------------------- |
| `cli.py`                    | validate, decide whether root is needed, dispatch        |
| `parser.py`                 | the argparse tree, `ALIAS_TO_CANONICAL`, `REQUIRED_ARGS` |
| `constants.py`              | roots, platform detection, the `CD_*` readers            |
| `exceptions.py`             | the expected-failure tree                                |
| `names.py`                  | the container-name rule                                  |
| `commands/help/pages.py`    | the text of every help page                              |
| `commands/help/render.py`   | width-clamped rendering to stderr                        |
| `commands/help/__init__.py` | `HELP_COMMANDS`, plus the front page                     |
| `__init__.py`               | `__version__`, resolved only when asked for              |
| `__main__.py`               | `python -m chroot_distro`                                |

### Paths and descriptors

`dirfd.py` is the primitive, and three rules cover why most of the filesystem code
goes through it:

- **Resolve a name once.** A helper says where an entry belongs
  (`tar_extract.safe_resolve_parts`, `paths.resolve_container_path`), then the
  caller re-walks those components and acts on `(dir_fd, name)`. Handing the
  resolved path back to the kernel is the bug the walk exists to prevent.
- **Pin a root you will use twice.** A rootfs, a stage, a cache dir: hold the
  descriptor for the length of the operation and address everything beneath it from
  there. That includes teardown: a tree a guest or a build step wrote picks its own
  depth and modes, so `shutil.rmtree` is the wrong tool for one (`ignore_errors`
  swallows an `OSError`, not the `RecursionError` a deep tree raises).
- **Fixed names under a guest-reachable root are walked, not joined.** `locks/`,
  `cache/oci_layers`, `cache/build_cache_index.json`, `build-tmp`: a symlink planted
  under a name this program picks must not redirect a write, so a planted entry is
  refused or dropped rather than followed.

| File                     | Owns                                                       |
| ------------------------ | ---------------------------------------------------------- |
| `dirfd.py`               | openat(2) walks, guarded opens, the bounded `Levels` stack |
| `paths.py`               | per-container path composition, `name:path` resolution     |
| `atomic.py`              | staged temporary plus rename, for every state file         |
| `helpers/tar_extract.py` | one streaming extractor for layers and rootfs tarballs     |

### Root and elevation

| File                     | Owns                                                                     |
| ------------------------ | ------------------------------------------------------------------------ |
| `elevate.py`             | re-exec as root: caps, Termux `su`, the socket, then sudo/doas/pkexec/su |
| `daemon.py`              | the group-gated socket, its client, and the forked root child            |
| `commands/daemon_cmd.py` | the init system's entry point                                            |
| `commands/setup.py`      | the group, the service for five init systems, `--uninstall`              |

### Session lifecycle (`login`, `run`, `build`)

| File                           | Owns                                                        |
| ------------------------------ | ----------------------------------------------------------- |
| `locking.py`                   | `ContainerLock`, `BuildLock`, `RunCacheLock`                |
| `helpers/session.py`           | the per-container session refcount                          |
| `helpers/session_registry.py`  | one JSON file per live session                              |
| `helpers/mount_manager.py`     | every mount, unmount, `/dev` node and propagation change    |
| `commands/login/__init__.py`   | resolve a session, mount for it, enter it                   |
| `commands/login/bindings.py`   | name the mounts a session needs, mount nothing              |
| `commands/login/chroot_cmd.py` | `ChrootConfig`, and the argv only `--get-chroot-cmd` prints |
| `commands/login/env.py`        | the environment a session runs with                         |
| `commands/login/passwd.py`     | the guest's account databases, and `resolve_rootfs_path`    |
| `commands/run.py`              | Entrypoint/Cmd resolution, then `login`                     |
| `commands/ps.py`               | list the sessions that are alive now                        |
| `commands/kill.py`             | stop everything in a container, tear the state down         |
| `commands/unmount.py`          | the orderly end: signal, zero, unmount                      |

### Isolation and namespaces

Three levels, and the difference between them is the mount set, not the
namespaces: default keeps host mounts and no namespaces; `CD_USE_NS` turns the
namespaces on and keeps the default mount set; `--isolated` or `CD_USE_ISOLATION`
binds nothing from the host and chroots the holder. `build` has no flag for it, so
there the env vars are the whole interface.

| File                            | Owns                                                                |
| ------------------------------- | ------------------------------------------------------------------- |
| `helpers/isolation.py`          | compose namespaces plus chroot, for all three callers               |
| `helpers/isolation_warnings.py` | turn a missing namespace into advice                                |
| `helpers/namespace.py`          | which namespaces this host can give, and the holder that keeps them |
| `helpers/max_iso_holder.py`     | nothing live: superseded standalone PID 1                           |
| `syscalls/__init__.py`          | the constant re-exports                                             |
| `syscalls/_constants.py`        | kernel constants and the namespace maps                             |
| `syscalls/_libc.py`             | the one libc handle, `check_syscall`, two backports                 |
| `syscalls/mount.py`             | binds, filesystem mounts, propagation changes                       |
| `syscalls/umount.py`            | umount2(2)                                                          |
| `syscalls/chroot.py`            | four ways to enter a chroot, plus `spawn_detached`                  |
| `syscalls/unshare.py`           | make namespaces, and hold them open                                 |
| `syscalls/nsenter.py`           | join namespaces with setns(2)                                       |
| `syscalls/idmap.py`             | idmapped mounts, so no rootfs needs chowning                        |
| `syscalls/capabilities.py`      | drop the bounding-set capabilities a guest must not keep            |

### Image pull, push and install

Every install writes `containers/<name>/manifest.json` with `image_ref`, `arch`,
`manifest` and `image_config`. That file is the source of truth for `reset`, `run`
(Entrypoint/Cmd), `push`, `diff` and the guest env defaults in
`commands/login/env.py`, and it is a document this program wrote but only half
chose, so every consumer holds its fields to the type OCI gives them.

| File                          | Owns                                                       |
| ----------------------------- | ---------------------------------------------------------- |
| `helpers/docker/__init__.py`  | the registry client's public names                         |
| `helpers/docker/refs.py`      | a user's string to (registry, repo, tag)                   |
| `helpers/docker/media.py`     | media type strings, `canonical_json`                       |
| `helpers/docker/transport.py` | tokens, TLS policy, the errors both produce                |
| `helpers/docker/pull.py`      | reference to one platform's manifest, then fill the rootfs |
| `helpers/docker/layers.py`    | fetch one blob, apply one layer                            |
| `helpers/docker/cache.py`     | the blob and manifest caches                               |
| `helpers/docker/push.py`      | upload blobs first, manifest last                          |
| `helpers/download.py`         | retry policy, TLS diagnosis, the segmented downloader      |
| `rate_limit.py`               | one token bucket shared by every download thread           |
| `helpers/oci_writer.py`       | manifest, config and OCI archive out of a finished build   |
| `helpers/layer_diff.py`       | what changed, packed as an OCI layer                       |
| `commands/install.py`         | install from a registry, a URL or a local archive          |
| `commands/install_local.py`   | a plain tarball or an OCI layout on disk                   |
| `commands/push.py`            | argument work, then `helpers/docker/push.py`               |
| `commands/search.py`          | Docker Hub search                                          |

### Build pipeline

Most of this subsystem's care is [Paths and descriptors](#paths-and-descriptors):
`commands/build._make_build_tmp` returns the scratch root's path plus descriptors
on it and on its parent, a `Stage` carries fds for its own directory and its
rootfs, and every consumer takes one as an optional keyword (production passes it,
a test working on a tree it made itself keeps the path form). A path stays for what
only a path can express: messages, bind sources, and the `--mount=from=` bind that
reaches mount(2) as a string.

Two trust boundaries are the build's own, and each file's header carries the
reasoning: a base image's config is adopted at exactly one point
(`engine._adopt_image_config`), and a dynamic loader takes orders from nobody but
the caller (`build_engine/constants.is_host_exec_var`, applied in
`run_step._build_child_env` and `handlers.do_env`).

| File                                   | Owns                                                   |
| -------------------------------------- | ------------------------------------------------------ |
| `helpers/dockerfile.py`                | Dockerfile text to instruction records                 |
| `helpers/build_cache.py`               | step results keyed by recipe hash                      |
| `helpers/build_engine/__init__.py`     | the engine's surface                                   |
| `helpers/build_engine/constants.py`    | the tables consulted before dispatch                   |
| `helpers/build_engine/errors.py`       | the exception that ends a build                        |
| `helpers/build_engine/parsing.py`      | one instruction's value text to a handler's pieces     |
| `helpers/build_engine/stage.py`        | the per-FROM state                                     |
| `helpers/build_engine/events.py`       | build events and the three reporters                   |
| `helpers/build_engine/dockerignore.py` | `.dockerignore` loading and matching                   |
| `helpers/build_engine/engine.py`       | one stage per FROM, one handler per instruction        |
| `helpers/build_engine/handlers.py`     | every instruction that edits the image config          |
| `helpers/build_engine/run_step.py`     | run one RUN, pack the delta                            |
| `helpers/build_engine/run_mounts.py`   | `RUN --mount`, all five types                          |
| `helpers/build_engine/users.py`        | a USER or `--chown` name against the image's databases |
| `helpers/build_engine/copy_step.py`    | COPY and ADD: locate, write, pack                      |
| `commands/build.py`                    | validate, run the engine, publish                      |
| `commands/diff.py`                     | what a rootfs holds that its image did not             |

### Container lifecycle and file transfer

| File                      | Owns                                              |
| ------------------------- | ------------------------------------------------- |
| `commands/list_cmd.py`    | what is installed, its size, whether it is busy   |
| `commands/remove.py`      | stop, unmount, delete both trees                  |
| `commands/rename.py`      | one `os.rename` of the container directory        |
| `commands/reset.py`       | delete the rootfs, install the same image again   |
| `commands/backup.py`      | write a container out as a tar stream             |
| `commands/restore.py`     | rebuild one container from a backup stream        |
| `commands/clear_cache.py` | empty the download cache, or drop the build cache |
| `commands/copy.py`        | copy or move between host paths and containers    |
| `commands/sync.py`        | mirror a tree, optionally pruning orphans         |

### Display, hardware and platform integration

| File                        | Owns                                                      |
| --------------------------- | --------------------------------------------------------- |
| `helpers/display.py`        | one display environment, and the paths to bind for it     |
| `helpers/x11.py`            | the host X11 session, and a cookie the guest can read     |
| `helpers/wayland.py`        | the Wayland half                                          |
| `helpers/sound.py`          | the audio half                                            |
| `helpers/xauthority.py`     | the `.Xauthority` format, so no `xauth` binary is needed  |
| `helpers/gpu.py`            | ICD and loader descriptors for the Mesa stack             |
| `helpers/nvidia.py`         | the proprietary driver's libraries, ICDs and tools        |
| `helpers/android.py`        | the Termux-side fixups, and nothing on Linux              |
| `helpers/rootfs.py`         | the guest `/etc` files this program writes                |
| `helpers/owner.py`          | a `--chown` spec to the numeric pair                      |
| `arch.py`                   | host arch, image arch, and what a rootfs turned out to be |
| `commands/info.py`          | one report a bug can be filed with                        |
| `commands/kernel_config.py` | what the running kernel was built with                    |

### Output and shared utilities

| File                  | Owns                                              |
| --------------------- | ------------------------------------------------- |
| `message.py`          | every user-facing line, and the rules they follow |
| `progress.py`         | bars, spinners, byte counters                     |
| `helpers/__init__.py` | nothing: a marker module                          |

Python below 3.14 gets `tarfile` with zstd from `backports.zstd`. Follow the
existing `if sys.version_info >= (3, 14):` import pattern when adding a tar user.

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

# Chroot-Distro

Chroot-Distro is a utility for managing rootful Linux containers in
[Termux](https://termux.dev) and on regular Linux hosts. It uses the
host kernel's native `chroot` and bind mounts (`mount --bind`) to provide a
high-performance, near-native Linux environment.

Containers are created by pulling Docker/OCI images directly from
Docker Hub or any compatible registry — or by extracting a local
tarball / OCI image archive. The container filesystem is assembled from
the image layers and stored locally, ready to be entered at any time.

Chroot-Distro can also **build** OCI images from a Dockerfile (no Docker
daemon required), storing the result in the local manifest cache or
exporting it as a standalone OCI tarball.

Unlike [proot-distro](https://github.com/termux/proot-distro) (which is
rootless via `proot`), Chroot-Distro **requires root privileges** on the host. Mutating commands
automatically re-launch themselves via `sudo`, `doas`, `pkexec`, or `su`
when needed (see [First-run check](#first-run-check)).

---

## Table of contents

1. [Introduction](#introduction)
2. [Commands reference](#commands-reference)
   * [`install`](#install--install-a-container)
   * [`build`](#build--build-an-image-from-a-dockerfile)
   * [`push`](#push--push-a-built-image-to-a-registry)
   * [`login`](#login--start-a-shell-inside-a-container)
   * [`run`](#run--run-the-image-defined-entrypoint)
   * [`list`](#list--list-installed-containers)
   * [`remove`](#remove--delete-a-container)
   * [`unmount`](#unmount--unmount-a-container)
   * [`rename`](#rename--rename-a-container)
   * [`reset`](#reset--reinstall-a-container-from-scratch)
   * [`backup`](#backup--archive-a-container)
   * [`restore`](#restore--restore-a-container-from-a-backup)
   * [`copy`](#copy--copy-files-to-or-from-a-container)
   * [`sync`](#sync--synchronize-files-to-or-from-a-container)
   * [`clear-cache`](#clear-cache--delete-the-download-cache)
   * [`help`](#help--show-command-help)
3. [How Chroot-Distro works](#how-chroot-distro-works)
4. [Storage layout](#storage-layout)
5. [Environment variables](#environment-variables)
6. [Shell completions](#shell-completions)
7. [Limitations](#limitations)
8. [Donate](#donate)

---

## Introduction

Chroot-Distro lets you run a full Linux userland — Ubuntu, Debian,
Alpine, Arch, openSUSE, distroless server images, anything available as
a Docker/OCI image — on top of Termux on a rooted Android device, or on
top of a regular Linux distribution, **with** native kernel performance,
**without** the overhead of `proot`'s `ptrace` interception, and
**without** a Docker daemon.

Typical use cases:

- Running a desktop-class Linux distribution on a phone or tablet at
  near-native speed (rooted device required on Termux).
- Disk-intensive and compile workloads (GCC/Clang, Rust, Go) without
  `proot` slowdowns.
- Spinning up server software (Nginx, Nextcloud, PostgreSQL, etc.) on
  Android by reusing the same OCI images you'd run on a server.
- Building custom OCI images from a Dockerfile on-device, without a
  Docker daemon — and pushing them to Docker Hub, GHCR, or any
  OCI-compatible registry.
- Trying a distribution non-destructively: install, experiment,
  `chroot-distro remove` when done.

### Installation

Chroot-Distro requires **Python 3.10 or newer**. There are no third-party
Python dependencies. Because it uses native `chroot` and bind mounts, the
effective user for mutating operations must be **root** (see
[First-run check](#first-run-check)).

#### On Termux (Android)

1. Root your device (Magisk, KernelSU, APatch, or similar).
2. Install Termux from
   [F-Droid](https://f-droid.org/en/packages/com.termux/) or
   [Termux GitHub Releases](https://github.com/termux/termux-app/releases).
3. Install Chroot-Distro:

```sh
pkg install python
pip install chroot-distro
```

From a local checkout:

```sh
git clone https://github.com/sabamdarif/chroot-distro
cd chroot-distro
pip install .                     # regular install
# pip install -e .                # editable install for development
```

#### On a regular Linux host

```sh
# Debian/Ubuntu example:
sudo apt install python3-pip

pip install chroot-distro
# or from a checkout:
git clone https://github.com/sabamdarif/chroot-distro
cd chroot-distro
pip install .
```

### First-run check

On startup, commands that modify containers or mounts verify that the
effective UID is `0`. If not, Chroot-Distro re-executes itself using, in
order: `sudo`, `doas`, `pkexec`, or `su`.

| Situation | Behaviour |
|---|---|
| Default | Auto-elevate when not root. |
| `--no-elevate` or `CHROOT_DISTRO_NO_ELEVATE=1` | Skip elevation; exit with an error if not root. |
| Termux, default | Prefer `su` (real root) over `sudo`. |
| Termux, `--use-sudo` or `CHROOT_DISTRO_USE_SUDO=1` | Prefer `sudo` for elevation. |

`list` and `help` do not require root and are never re-executed.

### Quick start

```sh
# Install Ubuntu 24.04 from Docker Hub
chroot-distro install ubuntu:24.04

# Start a shell inside the container
chroot-distro login ubuntu

# Same thing, using the login alias
chroot-distro sh ubuntu

# Run a single command and exit
chroot-distro login ubuntu -- /bin/uname -a

# List all installed containers
chroot-distro list

# Build and install a custom image from a Dockerfile
chroot-distro build -t myapp:1.0 --install-as myapp ./mycontext

# Publish the built image to a registry
export CD_DOCKER_AUTH=myuser:mypassword
chroot-distro push myuser/myapp:1.0

# Rebuild from scratch (loses all in-container data)
chroot-distro reset ubuntu

# Unmount bindings and end active sessions
chroot-distro unmount ubuntu

# Permanently remove a container (unmounts active sessions first)
chroot-distro remove ubuntu
```

---

## Commands reference

Every subcommand supports `--help` (also `-h`), which prints help text
laid out for the current terminal width.

**Global flags** (before the subcommand):

| Option | Description |
|---|---|
| `-h`, `--help` | Show top-level help. |
| `--no-elevate` | Do not auto-elevate to root (`CHROOT_DISTRO_NO_ELEVATE=1`). |
| `--use-sudo` | On Termux, prefer `sudo` over `su` (`CHROOT_DISTRO_USE_SUDO=1`). |

Short aliases are accepted for many commands (`sh` → `login`, `rm` →
`remove`, `ins` → `install`, etc.); each section below lists them.

### `install` — Install a container

```
chroot-distro install [OPTIONS] (IMAGE or PATH or URL)
Aliases: add, i, in, ins
```

Pull a Docker/OCI image and create a container from it, extract a local
archive, or download a remote archive over HTTP/HTTPS.

**Options:**

| Option | Description |
|---|---|
| `-n`, `--name NAME` | Custom local container name. Defaults to the image name (without tag/registry) or the archive filename. Must start with a letter or digit; may contain only letters, digits, `_`, `.`, `-`. |
| `--override-alias NAME` | Same as `-n` / `--name` (mutually exclusive). |
| `-a`, `--architecture ARCH` | Override target CPU architecture. Accepts native names (`aarch64`, `arm`, `i686`, `riscv64`, `x86_64`) or Docker platform strings (`linux/arm64`, `linux/amd64`, …). Defaults to the host CPU. |
| `-q`, `--quiet` | Suppress non-error output. |

#### From a Docker/OCI registry

`IMAGE` is a standard Docker image reference:

| Form | Example |
|---|---|
| Official image | `ubuntu:24.04` |
| Official, no tag (uses `latest`) | `alpine` |
| User image | `myuser/myimage:tag` |
| Custom registry | `ghcr.io/foo/bar:latest` |

Custom registries are detected when the first path component contains
`.` or `:` (a hostname). Public images on `ghcr.io`, `quay.io`,
`registry.gitlab.com`, etc. are pulled with an anonymous Bearer token
discovered from each registry's `/v2/` challenge.

**Private images** require credentials. Set `CD_DOCKER_AUTH` to
`username:password` (or `username:PAT`) before running `install`. The
colon separator is mandatory. `PD_DOCKER_AUTH` is accepted as a fallback
for compatibility with proot-distro:

```sh
export CD_DOCKER_AUTH=myuser:mypassword
chroot-distro install myuser/private-image:tag

export CD_DOCKER_AUTH=myuser:ghp_xxx
chroot-distro install ghcr.io/myorg/private-image:tag
```

Layers are cached under `$BASE_CACHE_DIR/oci_layers/` and reused on
subsequent installs. If the resolved manifest and all layers are already
cached, installation runs fully offline.

**Examples:**

```sh
chroot-distro install ubuntu:24.04
chroot-distro install alpine:3.21 --name my-alpine
chroot-distro install debian:bookworm --architecture aarch64
chroot-distro install ghcr.io/myorg/myimage:latest
```

#### From a local archive

`IMAGE` can be a path starting with `/`, `./`, `../`, or `~`. A bare
token like `ubuntu` is always treated as a Docker image reference.

Two archive formats are supported (auto-detected):

- **Plain rootfs tarball** — top-level entries form a standard Linux
  filesystem (`bin/`, `etc/`, `usr/`, …). Strip level is scored
  automatically. Compression: gzip, bzip2, xz, lzma, or uncompressed.
  No `manifest.json` is written (`reset` and `run` are not available).
- **OCI image layout** — archive contains `oci-layout` at its root (as
  from `docker save` or `skopeo copy oci-archive:`). Layers are applied
  with OCI whiteout semantics; `manifest.json` is written so `reset` and
  `run` work like registry installs.

**Examples:**

```sh
chroot-distro install ./alpine-rootfs.tar.gz
chroot-distro install ./myimage.oci.tar --name myimage
```

#### From a URL

When an HTTP or HTTPS URL is given instead of a local path, the archive
is downloaded fully and then processed the same way as a local file.
Only `http://` and `https://` are supported. The default container name
is derived from the last URL path component; use `--name` to override.

```sh
chroot-distro install https://example.com/rootfs.tar.xz --name demo
```

After installation, if the image defines an `Entrypoint`, a
`Run entrypoint: chroot-distro run <name>` hint is printed alongside
`Start shell: chroot-distro login <name>`.

---

### `build` — Build an image from a Dockerfile

```
chroot-distro build [OPTIONS] [PATH]
```

Build an OCI/Docker-compatible image from a Dockerfile. `PATH` is the
build context directory (default `.`); all `COPY`/`ADD` source paths are
resolved relative to it.

By default the built image is stored in the local manifest cache under
the tag given by `--tag` (default `<basename(PATH)>:latest`). A subsequent
`chroot-distro install <tag>` installs entirely without network access.

**Options:**

| Option | Description |
|---|---|
| `-f`, `--file PATH` | Dockerfile at PATH instead of `<PATH>/Dockerfile`. Pass `-` to read from stdin. |
| `-t`, `--tag REF` | Image reference to assign. Repeatable. |
| `--build-arg K=V` | Set a build-time `ARG` (only declared `ARG`s are honoured). Repeatable. |
| `--architecture ARCH` | Target CPU architecture (default: host). |
| `--target STAGE` | Stop after the named multi-stage build stage. |
| `-o`, `--output FILE` | Write an OCI image-layout tarball to FILE. Compression inferred from the extension. Repeatable. |
| `--install-as NAME` | After build, install the image as container NAME. |
| `--no-cache` | Disable per-step build caching. |
| `-v`, `--verbose` | Echo each instruction and stream `RUN` output. |
| `-q`, `--quiet` | Suppress non-error output. |

**Supported Dockerfile instructions:**

`FROM` (multi-stage, `FROM scratch`, `COPY --from=`), `RUN` (shell,
JSON exec, here-doc), `COPY` (`--from`, `--chown`, `--chmod`), `ADD`,
`CMD`, `ENTRYPOINT`, `ENV`, `ARG`, `LABEL`, `MAINTAINER`, `USER`,
`WORKDIR`, `EXPOSE`, `VOLUME`, `STOPSIGNAL`, `HEALTHCHECK`, `SHELL`,
`ONBUILD`.

BuildKit-only features (`RUN --mount`, `RUN --network`,
`RUN --security`, `COPY --link`, `COPY --parents`) are rejected with an
explicit error.

**`chroot` requirement:**

If the Dockerfile contains any `RUN` instruction, each step executes
inside the in-progress rootfs via `chroot` and therefore requires root.
Metadata-only builds (`COPY`/`ADD`/`ENV`/… without `RUN`) run in
pure-Python mode and do not require root.

**Examples:**

```sh
chroot-distro build .
chroot-distro build -t myapp:1.0 --install-as myapp .
chroot-distro build -t myapp:arm64 --architecture aarch64 -o myapp.oci.tar.gz .
chroot-distro build --build-arg HTTP_PROXY=$HTTP_PROXY -t myapp .
```

**Limitations:**

`RUN` steps run under `chroot`, not a real container runtime: no PID,
network, or IPC isolation, no `cgroups`, no `seccomp`. Steps that depend
on real namespaces or kernel features may fail or behave differently from
`docker build`. Multi-platform manifest lists are not produced.

---

### `push` — Push a built image to a registry

```
chroot-distro push [OPTIONS] IMAGE
```

Upload a locally built image to a Docker/OCI registry. The image must
have been produced by `chroot-distro build -t IMAGE` first; `push` reads
the manifest and blobs from the local cache. No Docker daemon is
required.

**Options:**

| Option | Description |
|---|---|
| `--architecture ARCH` | Push the manifest built for the given architecture (must match the build). Default: host. |
| `-q`, `--quiet` | Suppress non-error output. |

**Authentication:**

Set `CD_DOCKER_AUTH=username:password` (colon required). `PD_DOCKER_AUTH`
is accepted as a fallback:

```sh
chroot-distro build -t myuser/myapp:1.0 ./mycontext
export CD_DOCKER_AUTH=myuser:mypassword
chroot-distro push myuser/myapp:1.0
```

Each layer is HEAD-probed first; existing blobs are skipped. 401/403
responses include a hint to set or fix `CD_DOCKER_AUTH`.

---

### `login` — Start a shell inside a container

```
chroot-distro login [OPTIONS] CONTAINER [-- COMMAND ...]
Aliases: sh
```

Spawn an interactive shell (or a custom command) inside an installed
container. The `--` separator passes arguments to the container's login
shell.

**Examples:**

```sh
chroot-distro login ubuntu
chroot-distro login ubuntu --user myuser
chroot-distro login ubuntu -- /bin/ls /etc
chroot-distro login ubuntu -- bash -c "echo hello"
chroot-distro sh ubuntu
chroot-distro login ubuntu --get-chroot-cmd
```

**Options always available:**

| Option | Description |
|---|---|
| `-u`, `--user USER` | Log in as USER (default: `root`). Accepts `name`, numeric `uid`, `name:group`, or `uid:gid`. |
| `--isolated` | Reduce host exposure. On Termux: skip Android system, storage, and `$PREFIX` binds unless you opt in with `--shared-*` or `--bind`. On Linux: skip default `/tmp` and `/tmp/.X11-unix` unless `--shared-tmp` or `--shared-x11`. Mutually exclusive with `--minimal`. |
| `--minimal` | Bare minimum chroot: core pseudo-filesystems only (`/dev`, `/proc`, `/sys`, plus `/run`, `/dev/pts`, `/dev/shm` when present). Stripped guest environment. Mutually exclusive with `--isolated`. |
| `--shared-home` | Bind the invoking user's host home into the guest home (or `/root` for root). On Termux, binds `TERMUX_HOME`. |
| `--termux-home` | Alias for `--shared-home` (proot-distro compatibility). |
| `--shared-tmp` | Bind host tmp (`/tmp` on Linux, `$PREFIX/tmp` on Termux) to `/tmp` in the guest. On Linux, included by default unless `--isolated`. |
| `--shared-x11` | Bind the host X11 socket directory to `/tmp/.X11-unix` in the guest. On Linux, included by default unless `--isolated`. |
| `-b`, `--bind SRC[:DST]` | Bind-mount a custom host path (repeatable). `DST` must be an absolute guest path. |
| `--hostname STRING` | Hostname inside the container (default: `localhost`). |
| `-w`, `--work-dir PATH` | Initial working directory (default: user's home). |
| `-e`, `--env VAR=VALUE` | Set a guest environment variable (repeatable). |
| `--get-chroot-cmd` | Print the fully assembled `env` + `chroot` command line and exit. |

#### Host bindings (Linux, default mode)

Without `--isolated` or `--minimal`, host `/tmp` and `/tmp/.X11-unix`
(when present) are bind-mounted into the guest. Use `--isolated` to
skip those defaults, or `--minimal` for only core pseudo-filesystems.
Home is never bind-mounted unless you pass `--shared-home`.

#### Host bindings (Termux, default mode)

Without `--isolated` or `--minimal`, the following host paths are
bind-mounted when present and readable:

```
/apex
/data/app
/data/dalvik-cache
/data/misc/apexdata/com.android.art/dalvik-cache
/data/data/<termux-app-package>
/linkerconfig/com.android.art/ld.config.txt
/linkerconfig/ld.config.txt
/odm
/plat_property_contexts
/product
/property_contexts
/sdcard
/storage/emulated/0
/storage/self/primary
/system
/system_ext
/vendor
```

For normal-type containers, the Termux `$PREFIX` is also bound at its
original path so Termux utilities (`termux-api`, `pkg`, etc.) remain
reachable inside the guest.

#### Guest environment

The host environment is **not** carried into the guest. Precedence (later
entries win):

1. Baseline: `PATH` (from `DEFAULT_PATH_ENV`), `MOZ_FAKE_NO_SANDBOX=1`,
   `PULSE_SERVER=127.0.0.1` (Termux only).
2. Image-defined `Env` from `manifest.json`.
3. Android system vars (`ANDROID_*`, `BOOTCLASSPATH`, …), Termux only,
   when not `--isolated` and not `--minimal`.
4. Your `--env VAR=VALUE` entries.
5. `HOME`, `USER`, `TERM` (default `xterm-256color`), `COLORTERM`
   (when set on the host).

On Termux (unless isolated or minimal), `$PREFIX/bin` is appended to
`PATH`. A snippet at `/etc/profile.d/termux-profile.sh` re-applies
login-time variables after the distro's `/etc/profile` runs, so
`su - someuser` inside the container does not drop them.

In `--minimal` mode only your `--env` entries plus `TERM`/`COLORTERM`
are exported.

#### Session lifecycle

The first `login` or `run` for a container performs bind mounts and
increments a session counter. Each exiting session decrements it; when
the counter reaches zero, all bind mounts are unmounted automatically.
Use `unmount` to force teardown (see below).

---

### `run` — Run the image-defined entrypoint

```
chroot-distro run [OPTIONS] CONTAINER [-- ARG ...]
```

Run the `Entrypoint` and/or `Cmd` from the container's OCI manifest
(equivalent to `docker run`). Requires an OCI install with
`manifest.json` (plain tarball installs have no recorded
Entrypoint/Cmd).

**Entrypoint and Cmd resolution:**

| Image | Args after `--` | Inner command |
|---|---|---|
| `Entrypoint` + `Cmd` | _(none)_ | `Entrypoint + Cmd` |
| `Entrypoint` + `Cmd` | `ARGS` | `Entrypoint + ARGS` (Cmd replaced) |
| Only `Cmd` | _(none)_ | `Cmd` |
| Only `Cmd` | `ARGS` | `ARGS` (Cmd replaced) |
| Only `Entrypoint` | _(none)_ | `Entrypoint` |
| Only `Entrypoint` | `ARGS` | `Entrypoint + ARGS` |
| Neither | _(none)_ | Error |
| Neither | `ARGS` | `ARGS` |

When `--work-dir` is not given, `run` uses the image `WorkingDir`
(falling back to `/`).

`run` accepts the same options as `login`. See
`chroot-distro login --help`.

**Examples:**

```sh
chroot-distro run hello-world
chroot-distro run ubuntu -- /bin/echo hi
chroot-distro run nextcloud --get-chroot-cmd
```

---

### `list` — List installed containers

```
chroot-distro list [OPTIONS]
Aliases: li, ls
```

Show installed containers (subdirectories of `containers/` with a
`rootfs/`). Does not require root. When none are installed, an install
suggestion is printed.

| Option | Description |
|---|---|
| `-q`, `--quiet` | Print only container names, one per line. |

---

### `remove` — Delete a container

```
chroot-distro remove [OPTIONS] CONTAINER
Aliases: rm
```

Permanently delete the container and all its data. **This cannot be
undone and is not confirmed.**

Before deletion, active mounts are detected via `/proc/mounts` and
unmounted cleanly. File permissions are fixed on the fly so chmod-000'd
subtrees can always be removed.

| Option | Description |
|---|---|
| `-v`, `--verbose` | Log each deleted file. |
| `-q`, `--quiet` | Suppress non-error output. Mutually exclusive with `--verbose`. |

---

### `unmount` — Unmount a container

```
chroot-distro unmount CONTAINER
Aliases: umount, um
```

Safely unmount a container's bind mounts. If chroot processes are still
running, `SIGTERM` is sent (with `SIGKILL` after two seconds if needed),
the session counter is reset to `0`, and all bind mounts are removed.
If a path is busy, a lazy unmount (`umount -l`) is attempted as a
fallback.

---

### `rename` — Rename a container

```
chroot-distro rename OLDNAME NEWNAME
```

Rename a container from `OLDNAME` to `NEWNAME`.

| Option | Description |
|---|---|
| `-q`, `--quiet` | Suppress non-error output. |

---

### `reset` — Reinstall a container from scratch

```
chroot-distro reset CONTAINER
```

Remove the container rootfs and reinstall from the image recorded in
`containers/<name>/manifest.json`. **All data inside the container is
lost.** Requires an OCI install (plain rootfs tarballs cannot be
re-pulled).

| Option | Description |
|---|---|
| `-q`, `--quiet` | Suppress non-error output. |

---

### `backup` — Archive a container

```
chroot-distro backup [OPTIONS] CONTAINER
Aliases: bak, bkp
```

Create a TAR archive containing `<name>/manifest.json` (when present)
and `<name>/rootfs/`.

**Options:**

| Option | Description |
|---|---|
| `-o`, `--output FILE` | Write to FILE instead of stdout. Refuses to overwrite an existing file. |
| `-c`, `--compress TYPE` | Force compression: `gzip`, `bzip2`, `xz`, or `none`. |
| `-v`, `--verbose` | Log each archived file. |
| `-q`, `--quiet` | Suppress non-error output. Mutually exclusive with `--verbose`. |

Compression is inferred from the file extension unless `--compress`
overrides it. Without `--output`, the archive goes to stdout
(uncompressed by default); stdout cannot be a TTY.

File ownership in the archive is zeroed. Block/char devices, FIFOs, and
sockets are skipped. `backup` is **TTY-safe** when piping into
interactive tools (e.g. `gpg -c`).

**Examples:**

```sh
chroot-distro backup ubuntu --output ubuntu.tar.xz
chroot-distro backup ubuntu | gzip > ubuntu.tar.gz
chroot-distro backup ubuntu | gpg -c > ubuntu.tar.gpg
```

---

### `restore` — Restore a container from a backup

```
chroot-distro restore [OPTIONS] [BACKUP_FILE]
```

Restore from a TAR archive. When `BACKUP_FILE` is omitted, data is read
from stdin. Compression is auto-detected.

**Options:**

| Option | Description |
|---|---|
| `-v`, `--verbose` | Log each extracted file. |
| `-q`, `--quiet` | Suppress non-error output. Mutually exclusive with `--verbose`. |

**Archive format requirements:**

- Files must live under `<name>/manifest.json` and `<name>/rootfs/…`.
  Bare-root archives are rejected.
- Without `manifest.json`, login still works but `reset` and `run` will
  not.
- Hard links in the archive are materialised as independent copies.

`restore` is **TTY-safe** for interactive pipelines
(`gpg -d archive.gpg | chroot-distro restore`).

**Examples:**

```sh
chroot-distro restore ubuntu.tar.xz
cat ubuntu.tar.xz | chroot-distro restore
gpg -d ubuntu.tar.gpg | chroot-distro restore
```

---

### `copy` — Copy files to or from a container

```
chroot-distro copy [OPTIONS] [CONTAINER:]SRC [CONTAINER:]DEST
Aliases: cp
```

Copy files between the host and a container rootfs, or between two
containers. In-container paths use the `container:path` prefix.

| Option | Description |
|---|---|
| `-r`, `--recursive` | Copy directories recursively (preserves symlinks). |
| `-m`, `--move` | Move instead of copy (delete source after success). |
| `-v`, `--verbose` | Log each copied file. |
| `-q`, `--quiet` | Suppress non-error output. Mutually exclusive with `--verbose`. |

**Examples:**

```sh
chroot-distro copy ./file.txt ubuntu:/root/file.txt
chroot-distro copy ubuntu:/etc/resolv.conf ./resolv.conf.bak
chroot-distro copy --recursive ./myapp ubuntu:/opt/myapp
```

---

### `sync` — Synchronize files to or from a container

```
chroot-distro sync [OPTIONS] [CONTAINER:]SRC [CONTAINER:]DEST
```

Synchronize SRC to DEST, copying only files that differ. Always
recursive.

**Comparison method:**

| Mode | What is compared |
|---|---|
| Default | File size and integer modification time |
| `--checksum` | File size and CRC32 checksum |

Regular files are written atomically (`.~cd_sync` temp file →
`os.replace`). Symlinks are copied as-is. Hard links become independent
copies. Block/char devices, FIFOs, and sockets are skipped.

| Option | Description |
|---|---|
| `-c`, `--checksum` | Compare by size + CRC32 instead of size + mtime. |
| `-d`, `--delete` | Remove destination entries with no source counterpart. |
| `-v`, `--verbose` | Log each synced or deleted entry. |
| `-q`, `--quiet` | Suppress non-error output. Mutually exclusive with `--verbose`. |

**Examples:**

```sh
chroot-distro sync ./app ubuntu:/opt/app
chroot-distro sync --checksum ./data ubuntu:/data
chroot-distro sync --delete ./app ubuntu:/opt/app
```

---

### `clear-cache` — Delete the download cache

```
chroot-distro clear-cache
Aliases: clear, cl
```

Remove every entry from `$BASE_CACHE_DIR` — layer blobs (`oci_layers/`),
resolved manifests (`oci_manifests/`), and the build cache index
(`build_cache_index.json`). Freed disk space is reported in human-readable
units.

| Option | Description |
|---|---|
| `-v`, `--verbose` | Log each deleted file. |
| `-q`, `--quiet` | Suppress non-error output. Mutually exclusive with `--verbose`. |

After `clear-cache`, the next `install` or `reset` of an image requires
network access again.

---

### `help` — Show command help

```
chroot-distro help [COMMAND]
Aliases: h, he, hel
```

Print detailed help for `COMMAND`, or general usage when omitted.

---

## How Chroot-Distro works

Chroot-Distro is a thin orchestration layer around two primary building
blocks:

### 1. OCI registry client

The `install` command speaks the OCI Distribution protocol directly over
`urllib`:

- Public images on **Docker Hub** need no credentials
  (e.g. `ubuntu:24.04`).
- Public images on **other registries** use a full reference
  (e.g. `ghcr.io/myorg/myimage:tag`).
- Manifest lists are resolved to the platform matching your CPU (or
  `--architecture`).
- Each layer blob is downloaded with **SHA-256 verified** before
  entering the cache.
- Layer blobs and the resolved single-arch manifest are cached locally.

Layers are applied in order with full OCI whiteout semantics. After all
layers are applied, Chroot-Distro adds small fixups when `/etc/` exists:

- `/etc/resolv.conf` is replaced with Google DNS (8.8.8.8 / 8.8.4.4).
- `/etc/hosts` gets a minimal localhost mapping.
- On Termux, the host Android user is registered as `aid_<name>` in
  `/etc/passwd`, `/etc/group`, etc., so Android UID permissions work
  inside the guest.

The OCI manifest and image config are saved to
`containers/<name>/manifest.json` for `reset` and `run`.

Local archives and HTTP/HTTPS URLs follow the same extraction paths as
in the [`install`](#install--install-a-container) section.

### 2. Native chroot and bind mounts

Unlike `proot`, which rewrites paths via `ptrace`, Chroot-Distro uses
real kernel features:

- **Bind mounts** (`mount --bind`) for host directories inside the guest.
- **Session tracking** under `$RUNTIME_DIR/data/<name>/sessions`.
- **Automatic mount/unmount**: the first session mounts; the last session
  exiting unmounts everything.
- **Lazy unmount fallback** (`umount -l`) when a target is busy.

A typical `login` invocation looks roughly like:

```sh
env PATH=… HOME=/root USER=root … \
  chroot /…/containers/ubuntu/rootfs \
  /bin/sh -c 'cd /root && exec /bin/bash -l'
```

Add `--get-chroot-cmd` to print the exact command line without running it.

#### Cross-architecture support

Guest architectures (`aarch64`, `arm`, `i686`, `x86_64`, `riscv64`) are
detected at login by reading ELF headers of common shell binaries. Cross-arch
execution uses **QEMU user-mode** via `binfmt_misc` / QEMU user binaries
installed on the host.

---

## Storage layout

All runtime data lives under `$RUNTIME_DIR`:

- **Termux**: `$TERMUX__PREFIX/var/lib/chroot-distro/`, where
  `TERMUX__PREFIX` defaults to `/data/data/com.termux/files/usr`.
- **Regular Linux**: `$XDG_DATA_HOME/chroot-distro/` (default
  `~/.local/share/chroot-distro/`).

The OCI cache (`$BASE_CACHE_DIR`) is under `$RUNTIME_DIR/cache` on
Termux, and under `$XDG_CACHE_HOME/chroot-distro/` (default
`~/.cache/chroot-distro/`) on a regular Linux host.

Because mutating commands run as root after auto-elevation, effective
paths on Linux are typically under `/root/.local/share/` and
`/root/.cache/` unless you set `XDG_DATA_HOME` / `XDG_CACHE_HOME`.

| Path | Contents |
|---|---|
| `containers/<name>/rootfs/` | Container root filesystem |
| `containers/<name>/manifest.json` | Image reference, arch, OCI manifest, image config |
| `data/<name>/sessions` | Active `login` / `run` session counter |
| `locks/<name>.lock` | Per-container POSIX flock |
| `locks/build/<key>.lock` | Build/push lock |
| `$BASE_CACHE_DIR/oci_layers/` | Cached OCI layer blobs |
| `$BASE_CACHE_DIR/oci_manifests/` | Cached single-arch manifests |
| `$BASE_CACHE_DIR/build_cache_index.json` | Dockerfile build cache index |

---

## Environment variables

| Variable | Effect |
|---|---|
| `TERMUX__PREFIX` | Override Termux prefix; drives `RUNTIME_DIR` on Termux. Default: `/data/data/com.termux/files/usr`. |
| `TERMUX__HOME` | Override Termux home for `--shared-home` bindings. Default: `/data/data/com.termux/files/home`. |
| `TERMUX_APP__PACKAGE_NAME` | Termux app package (default `com.termux`); used for `/data/data/<pkg>/…` binds. |
| `TERMUX_APP__APP_VERSION_NAME`, `TERMUX_VERSION` | Either counts toward Termux detection when set. |
| `XDG_DATA_HOME` | Base for `$XDG_DATA_HOME/chroot-distro/` on non-Termux hosts. Default: `~/.local/share`. |
| `XDG_CACHE_HOME` | Base for `$XDG_CACHE_HOME/chroot-distro/` on non-Termux hosts. Default: `~/.cache`. |
| `CD_DOCKER_AUTH` | Registry credentials as `username:password` or `username:PAT` (colon required). Used by `install`, `build` (`FROM` pulls), and `push`. `PD_DOCKER_AUTH` is accepted as a fallback. |
| `CD_FORCE_NO_COLORS` | When set, disables ANSI colours in Chroot-Distro output. |
| `CHROOT_DISTRO_NO_ELEVATE` | When set to `1`, disables privilege auto-elevation (same as `--no-elevate`). |
| `CHROOT_DISTRO_USE_SUDO` | When set to `1`, prefer `sudo` over `su` on Termux (same as `--use-sudo`). |
| `COLUMNS` | Fallback terminal width for `--help` rendering. |
| `TERM`, `COLORTERM` | Inherited into the guest (always; even in `--minimal`). `TERM` defaults to `xterm-256color` when unset on the host. |

---

## Shell completions

Completion scripts for Bash, Zsh, and Fish live in
`src/chroot_distro/completions/`:

- `chroot-distro.bash`
- `_chroot-distro`
- `chroot-distro.fish`

They complete subcommands, global flags (`--no-elevate`, `--use-sudo`),
and per-command options (including `login`/`run` flags such as
`--shared-home`, `--termux-home`, `--get-chroot-cmd`, and Termux-only
`--isolated` / `--minimal`).

If your shell does not pick them up automatically, install them manually:

```sh
# Bash
mkdir -p ~/.local/share/bash-completion/completions
cp src/chroot_distro/completions/chroot-distro.bash \
   ~/.local/share/bash-completion/completions/chroot-distro

# Zsh (add fpath before compinit in ~/.zshrc)
mkdir -p ~/.zsh/completions
cp src/chroot_distro/completions/_chroot-distro ~/.zsh/completions/_chroot-distro

# Fish
mkdir -p ~/.config/fish/completions
cp src/chroot_distro/completions/chroot-distro.fish \
   ~/.config/fish/completions/chroot-distro.fish
```

---

## Limitations

### Kernel and chroot limitations

- **Root required**: real `chroot` and bind mounts need appropriate
  privileges; there is no rootless mode.
- **No real init**: `systemd`, socket-activated supervisors, and full
  init systems generally do not work. Individual long-running processes
  are fine.
- **Kernel features**: FUSE modules, real `iptables`, custom cgroup
  hierarchies, and similar kernel-module features may not work inside the
  guest.
- **Namespaces**: Chroot-Distro is not a full container runtime — no
  network/PID/IPC namespace isolation comparable to Docker or Podman.
- **Bind mount hygiene**: crashed sessions or orphan processes can leave
  mounts busy; `unmount` and lazy unmount mitigate this but orphaned
  processes should be cleaned up.

### Chroot-Distro limitations

- **Termux requires root**: unlike proot-distro, Chroot-Distro cannot run
  containers on a non-rooted Android device.
- **Registry authentication**: private pulls and pushes need
  `CD_DOCKER_AUTH=user:password` (or `PD_DOCKER_AUTH`). Docker
  `config.json` credential helpers are not read.
- **No zstd-compressed layers**: Python's `tarfile` does not support
  zstd. Images using zstd layers fail with an explicit error; try another
  tag or compression format.
- **Dockerfile builds are not BuildKit**: `RUN` executes under `chroot`,
  not a real container runtime. BuildKit-only Dockerfile features are
  rejected. Multi-platform manifest lists are not produced — build and
  push once per architecture.
- **`push` is single-arch**: no manifest-list assembly, cross-repo blob
  mounting, or chunked uploads.
- **No live state migration**: `backup`/`restore` capture the rootfs and
  manifest, not in-memory process state.

---

## Donate

If this project is useful to you, tips in cryptocurrency are welcome:

**Bitcoin**

```
13Q7xf3qZ9xH81rS2gev8N4vD92L9wYiKH
```

**Ethereum / USDT (BEP20, ERC20)**

```
0x1d216cf986d95491a479ffe5415dff18dded7e71
```

**USDT (TRC20)**

```
TCjRKPLG4BgNdHibt2yeAwgaBZVB4JoPaD
```

**Dogecoin**

```
DJkMCnBAFG14TV3BqZKmbbjD8Pi1zKLLG6
```

---

## Issues and contributing

- **Bug reports**: https://github.com/sabamdarif/chroot-distro/issues
- **License**: GPL-3.0-only. See [LICENSE](LICENSE).

### Acknowledgments

- [proot-distro](https://github.com/termux/proot-distro) — architecture
  and CLI design inspiration.
- [Magisk-Modules-Alt-Repo/chroot-distro](https://github.com/Magisk-Modules-Alt-Repo/chroot-distro)
- [ravindu644/Ubuntu-Chroot](https://github.com/ravindu644/Ubuntu-Chroot)

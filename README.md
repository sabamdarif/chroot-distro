# Chroot-Distro

[![PyPI Release](https://img.shields.io/pypi/v/chroot-distro?style=flat&label=Release)](https://pypi.org/project/chroot-distro/)
[![PyPI Downloads](https://img.shields.io/pypi/dm/chroot-distro?style=flat&label=Downloads)](https://pypi.org/project/chroot-distro/)
[![License](https://img.shields.io/github/license/sabamdarif/chroot-distro?style=flat)](LICENSE)


Chroot-Distro is a utility for managing rootful Linux containers in Termux and on standard Linux hosts. It uses the host kernel's native `chroot(2)` and `mount(2)` system calls directly (instead of running external binaries) to provide a high-performance, near-native Linux environment.

Containers are created by pulling Docker/OCI images directly from Docker Hub (or any compatible registry), or by extracting a local tarball / OCI image archive. The container filesystem is assembled from the image layers and stored locally, ready to be entered at any time.

Chroot-Distro can also **build** OCI images from a Dockerfile (no Docker daemon required), storing the result in the local manifest cache or exporting it as a standalone OCI tarball.

Chroot-Distro requires **root privileges** on the host, but you don't have to type a password every time: a one-time `sudo chroot-distro setup` enables Docker-style passwordless operation through the `chroot-distro` group (see [Passwordless setup](#passwordless-setup-linux)). On Termux, Android's native `su` is used directly — no `sudo`/`tsu` package needed.

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
   * [`ps`](#ps--list-active-sessions)
   * [`search`](#search--search-docker-hub)
   * [`setup`](#setup--enable-passwordless-operation-linux)
   * [`diff`](#diff--inspect-filesystem-changes)
   * [`remove`](#remove--delete-a-container)
   * [`kill`](#kill--forcibly-stop-a-running-container)
   * [`unmount`](#unmount--unmount-a-container)
   * [`rename`](#rename--rename-a-container)
   * [`reset`](#reset--reinstall-a-container-from-scratch)
   * [`backup`](#backup--archive-a-container)
   * [`restore`](#restore--restore-a-container-from-a-backup)
   * [`copy`](#copy--copy-files-to-or-from-a-container)
   * [`sync`](#sync--synchronize-files-to-or-from-a-container)
   * [`clear-cache`](#clear-cache--delete-the-download-cache)
   * [`info`](#info--show-host-and-container-diagnostics)
   * [`help`](#help--show-command-help)
3. [How Chroot-Distro works](#how-chroot-distro-works)
4. [Storage layout](#storage-layout)
5. [Environment variables](#environment-variables)
6. [Shell completions](#shell-completions)
7. [Limitations](#limitations)
8. [Donate](#donate)

---

## Introduction

Chroot-Distro lets you run a full Linux userland — Ubuntu, Debian, Alpine, Arch, openSUSE, distroless server images, or anything available as a Docker/OCI image — on top of Termux on a rooted Android device, or on top of a regular Linux distribution, with native kernel performance and without needing a Docker daemon.

### Installation

Chroot-Distro requires **Python 3.10 or newer**. There are no third-party
Python dependencies. Because it uses native `chroot(2)` and `mount(2)` system calls, the
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

No `sudo`/`tsu` package is required.

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

sudo pip install chroot-distro
# or from a checkout:
git clone https://github.com/sabamdarif/chroot-distro
cd chroot-distro
sudo pip install .
```

> [!NOTE]
> **System-wide vs. User installation:** On a regular Linux host, you can install the package at the user level (e.g., `pip install .` or `pip install chroot-distro`), but commands will fall back to prompting for your sudo/doas password at runtime.
> If you want the passwordless, Docker-style daemon experience (`sudo chroot-distro setup`), you **must** install it system-wide with `sudo` (not `--user`). The daemon executes the code **as root**, so the package must reside in a secure, root-owned, non-user-writable location.

### First-run check

On startup, commands that modify containers or mounts verify that the effective UID is `0`. If not, Chroot-Distro elevates automatically using the first mechanism that works:

1. **File capabilities** — if the process already holds the six required capabilities, no elevation happens at all.
2. **Termux:** Android's `su` binary directly (Magisk / KernelSU / APatch), with the full Termux environment set up on the root side.
3. **Linux:** the passwordless `chroot-distro` daemon socket, if [Passwordless setup](#passwordless-setup-linux) has been run.
4. Fallback: `sudo`, `doas`, `pkexec`, or `su` (these prompt for a password).

`list`, `ps`, `search`, and `help` do not require root on Termux and are run immediately. `info` runs with root privileges if root is available on Termux (so it can read `/proc/config.gz`), and otherwise falls back to a rootless run. On regular Linux, `list`, `ps`, and `info` always elevate to inspect root-owned data.

### Passwordless setup (Linux)

Just like adding your user to the `docker` group lets you run `docker` without a password, Chroot-Distro ships a group-gated root daemon (pure Python, no third-party code, no `sudoers` edits). Enable it once:

```sh
sudo chroot-distro setup
```

This one command:

1. creates the **`chroot-distro`** system group,
2. adds your user to it (equivalent to `sudo usermod -aG chroot-distro $USER`),
3. detects your init system — **systemd** (with on-demand socket activation), **OpenRC**, **runit**, **dinit**, or **sysvinit** — and installs + starts the matching service, which owns the root socket at `/run/chroot-distro.sock` (`root:chroot-distro`, mode `0660`).

Then **log out and back in** (or run `newgrp chroot-distro`) so the group membership takes effect. From that point on, every `chroot-distro` command runs with no password prompt.

To add another user later:

```sh
sudo usermod -aG chroot-distro <username>
```

To remove the service again:

```sh
sudo chroot-distro setup --uninstall
```

> **Security note:** membership of the `chroot-distro` group grants root-equivalent access on the host (exactly like the `docker` group). Only add trusted users.

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

# List active sessions (PID, container, type, user, uptime, command)
chroot-distro ps

# Search Docker Hub for an image
chroot-distro search nextcloud

# Print diagnostic report for host and containers
chroot-distro info

# See what changed in a container relative to its image
chroot-distro diff ubuntu

# Unmount bindings and end active sessions
chroot-distro unmount ubuntu

# Forcibly stop a running container (SIGKILL + unmount), by name or session PID
chroot-distro kill ubuntu
chroot-distro kill 12345

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
colon separator is mandatory:

```sh
export CD_DOCKER_AUTH=myuser:mypassword
chroot-distro install myuser/private-image:tag

export CD_DOCKER_AUTH=myuser:ghp_xxx
chroot-distro install ghcr.io/myorg/private-image:tag
```

Layers are cached under `$BASE_CACHE_DIR/oci_layers/` and reused on
subsequent installs. If the resolved manifest and all layers are already
cached, installation runs fully offline.

Missing layers are downloaded in parallel (default **4** workers). Set
`CD_DOWNLOAD_WORKERS` to tune concurrency (integer **1–10**; values above
10 are capped).

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

**`chroot(2)` requirement:**

If the Dockerfile contains any `RUN` instruction, each step executes
inside the in-progress rootfs via the `chroot(2)` system call and therefore requires root.
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

Set `CD_DOCKER_AUTH=username:password` (colon required):

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
| `--isolated` | Reduce host exposure and enable namespace isolation (mount, PID, UTS, IPC, and cgroup when supported, via `unshare(2)`/`setns(2)` system calls directly). Binds **no** host paths at all — `--shared-home`, `--shared-tmp`, `--shared-display`/`--shared-x11`, and `--bind` are all ignored (with a warning) when combined with `--isolated`, since there's nothing for them to bind into. Mutually exclusive with `--minimal`. To get the same namespace isolation **without** reducing the mount set (so `--shared-*`/`--bind` keep working), set `CD_USE_NS=1` instead (see [Environment variables](#environment-variables)). |
| `--minimal` | Bare minimum chroot: core pseudo-filesystems only (`/dev`, `/proc`, `/sys`, plus `/run`, `/dev/pts`, `/dev/shm` when present). Stripped guest environment. Mutually exclusive with `--isolated`. |
| `--shared-home` | Bind the invoking user's host home into the guest home (or `/root` for root). On Termux, binds `TERMUX_HOME`. Ignored under `--isolated`. |
| `--shared-tmp` | Bind host tmp (`/tmp` on Linux, `$PREFIX/tmp` on Termux) to `/tmp` in the guest. Opt-in only: by default the container gets its own fresh `/tmp`, not the host's. Ignored under `--isolated`. |
| `--shared-display` | Share the host display server (X11 and Wayland), audio (PulseAudio/PipeWire), and D-Bus session bus with the container. Binds only the specific session sockets, not the host's whole `/run`. Opt-in only. `--shared-x11` is accepted as a backward-compatible alias. Ignored under `--isolated`. |
| `-b`, `--bind SRC[:DST]` | Bind-mount a custom host path (repeatable). `DST` must be an absolute guest path. Ignored under `--isolated`. |
| `-w`, `--work-dir PATH` | Initial working directory (default: user's home). |
| `-e`, `--env VAR=VALUE` | Set a guest environment variable (repeatable). |
| `--entrypoint EXECUTABLE` | (`run` only) Replace the image Entrypoint for this run; Cmd is cleared and any trailing `-- args` become the new arguments. |
| `--get-chroot-cmd` | Print the fully assembled `env` + `chroot` command line and exit. |

#### Display sharing

Pass `--shared-display` (or `--shared-x11`) to use your host's screen,
audio, and D-Bus session inside the container — handy for running GUI
apps. It's opt-in: without this flag, none of that is shared, and `/tmp`
and `/run` stay isolated from the host. It works best on regular Linux;
on Termux only some of this is available. `--shared-display` (like every
`--shared-*` flag) is ignored if you also pass `--isolated`, since
`--isolated` binds no host paths at all — drop `--isolated`, or use
`CD_USE_NS=1` instead, if you need display sharing alongside namespace
isolation.

#### GPU acceleration (auto-detected)

If you have a GPU (AMD, Intel, or NVIDIA), Chroot-Distro automatically
sets it up for hardware-accelerated rendering — no flag needed. This
works independently of display sharing and isn't available on Termux.

#### Namespace isolation (`--isolated` and `CD_USE_NS`)

With `--isolated`, chroot-distro creates a per-container namespace holder
(via the `unshare(2)` system call) and runs bind mounts, special mounts, and `chroot(2)` inside that
environment (via the `setns(2)` system call). Supported namespaces: **mount**, **PID**, **UTS**,
**IPC**, and **cgroup**. The cgroup namespace is acquired best-effort (used
when the kernel supports it, skipped otherwise); the **mount/PID/UTS/IPC**
set is **all-or-nothing**: chroot-distro probes that set first, and if any
one of them is unsupported on the kernel it acquires none of them and falls
back fully to a non-isolated login (with a warning naming the missing
namespace), so a session is never left half-isolated. This is **not** a full
container runtime: there is no network namespace, no user namespace
mapping, and no image layering.

`--isolated` couples two things: namespace isolation **and** binding no
host paths at all — no Android system/storage/`$PREFIX` binds on Termux,
no `/tmp` sharing, no display sharing on Linux, and no `--shared-*` /
`--bind` flags take effect (they're accepted but ignored, with a
warning, since there's nothing to bind into). If you want **only** the
namespace isolation while keeping every default mount — and keeping
`--shared-*` / `--bind` working — set the `CD_USE_NS=1` environment
variable instead: every `login`/`run` then runs in the same
mount/PID/UTS/IPC/cgroup namespaces but with the full default mount set
intact. `CD_USE_NS` accepts `1`/`true`/`yes`/`on`.

> `CD_USE_NS` is set by the invoking user but the tool re-executes itself
> as root; chroot-distro forwards the variable across `sudo`/`doas`/`pkexec`
> /`su` automatically, so it keeps working even when the `sudo` line prints
> `'-E' is ignored`.

Do not mix isolated (via `--isolated` or `CD_USE_NS`) and non-isolated
logins on the same container without running `chroot-distro unmount <name>`
first. Concurrent isolated sessions share the same holder and mounts.

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
2. Image-defined `Env` from `manifest.json` (display and GPU vars are blocked
   here — they are always set by auto-detection).
3. Android system vars (`ANDROID_*`, `BOOTCLASSPATH`, …), Termux only,
   when not `--isolated` and not `--minimal`.
4. Your `--env VAR=VALUE` entries.
5. `HOME`, `USER`, `TERM` (default `xterm-256color`), `COLORTERM`
   (when set on the host), and `HOSTNAME` (the container name).
6. When display sharing is active (via `--shared-display`):
   `DISPLAY`, `XAUTHORITY`, `XDG_RUNTIME_DIR`, `WAYLAND_DISPLAY`,
   `XDG_SESSION_TYPE`, `XDG_CURRENT_DESKTOP`, `DESKTOP_SESSION`,
   `PULSE_SERVER`, `DBUS_SESSION_BUS_ADDRESS`. Your `--env` entries override
   these.
7. On Linux (unless `--minimal`): GPU env vars when NVIDIA is auto-detected
   (independent of `--shared-display`):
   native — `__NV_PRIME_RENDER_OFFLOAD`, `__GLX_VENDOR_LIBRARY_NAME`;
   WSL2 — `GALLIUM_DRIVER`, `MESA_D3D12_DEFAULT_DEVICE_TYPE`,
   `LIBGL_ALWAYS_SOFTWARE`. Your `--env` entries override these.

`HOSTNAME` is always set to the host system hostname name. The
`hostname`/`uname` commands report it only when namespace isolation is
active (via `--isolated` or `CD_USE_NS`), where the UTS namespace is given
a real hostname; otherwise they still report the host's name (no UTS
namespace to change).

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
| any | `--entrypoint EXE` | `EXE` (Entrypoint replaced, Cmd cleared) |
| any | `--entrypoint EXE -- ARGS` | `EXE + ARGS` |

`--entrypoint` (or the `CD_ENTRYPOINT` env var) replaces the image
Entrypoint entirely for this run, mirroring `docker run --entrypoint`;
Cmd is cleared and any trailing `-- args` become the new arguments.
The `CD_USER`, `CD_WORKDIR`, and `CD_ENV` environment variables provide
the same defaults as `--user`, `--work-dir`, and `--env` (a CLI flag
always wins over the matching env var).

When `--work-dir` is not given, `run` uses the image `WorkingDir`
(falling back to `/`).

`run` accepts the same options as `login`. See
`chroot-distro login --help`.

**Examples:**

```sh
chroot-distro run hello-world
chroot-distro run ubuntu -- /bin/echo hi
chroot-distro run ubuntu --entrypoint /bin/echo -- overridden
chroot-distro run nextcloud --get-chroot-cmd
```

---

### `list` — List installed containers

```
chroot-distro list [OPTIONS]
Aliases: li, ls
```

Show installed containers (subdirectories of `containers/` with a
`rootfs/`). For each container prints **rootfs size**, **image source**
(Docker/OCI reference and architecture from `manifest.json`, or
`local archive` for plain tarballs), and **status** (`idle` or
`in use` with PID when another command holds the container lock).
Does not require root. When none are installed, an install suggestion is
printed.

| Option | Description |
|---|---|
| `-q`, `--quiet` | Print only container names, one per line. |

---

### `ps` — List active sessions

```
chroot-distro ps [OPTIONS]
```

List every active container session — one row per live `login` or `run`.
Each session is tracked by a per-PID JSON file under
`$RUNTIME_DIR/sessions/` with flock-based liveness detection (immune to
PID recycling and crash-safe). Does not require root.

Output columns:

| Column | Description |
|---|---|
| `PID` | Host PID of the session's chroot process. |
| `CONTAINER` | Container name. |
| `TYPE` | `login` or `run` (recorded at session start). |
| `USER` | User the session runs as. |
| `UPTIME` | Elapsed time since session start (e.g. `3m12s`, `1h04m`). |
| `COMMAND` | Inner command line (shell-quoted, truncated to terminal width). |

Example output:

```
PID     CONTAINER  TYPE   USER  UPTIME  COMMAND
12345   ubuntu     login  root  3m12s   /bin/bash -l
12388   debian     run*    root  0m44s   nginx -g 'daemon off;'

* detached session
```

| Option | Description |
|---|---|
| `-q`, `--quiet` | Print only PIDs, one per line (for scripting). |

---

### `search` — Search Docker Hub

```
chroot-distro search [OPTIONS] TERM
Aliases: find, se
```

Search Docker Hub for images matching `TERM` and print the image name,
star count, whether it is an official image, and a short description.
Uses a single unauthenticated request to the Docker Hub search API.
Requires network access; does **not** require root.

| Option | Description |
|---|---|
| `-l`, `--limit N` | Maximum number of results to show (default `25`, max `100`). |

**Examples:**

```sh
chroot-distro search nextcloud
chroot-distro search --limit 50 ubuntu
```

---

### `setup` — Enable passwordless operation (Linux)

```
chroot-distro setup [--uninstall]
```

One-time setup that enables Docker-style passwordless operation on a
regular Linux host. Run once as root; it creates the `chroot-distro`
group, adds the invoking user to it, and installs + starts the
group-gated root daemon under your init system (**systemd**, **OpenRC**,
**runit**, **dinit**, or **sysvinit**). See
[Passwordless setup (Linux)](#passwordless-setup-linux) for the full
workflow, group management, and the security note.

chroot-distro must be installed system-wide as root (not
`pip install --user`); a user-writable install is refused because the
daemon re-executes the code as root. Not applicable on Termux, which
uses the root manager's native `su` and needs no setup.

| Option | Description |
|---|---|
| `--uninstall` | Stop and remove the daemon service. The `chroot-distro` group is kept. |

**Examples:**

```sh
sudo chroot-distro setup
sudo chroot-distro setup --uninstall
```

---

### `diff` — Inspect filesystem changes

```
chroot-distro diff CONTAINER
```

Inspect changes to files and directories in a container's filesystem
relative to the OCI/Docker image it was installed from (like
`docker diff`). The image baseline is reconstructed from the cached OCI
layers, then compared against the live rootfs. Output uses Docker-style
markers:

| Marker | Meaning |
|---|---|
| `A` | File or directory was added |
| `C` | File or directory was changed |
| `D` | File or directory was deleted |

Pseudo-filesystem mount points (`/dev`, `/proc`, `/sys`, `/run`, `/tmp`)
are excluded. Available only for containers installed from an image whose
layers are still present in the cache (avoid `clear-cache` to keep `diff`
working).

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
If a path is busy, a lazy unmount (via the `umount2(2)` system call with `MNT_DETACH`) is attempted as a
fallback.

---

### `kill` — Forcibly stop a running container

```
chroot-distro kill (CONTAINER | PID)
```

Forcibly stop a running container. The argument may be a container name or a session PID shown in `chroot-distro ps`. When a session PID is provided, the entire container that the session belongs to is stopped. Only PIDs from active chroot-distro sessions are accepted; random host PIDs are rejected.

All processes inside the container's chroot are sent `SIGTERM` and then `SIGKILL` after a short grace period, the bind mounts are unmounted, and the namespace holder (if any) is released. This is the abrupt counterpart to `unmount` (equivalent to `docker kill`).

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

### `info` — Show host and container diagnostics

```
chroot-distro info
Aliases: version-info, nf
```

Print a structured diagnostics report about the host and installed containers. Useful to attach when filing a bug report so issues can be reproduced and triaged faster.

The report covers five sections:

- **Program** — `chroot-distro` version, Python version, data location.
- **Host** — On Termux: Termux version, Android release/SDK, device. On Linux: distribution name/version, kernel, libc. Host CPU architecture and 32-bit support are shown in both cases.
- **Capabilities** — Host checks that affect launching containers: privilege-escalation tool (`sudo`/`doas`/`pkexec`/`su`), Termux `/data` suid/exec flags, `binfmt_misc` + QEMU for foreign architectures, `unshare`/`nsenter` and user-namespace support, free disk space on the data dir, download cache size, and SELinux/AppArmor mode.
- **Images** — Every installed container with rootfs size, detected architecture, image source, busy/idle status, plus source URL and image type from manifest labels when available.
- **Analysis** — Lightweight checks per image: architecture mismatch against the host, missing manifest, empty or unusual rootfs.

Like `list` and `ps`, `info` is a read-only command. On Termux, it automatically runs with root privileges if root is available (to read root-only files like `/proc/config.gz`), otherwise falling back to a rootless run. On regular Linux hosts, it always elevates to inspect the same root-owned data directory where containers are installed.

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

Chroot-Distro uses real kernel features rather than path rewriting:

- **Bind mounts** (via the `mount(2)` system call) for host directories inside the guest.
- **Session tracking** under `$RUNTIME_DIR/data/<name>/sessions` (counter)
  and `$RUNTIME_DIR/sessions/<pid>.json` (per-session registry for `ps`,
  with `flock`-based liveness detection).
- **Automatic mount/unmount**: the first session mounts; the last session
  exiting unmounts everything.
- **Lazy unmount fallback** (via the `umount2(2)` system call with `MNT_DETACH`) when a target is busy.

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

### Directory Variables and Definitions

The application dynamically computes paths based on the environment (Termux/Android vs. Regular Linux):

| Variable | Description | Termux Path | Regular Linux Path |
|---|---|---|---|
| `RUNTIME_DIR` | Root directory for application state (containers, sessions, locks, logs). | `/data/data/com.termux/files/usr/var/lib/chroot-distro` | `~/.local/share/chroot-distro` |
| `BASE_CACHE_DIR` | Base directory for caching downloaded OCI layers, manifests, and build cache index. | `$RUNTIME_DIR/cache` | `~/.cache/chroot-distro` |
| `CONTAINERS_DIR` | Directory containing the root filesystems (`rootfs`) of installed distributions. | `$RUNTIME_DIR/containers` | `~/.local/share/chroot-distro/containers` |
| `SESSIONS_DIR` | Directory for active session tracker files (`<pid>.json`) used by the `ps` command. | `$RUNTIME_DIR/sessions` | `~/.local/share/chroot-distro/sessions` |
| `LOCKS_DIR` | Directory for POSIX flock files to prevent concurrent access conflicts. | `$RUNTIME_DIR/locks` | `~/.local/share/chroot-distro/locks` |
| `LAYER_CACHE_DIR` | Directory where downloaded OCI layers are cached. | `$BASE_CACHE_DIR/oci_layers` | `~/.cache/chroot-distro/oci_layers` |
| `MANIFEST_CACHE_DIR` | Directory where fetched OCI manifests are cached. | `$BASE_CACHE_DIR/oci_manifests` | `~/.cache/chroot-distro/oci_manifests` |

> [!NOTE]
> Since mutating commands on regular Linux run as `root` (via auto-elevation), the regular Linux paths above will default to being under the `/root` home directory (e.g., `/root/.local/share/chroot-distro` and `/root/.cache/chroot-distro`) unless `XDG_DATA_HOME` or `XDG_CACHE_HOME` are explicitly set and forwarded.


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

### User-configurable variables

| Variable | Effect |
|---|---|
| `TERMUX__PREFIX` | Override Termux prefix; drives `RUNTIME_DIR` on Termux. Default: `/data/data/com.termux/files/usr`. |
| `TERMUX__HOME` | Override Termux home for `--shared-home` bindings. Default: `/data/data/com.termux/files/home`. |
| `TERMUX_APP__PACKAGE_NAME` | Termux app package (default `com.termux`); used for `/data/data/<pkg>/…` binds. |
| `TERMUX_APP__APP_VERSION_NAME`, `TERMUX_VERSION` | Either counts toward Termux detection when set. |
| `XDG_DATA_HOME` | Base for `$XDG_DATA_HOME/chroot-distro/` on non-Termux hosts. Default: `~/.local/share`. |
| `XDG_CACHE_HOME` | Base for `$XDG_CACHE_HOME/chroot-distro/` on non-Termux hosts. Default: `~/.cache`. |
| `CD_DOCKER_AUTH` | Registry credentials as `username:password` or `username:PAT` (colon required). Used by `install`, `build` (`FROM` pulls), and `push`. |
| `CD_DOWNLOAD_WORKERS` | Parallel registry layer downloads during `install` (default `4`, maximum `10`). Invalid values use the default; out-of-range values are clamped. |
| `CD_DOWNLOAD_RATE_LIMIT` | Bandwidth limit for downloads (e.g., `5M` for 5 MiB/s, default `0` = unlimited). Supports suffixes `K`, `M`, `G` (case-insensitive). |
| `CD_DOWNLOAD_MAX_RETRIES` | Maximum retry attempts per connection failure (default `3`, clamped between `0` and `20`). |
| `CD_USE_NS` | When truthy (`1`/`true`/`yes`/`on`), every `login`/`run` uses full Linux namespace isolation (mount, PID, UTS, IPC, and cgroup when supported) **without** skipping any default bind mounts. Differs from `--isolated`, which also reduces the mount set. Forwarded across privilege elevation automatically. |
| `CD_USE_ISOLATION` | When truthy (`1`/`true`/`yes`/`on`), forces **maximum isolation** on — the env-var equivalent of `--isolated` (bind no host paths, chroot the namespace holder) — even when the flag is absent. Honored by `login`, `run`, and `build` (which has no `--isolated` flag; this is the only way to isolate its `RUN` steps). For `build`, the container's `/etc/resolv.conf` is written so package installs keep DNS. Forwarded across privilege elevation automatically. |
| `CD_FORCE_NO_COLORS` | When set, disables ANSI colours in Chroot-Distro output. |
| `CD_USER` | Default user for `login`/`run` (`name`, `uid`, or `uid:gid`) when `--user` is not given. Precedence: `--user` > `CD_USER` > image `User` > `root`. |
| `CD_WORKDIR` | Default working directory for `login`/`run` when `--work-dir` is not given. Precedence: `--work-dir` > `CD_WORKDIR` > image `WorkingDir` > home/`/`. |
| `CD_ENV` | Newline-separated `VAR=VALUE` entries added to the guest environment (lines without `=` are ignored). Layered before `--env`, so a matching `--env` wins. |
| `CD_ENTRYPOINT` | Replaces the image Entrypoint for `run` when `--entrypoint` is not given (Cmd is cleared). Precedence: `--entrypoint` > `CD_ENTRYPOINT` > image `Entrypoint`. `run` only. |
| `COLUMNS` | Fallback terminal width for `--help` rendering. |
| `TERM`, `COLORTERM` | Inherited into the guest (always; even in `--minimal`). `TERM` defaults to `xterm-256color` when unset on the host. |

### Auto-set guest environment variables

These are set automatically by chroot-distro at login. They cannot be
overridden from `manifest.json` image `Env`, but can be overridden with
`--env`.

**Display and audio (Linux, non-minimal, only when `--shared-display` /
`--shared-x11` is passed — not set by default):**

| Variable | Source / Fallback |
|---|---|
| `DISPLAY` | Host `$DISPLAY`; fallback `:0` |
| `XAUTHORITY` | Host `$XAUTHORITY`; fallback `~/.Xauthority`; fallback Xwayland auth file in `/run/user/<uid>/` |
| `XDG_RUNTIME_DIR` | Host `$XDG_RUNTIME_DIR`; fallback `/run/user/<uid>` |
| `WAYLAND_DISPLAY` | Host `$WAYLAND_DISPLAY`; fallback `wayland-0` if socket exists |
| `XDG_SESSION_TYPE` | Host `$XDG_SESSION_TYPE` (no fallback) |
| `XDG_CURRENT_DESKTOP` | Host `$XDG_CURRENT_DESKTOP` (no fallback) |
| `DESKTOP_SESSION` | Host `$DESKTOP_SESSION` (no fallback) |
| `PULSE_SERVER` | Host `$PULSE_SERVER`; fallback `unix:/run/user/<uid>/pulse/native` if socket exists |
| `DBUS_SESSION_BUS_ADDRESS` | Host `$DBUS_SESSION_BUS_ADDRESS`; fallback `unix:path=/run/user/<uid>/bus` if socket exists |

**Hostname and GPU (non-minimal, auto-detected/auto-set):**

| Variable | Value |
|---|---|
| `HOSTNAME` | The container name (`hostname`/`uname -n` only reflect it under `--isolated`) |
| `__NV_PRIME_RENDER_OFFLOAD`, `__GLX_VENDOR_LIBRARY_NAME` | `1`, `nvidia` — NVIDIA on native Linux |
| `GALLIUM_DRIVER`, `MESA_D3D12_DEFAULT_DEVICE_TYPE`, `LIBGL_ALWAYS_SOFTWARE` | `d3d12`, `GPU`, `0` — NVIDIA on WSL2 |

---

## Shell completions

Completion scripts for Bash, Zsh, and Fish live in
`src/chroot_distro/completions/`:

- `chroot-distro.bash`
- `_chroot-distro`
- `chroot-distro.fish`

They complete subcommands, global flags, and per-command options (including
`login`/`run` flags such as `--shared-home`, `--shared-display`,
`--get-chroot-cmd`, `--isolated`, and `--minimal`).

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

### Design choices (not limitations)

- **Shared network by default**: containers use the host's network stack
  directly. There is no network namespace and no per-container network
  isolation, even under `--isolated` / `CD_USE_NS=1`. This is intentional:
  Chroot-Distro targets fast, near-native access to the host (Wi-Fi,
  mobile data, VPNs already configured on the host, etc.) rather than
  Docker-style network sandboxing, so there is no virtual NIC, no NAT, and
  no per-container firewall to set up or work around.
- **Shared GPU by default**: GPU passthrough (see
  [GPU acceleration](#gpu-acceleration-auto-detected)) is automatic and
  unconditional whenever supported hardware/drivers are detected — it is
  not gated behind `--isolated`, `--shared-display`, or any opt-in flag.
  The container talks to the same `/dev/dri`, NVIDIA device nodes, and
  driver stack as the host, by design, so 3D/Vulkan/OpenCL workloads work
  out of the box without per-container GPU allocation or arbitration.

### Kernel and chroot limitations

- **Root required**: the `chroot(2)` and `mount(2)` system calls require appropriate
  privileges; there is no rootless mode.
- **No real init**: `systemd`, socket-activated supervisors, and full
  init systems generally do not work. Individual long-running processes
  are fine.
- **Kernel features**: FUSE modules, real `iptables`, custom cgroup
  hierarchies, and similar kernel-module features may not work inside the
  guest.
- **Namespaces**: `--isolated` (or `CD_USE_NS=1`) provides
  mount/PID/UTS/IPC isolation, plus the cgroup namespace when the kernel
  supports it, using the `unshare(2)` and `setns(2)` system calls directly. There is no user-namespace mapping
  and no parity with Docker or Podman. (Networking is intentionally
  excluded from this isolation set — see
  [Design choices](#design-choices-not-limitations) above.)

### Chroot-Distro limitations

- **Root is required on Termux**: Chroot-Distro relies on real `chroot`
  and bind mounts, so it cannot run containers on a non-rooted Android
  device.
- **Registry authentication**: private pulls and pushes need
  `CD_DOCKER_AUTH=user:password`. Docker
  `config.json` credential helpers are not read.
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
- [pyLoad](https://github.com/pyload/pyload) — sliding-window speed tracking, token-bucket rate limiting, and connection resilience algorithms.
- [distrobox](https://github.com/89luca89/distrobox/) - shared-display option improvements 
- [Magisk-Modules-Alt-Repo/chroot-distro](https://github.com/Magisk-Modules-Alt-Repo/chroot-distro)
- [ravindu644/Ubuntu-Chroot](https://github.com/ravindu644/Ubuntu-Chroot)

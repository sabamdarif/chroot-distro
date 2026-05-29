# Chroot-Distro

Chroot-Distro is a utility for managing rootful Linux containers in
[Termux](https://termux.dev) and on regular Linux hosts. It uses native kernel
`chroot` and bind mounts (`mount --bind`) to provide a high-performance, near-native Linux
environment.

Containers are created by pulling Docker/OCI images directly from
Docker Hub or any compatible registry — or by extracting a local
tarball / OCI image archive. The container filesystem is assembled from
the image layers and stored locally, ready to be entered at any time.

Chroot-Distro can also **build** OCI images from a Dockerfile (no Docker
daemon required), storing the result in the local manifest cache or
exporting it as a standalone OCI tarball.

> [!IMPORTANT]
> **Root Requirement**: Unlike `proot-distro` (which is rootless via `proot`),
> `chroot-distro` relies on the host kernel's native namespaces and mount system.
> Therefore, it **requires root privileges** (which it automatically elevates using sudo, doas, pkexec, or su if needed).

---

## Table of contents

1. [Introduction](#introduction)
2. [Installation](#installation)
3. [First-run check](#first-run-check)
4. [Quick start](#quick-start)
5. [Commands reference](#commands-reference)
   * [`install`](#install--install-a-container)
   * [`build`](#build--build-an-image-from-a-dockerfile)
   * [`push`](#push--push-a-built-image-to-a-registry)
   * [`login`](#login--start-a-shell-inside-a-container)
   * [`run`](#run--run-the-image-defined-entrypoint)
   * [`list`](#list--list-installed-containers)
   * [`remove`](#remove--delete-a-container)
   * [`rename`](#rename--rename-a-container)
   * [`reset`](#reset--reinstall-a-container-from-scratch)
   * [`backup`](#backup--archive-a-container)
   * [`restore`](#restore--restore-a-container-from-a-backup)
   * [`copy`](#copy--copy-files-to-or-from-a-container)
   * [`sync`](#sync--synchronize-files-to-or-from-a-container)
   * [`clear-cache`](#clear-cache--delete-the-download-cache)
6. [How Chroot-Distro works](#how-chroot-distro-works)
7. [Storage layout](#storage-layout)
8. [Environment variables](#environment-variables)
9. [Shell completions](#shell-completions)
10. [Limitations](#limitations)
11. [Donate / Support](#donate--support)

---

## Introduction

Chroot-Distro lets you run a full Linux userland — Ubuntu, Debian,
Alpine, Arch, openSUSE, distroless server images, anything available as
a Docker/OCI image — on top of Termux on an Android device, or on top
of a regular Linux distribution, **with** native kernel performance, **without**
the overhead of `proot`'s `ptrace` interception, and **without** a Docker daemon.

Typical use cases:

- Running a desktop-class Linux distribution on a phone or tablet at native speeds.
- Running disk-intensive and compiling workloads (e.g. GCC/Clang, Rust, Go builds) without `proot` slowdowns.
- Spinning up server software (Nginx, Nextcloud, PostgreSQL, Docker-in-Chroot, etc.) on
  Android by reusing the same OCI images you'd run on a server.
- Building custom OCI images from a Dockerfile on-device, without a Docker daemon.
- Trying a distribution non-destructively: install, mess around,
  `chroot-distro remove` when done.

The CLI is exposed both as `chroot-distro` and the shorter alias `cd` (provided it does not conflict with your shell's built-in `cd`).

---

## Installation

Chroot-Distro requires Python 3.10 or newer. Since it uses native mount and chroot, it requires root privileges (which it automatically elevates using sudo, doas, pkexec, or su if needed).

### On Termux (Android)

1. Ensure your device is **rooted** (via Magisk, KernelSU, or APatch).
2. Install from PyPI:
   ```sh
   pip install chroot-distro
   ```
   Or from a local git clone:
   ```sh
   git clone https://github.com/sabamdarif/chroot-distro
   cd chroot-distro
   pip install .
   ```

### On a regular Linux host

```sh
# On Debian/Ubuntu:
apt install python3-pip

pip install chroot-distro          # from PyPI
# or
git clone https://github.com/sabamdarif/chroot-distro
cd chroot-distro
pip install .                     # from local checkout
```

---

## First-run check / Auto-Elevation

On startup, mutating commands verify if the program is being run by a user with root privileges (UID `0`). If not, the program automatically attempts to elevate itself using standard tools (`sudo`, `doas`, `pkexec`, or `su`). You can opt out of this auto-elevation by passing `--no-elevate` or setting the environment variable `CHROOT_DISTRO_NO_ELEVATE=1`.

---

## Quick start

```sh
# List available distributions
chroot-distro list

# Install Ubuntu 24.04 from Docker Hub
chroot-distro install ubuntu:24.04

# Start a shell inside the container
chroot-distro login ubuntu

# Same thing, but using the short command alias
cd sh ubuntu

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

# Permanently remove a container (unmounts all active sessions first)
chroot-distro remove ubuntu
```

---

## Commands reference

Every command supports `--help` (also `-h`, `--usage`), which prints
help text laid out for the current terminal width.

### `install` — Install a container

```
chroot-distro install [OPTIONS] (IMAGE or PATH or URL)
Aliases: add, i, in, ins
```

Pull a Docker/OCI image and create a container from it, extract a local archive file, or fetch a remote archive via HTTP/HTTPS.

**Options:**

| Option | Description |
|---|---|
| `-n`, `--name NAME` | Set a custom local name for the container. Defaults to the image name or archive filename. Must start with a letter/digit and contain only letters, digits, `_`, `.`, `-`. |
| `-a`, `--architecture ARCH` | Override the target CPU architecture. Accepts native names (`aarch64`, `arm`, `i686`, `riscv64`, `x86_64`) or Docker platforms (`linux/arm64`, `linux/amd64`, etc.). Defaults to host. |
| `-q`, `--quiet` | Suppress non-error output. |

#### From a OCI registry

`IMAGE` is a standard Docker image reference:

| Form | Example |
|---|---|
| Official image | `ubuntu:24.04` |
| Official, no tag (uses `latest`) | `alpine` |
| User image | `myuser/myimage:tag` |
| Custom registry | `ghcr.io/foo/bar:latest` |

Custom registries are detected by the first path component containing `.` or `:`. Public images on registries are pulled with an anonymous Bearer token.

**Private images** require credentials. Set the environment variable `CD_DOCKER_AUTH` to `username:password` (or `username:PAT`) before running `install` (e.g. `export CD_DOCKER_AUTH=myuser:ghp_xxx`). `PD_DOCKER_AUTH` is also accepted as a fallback.

Layers are cached in `/root/.cache/chroot-distro/oci_layers/` and reused on subsequent installs. If both the resolved manifest and all layers are cached, installation runs fully offline.

#### From a local archive or URL

Provide a path starting with `/`, `./`, `../`, or `~`, or an HTTP/HTTPS URL:
- **Plain rootfs tarball**: A tar archive whose top-level entries form a standard Linux filesystem (`bin/`, `etc/`, `usr/`, etc.). The tool automatically scores directory names to detect strip components. Supported compression: gzip, bzip2, xz, lzma, or uncompressed.
- **OCI image layout**: A tar archive containing an `oci-layout` file (produced by `docker save` or `skopeo`). Layers are applied in order with OCI whiteout markers, allowing `reset` and `run` to work like with registry-pulled images.

---

### `build` — Build an image from a Dockerfile

```
chroot-distro build [OPTIONS] [PATH]
```

Build an OCI/Docker-compatible image from a Dockerfile. `PATH` is the build context directory (default `.`); all `COPY`/`ADD` source paths are resolved relative to it.

By default, the built image is stored in the local manifest cache under the tag given by `--tag` (defaulting to `<basename(PATH)>:latest`). A subsequent `chroot-distro install <tag>` finds the manifest in the cache and installs offline.

**Options:**

| Option | Description |
|---|---|
| `-f`, `--file PATH` | Use a Dockerfile at PATH instead of `<PATH>/Dockerfile`. Pass `-` to read the Dockerfile from stdin. |
| `-t`, `--tag REF` | Image reference to assign. Repeatable. |
| `--build-arg K=V` | Set a build-time `ARG`. |
| `--architecture ARCH` | Target CPU architecture (default: host). |
| `--target STAGE` | Stop after the named stage of a multi-stage build. |
| `-o`, `--output FILE` | Write the built image as an OCI image-layout tarball to FILE. |
| `--install-as NAME` | After build, install the image as a container named NAME. |
| `--no-cache` | Disable build caching. |
| `-v`, `--verbose` | Echo each instruction and stream `RUN` output. |
| `-q`, `--quiet` | Suppress non-error output. |

**Supported Dockerfile instructions:**
`FROM`, `RUN`, `COPY` (with `--from`, `--chown`, `--chmod`), `ADD`, `CMD`, `ENTRYPOINT`, `ENV`, `ARG`, `LABEL`, `MAINTAINER`, `USER`, `WORKDIR`, `EXPOSE`, `VOLUME`, `STOPSIGNAL`, `HEALTHCHECK`, `SHELL`, `ONBUILD`.

BuildKit-only features (`RUN --mount`, `RUN --network`, `RUN --security`, `COPY --link`, `COPY --parents`) are rejected with an explicit error.

**`chroot` requirement:**
If the Dockerfile contains any `RUN` instructions, they must be executed against the in-progress rootfs under `chroot` and therefore require root privileges. Metadata-only builds run in pure Python and do not require root.

---

### `push` — Push a built image to a registry

```
chroot-distro push [OPTIONS] IMAGE
```

Upload a locally built image to a Docker/OCI registry. The image must have been produced by `chroot-distro build -t IMAGE` first. It streams layers from the local cache to the registry without requiring a Docker daemon.

Set `CD_DOCKER_AUTH=username:password` for authentication.

**Options:**

| Option | Description |
|---|---|
| `-a`, `--architecture ARCH` | Push the manifest built for the given architecture. Default: host. |
| `-q`, `--quiet` | Suppress non-error output. |

---

### `login` — Start a shell inside a container

```
chroot-distro login [OPTIONS] CONTAINER [-- COMMAND ...]
Aliases: sh
```

Spawn an interactive shell (or a custom command) inside an installed container. The `--` separator passes a command to run inside the container's login shell.

**Options:**

| Option | Description |
|---|---|
| `-u`, `--user USER` | Log in as USER (default: `root`). Accepts username (`name`), numeric `uid`, or `name:group` / `uid:gid`. |
| `--shared-home` | Bind the host user's home directory into the container (mounted at the guest user's home path). |
| `--shared-tmp` | Bind the host tmp directory (`$PREFIX/tmp` on Termux) to `/tmp` inside the container. |
| `--shared-x11` | Bind the host X11 socket directory to `/tmp/.X11-unix` inside the container. |
| `-b`, `--bind SRC[:DST]` | Bind-mount a custom host path (repeatable). `DST` must be an absolute path. |
| `--hostname STRING` | Customize hostname inside the container (default: `localhost`). |
| `-w`, `--work-dir PATH` | Set the initial working directory (default: user's home directory). |
| `-e`, `--env VAR=VALUE` | Set an environment variable in the guest (repeatable). |
| `--get-chroot-cmd` | Print the fully assembled `env` + `chroot` command line and exit. |

**Android/Termux-Specific Options:**

| Option | Description |
|---|---|
| `--isolated` | Skip non-essential host bindings (SD Card, Termux app paths, Android system paths). |
| `--minimal` | Bare-minimum environment: only binds `/dev`, `/proc`, `/sys`. Disables supplementary Android GID mapping. |

#### Host bindings (Termux, default mode)
Without `--isolated` or `--minimal`, the following host paths are bind-mounted inside the container when present and readable:

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

For normal-type containers, the Termux `$PREFIX` is also bound at its original path inside the guest so Termux utilities are reachable.

#### Guest environment
The host's environment is **not** carried into the guest. Chroot-Distro builds a clean environment dict. Precedence (later entries win):
1. **Baseline**: `PATH` (default: `/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin`), `MOZ_FAKE_NO_SANDBOX=1` and `PULSE_SERVER=127.0.0.1` (Android/Termux only).
2. **Image-defined `Env`**: Read from `manifest.json`.
3. **Android system vars**: (`ANDROID_*`, `BOOTCLASSPATH`, etc.), Android/Termux only, when not `--isolated` and not `--minimal`.
4. **User `--env`**: Your `--env VAR=VALUE` CLI entries.
5. **Session vars**: `HOME`, `USER`, `TERM` (defaulting to `xterm-256color`), `COLORTERM` (only when set on host).

On Android/Termux (unless isolated or minimal), `$PREFIX/bin` is appended to `PATH` so Termux host tools stay reachable. A profile script at `/etc/profile.d/termux-profile.sh` is automatically written to re-apply env variables after guest profile initialization.

---

### `run` — Run the image-defined entrypoint

```
chroot-distro run [OPTIONS] CONTAINER [-- ARG ...]
```

Run the `Entrypoint` and/or `Cmd` defined in the container's OCI image manifest (equivalent to `docker run`).

**Entrypoint and Cmd resolution:**

| Image defines | Args after `--` | Command executed inside chroot |
|---|---|---|
| `Entrypoint` + `Cmd` | _(none)_ | `Entrypoint + Cmd` |
| `Entrypoint` + `Cmd` | `ARGS` | `Entrypoint + ARGS` (`Cmd` replaced) |
| Only `Cmd` | _(none)_ | `Cmd` |
| Only `Cmd` | `ARGS` | `ARGS` (`Cmd` replaced) |
| Only `Entrypoint` | _(none)_ | `Entrypoint` |
| Only `Entrypoint` | `ARGS` | `Entrypoint + ARGS` |
| Neither | _(none)_ | Error |
| Neither | `ARGS` | `ARGS` |

Supports the same options as `login`.

---

### `list` — List installed containers

```
chroot-distro list [OPTIONS]
Aliases: li, ls
```

Show all installed containers. Does not require root.

| Option | Description |
|---|---|
| `-q`, `--quiet` | Print only container names, one per line. |

---

### `remove` — Delete a container

```
chroot-distro remove [OPTIONS] CONTAINER
Aliases: rm
```

Permanently delete the container and all of its data. **This cannot be undone and is not confirmed.**

Before deletion, Chroot-Distro verifies active mounts using `/proc/mounts` and performs a clean recursive unmount. It then fixes file permissions (chmod) on the fly to guarantee the rootfs can be cleared safely without leaving dead mounts or system locks.

| Option | Description |
|---|---|
| `-v`, `--verbose` | Log each deleted file. |
| `-q`, `--quiet` | Suppress non-error output. |

---

### `rename` — Rename a container

```
chroot-distro rename OLDNAME NEWNAME
```

Rename a container from `OLDNAME` to `NEWNAME`.

---

### `reset` — Reinstall a container from scratch

```
chroot-distro reset CONTAINER
```

Remove the container rootfs and reinstall it from the Docker image manifest cached at install time. **All data inside the container is lost.**

---

### `backup` — Archive a container

```
chroot-distro backup [OPTIONS] CONTAINER
Aliases: bak, bkp
```

Create a TAR archive of the container containing `<name>/manifest.json` and `<name>/rootfs/`.

**Options:**

| Option | Description |
|---|---|
| `-o`, `--output FILE` | Write to FILE instead of stdout. Refuses to overwrite. |
| `-c`, `--compress TYPE` | Force compression: `gzip`, `bzip2`, `xz`, or `none`. |
| `-v`, `--verbose` | Log each archived file. |
| `-q`, `--quiet` | Suppress non-error output. |

File ownership is zeroed out in the archive (`uid=gid=0`). Block/character devices, FIFOs, and sockets are silently skipped. Before archiving, permissions are adjusted to ensure the rootfs is readable.

`backup` is **TTY-safe** when piping to commands that might require user input (e.g. `gpg -c`).

---

### `restore` — Restore a container from a backup

```
chroot-distro restore [OPTIONS] [BACKUP_FILE]
```

Restore a container from a TAR archive. Reads from stdin when `BACKUP_FILE` is omitted. Compression is auto-detected.

**Options:**

| Option | Description |
|---|---|
| `-v`, `--verbose` | Log each extracted file. |
| `-q`, `--quiet` | Suppress non-error output. |

**Requirements:**
Files must be stored under a subdirectory named after the container (e.g. `<name>/rootfs/`). The existing rootfs is cleared on the first match. Hard links inside the archive are materialized as independent file copies via `shutil.copy2` to preserve filesystem isolation.

`restore` is **TTY-safe** when reading from an interactive pipeline (e.g. `gpg -d | chroot-distro restore`).

---

### `copy` — Copy files to or from a container

```
chroot-distro copy [OPTIONS] [CONTAINER:]SRC [CONTAINER:]DEST
Aliases: cp
```

Copy files between the host filesystem and a container rootfs, or between two containers. In-container paths are prefixed with the container name and a colon: `ubuntu:/etc/resolv.conf`.

| Option | Description |
|---|---|
| `-r`, `--recursive` | Copy directories recursively. |
| `-m`, `--move` | Move instead of copying (deletes source after success). |
| `-v`, `--verbose` | Log each copied file. |
| `-q`, `--quiet` | Suppress non-error output. |

---

### `sync` — Synchronize files to or from a container

```
chroot-distro sync [OPTIONS] [CONTAINER:]SRC [CONTAINER:]DEST
```

Synchronize SRC to DEST, copying only files that differ. Recursive by default.

**Comparison modes:**
- Default: File size and integer modification time.
- `--checksum` (`-c`): File size and CRC32 checksum.

Files are written atomically using a temp file (`.~cd_sync` -> `os.replace`) to prevent corruption on interruption.

| Option | Description |
|---|---|
| `-c`, `--checksum` | Compare by size + CRC32 instead of size + mtime. |
| `-d`, `--delete` | Remove extra files in destination. |
| `-v`, `--verbose` | Log each synced/deleted entry. |
| `-q`, `--quiet` | Suppress non-error output. |

---

### `clear-cache` — Delete the download cache

```
chroot-distro clear-cache
Aliases: clear, cl
```

Remove all entries from the cache directory (registry layers, manifests, build cache index).

---

## How Chroot-Distro works

Chroot-Distro is built around two primary blocks:

### 1. OCI registry client
The OCI pull/push logic is written in pure Python using `urllib`:
- Discovers challenge token endpoints and obtains OAuth bearer tokens.
- Downloads OCI layer blobs, verifying their SHA-256 integrity on the fly.
- Sequence-extracts layers onto a clean folder, respecting OCI whiteout formats.
- Performs post-install configurations: DNS setups (`resolv.conf`), minimal `hosts`, and populates Android UIDs/GIDs in guest databases (`/etc/passwd`, `/etc/group`) for proper network access mapping.

### 2. Native chroot & mount
Unlike `proot` which acts as a path translator via `ptrace` system call interceptions:
- **Real Bind Mounts**: Chroot-Distro performs kernel-level bind-mounting (`mount --bind`).
- **Session Tracking**: A file-based session tracker (`RUNTIME_DIR/data/<name>/sessions`) tracks active `login` and `run` instances.
- **Automated Mounting**: The first login session mounts necessary host directories (`/dev`, `/proc`, `/sys`, custom bindings). Subsequent sessions skip mounting.
- **Automated Unmounting**: The last session exiting (counter drops to 0) automatically unmounts all bind mounts.
- **Lazy Unmount Fallback**: If an unmount fails with "target is busy", Chroot-Distro issues a lazy unmount (`umount -l`) to clean up namespace resources safely, preventing data corruption or path leaks.
- **Under the Hood Command**:
  When logging in, Chroot-Distro issues an execution path matching:
  ```sh
  env -i USER=root HOME=/root PATH=... \
    chroot /root/.local/share/chroot-distro/containers/ubuntu/rootfs \
    /bin/sh -c 'cd /root && exec /bin/bash -l'
  ```

#### Cross-architecture support
Emulating guest CPU architectures (e.g. running `x86_64` on `aarch64` Android) uses **QEMU user-mode** via host-installed binary mappings. Architectures are auto-detected by parsing the ELF headers of common shells in the guest rootfs on login.

---

## Storage layout

Since Chroot-Distro must run as root, all runtime files are placed in root's home directory:

| Path | Contents |
|---|---|
| `/root/.local/share/chroot-distro/containers/<name>/rootfs/` | Container root filesystem |
| `/root/.local/share/chroot-distro/containers/<name>/manifest.json` | Image manifest metadata |
| `/root/.local/share/chroot-distro/locks/<name>.lock` | POSIX flock session lock |
| `/root/.local/share/chroot-distro/locks/build/` | POSIX flock image building locks |
| `/root/.cache/chroot-distro/oci_layers/` | Cached OCI layer blobs (shared cache) |
| `/root/.cache/chroot-distro/oci_manifests/` | Cached single-arch image manifests |
| `/root/.cache/chroot-distro/build_cache_index.json` | Build cache index |

---

## Environment variables

| Variable | Effect |
|---|---|
| `CD_DOCKER_AUTH` | Scoped Bearer authentication for registries. Format: `username:password` or `username:PAT`. `PD_DOCKER_AUTH` is also checked as fallback. |
| `CD_FORCE_NO_COLORS` | Set to any value to disable ANSI escape colors in logs/output. |
| `XDG_DATA_HOME` | Customizes base data directory (default: `/root/.local/share`). |
| `XDG_CACHE_HOME` | Customizes base cache directory (default: `/root/.cache`). |
| `COLUMNS` | Fallback terminal width for help rendering. |

---

## Shell completions

Completion scripts are installed for Bash, Zsh, and Fish:

### Zsh
Copy the script to your functions path:
```sh
mkdir -p ~/.zsh/completions
cp src/chroot_distro/completions/_chroot-distro ~/.zsh/completions/_chroot-distro
# Add 'fpath=(~/.zsh/completions $fpath)' to .zshrc before compinit
```

### Bash
```sh
mkdir -p ~/.local/share/bash-completion/completions
cp src/chroot_distro/completions/chroot-distro.bash \
   ~/.local/share/bash-completion/completions/chroot-distro
```

---

## Limitations

- **Root Privilege Requirement**: Unlike rootless solutions, all modifying operations require root access (automatically handled via self-elevation).
- **No Background Supervisors**: Standard systemd / init daemon managers cannot be initialized directly out of the box due to namespace limits.
- **No zstd-compressed layers**: Python's `tarfile` module lacks zstd decompression. Images packed with zstd layers will fail. Use standard gzip or xz OCI image tags.
- **Real Bind Mounts Persistence**: Real mounts are placed on the host file structure. If a login shell crashes or processes hang, paths can remain locked. While Chroot-Distro uses lazy unmount fallback (`umount -l`) to clean up, orphan processes should be monitored.
- **Dockerfile Build limits**: Builds run `RUN` steps via native chroot. BuildKit-exclusive features (such as `RUN --mount`) are not supported.

---

## Donate / Support

If you find this project helpful and would like to support its development, consider buying me a coffee! Your support helps maintain and improve this project.

**Cryptocurrency Addresses:**

*   **USDT (BEP20, ERC20):** `0x1d216cf986d95491a479ffe5415dff18dded7e71`
*   **USDT (TRC20):** `TCjRKPLG4BgNdHibt2yeAwgaBZVB4JoPaD`
*   **BTC:** `13Q7xf3qZ9xH81rS2gev8N4vD92L9wYiKH`
*   **DOGE:** `DJkMCnBAFG14TV3BqZKmbbjD8Pi1zKLLG6`
*   **ETH:** `0x1d216cf986d95491a479ffe5415dff18dded7e71`

---

## License

This project is licensed under the **GNU General Public License v3.0** (see [LICENSE](LICENSE)).

```
Copyright (C) 2025 sabamdarif

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
```

---

## Acknowledgments

Special thanks to:

- [proot-distro](https://github.com/termux/proot-distro) — The blueprint and inspiration for this project's architecture.
- [Magisk-Modules-Alt-Repo/chroot-distro](https://github.com/Magisk-Modules-Alt-Repo/chroot-distro)
- [ravindu644/Ubuntu-Chroot](https://github.com/ravindu644/Ubuntu-Chroot)
- [gdraheim/docker-systemctl-replacement](https://github.com/gdraheim/docker-systemctl-replacement)

---

<div align="center">

**⭐ If you enjoy this project, consider giving it a star!**

</div>

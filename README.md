<div align="center">

# Chroot Distro

#### Install Linux distributions on Android devices and regular Linux hosts using native chroot

![Release](https://img.shields.io/github/v/release/sabamdarif/chroot-distro?style=for-the-badge&color=blueviolet) ![GitHub License](https://img.shields.io/github/license/sabamdarif/chroot-distro?style=for-the-badge) ![Total Downloads](https://img.shields.io/github/downloads/sabamdarif/chroot-distro/total?style=for-the-badge&color=blueviolet)

</div>

---

**Chroot Distro** is a utility for managing Linux containers inside a native `chroot` environment on Termux (rooted Android devices) and on regular Linux hosts. It is designed as a direct clone of [PRoot-Distro](https://github.com/termux/proot-distro), but replaces rootless `proot` path interception with native kernel `chroot` and bind mounts (`mount --bind`).

This gives you **near-native execution speed and maximum performance** since there is no `ptrace` system call interception overhead, making it ideal for compilation, package management, and performance-heavy workloads.

> [!IMPORTANT]
> **Root Requirement**: Unlike `proot-distro` (which is rootless), `chroot-distro` interacts directly with the Linux kernel's namespace and mount system, and **requires root privileges** to run.

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Supported Distributions](#supported-distributions)
3. [Installation](#installation)
4. [Quick Start](#quick-start)
5. [Commands Reference](#commands-reference)
   * [`install`](#install--install-a-container)
   * [`login`](#login--enter-a-container-shell)
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
   * [`build`](#build--build-an-image-from-a-dockerfile)
   * [`push`](#push--push-a-built-image-to-a-registry)
6. [How Chroot-Distro Works](#how-chroot-distro-works)
   * [OCI Registry Client](#1-oci-registry-client)
   * [Mount & Session Management](#2-mount--session-management)
7. [Storage Layout](#storage-layout)
8. [Environment Variables](#environment-variables)
9. [Limitations](#limitations)
10. [Support the Project](#support-the-project)
11. [License](#license)
12. [Acknowledgments](#acknowledgments)

---

## Prerequisites

- **Rooted Android Device** (via Magisk, KernelSU, APatch, etc.) or a regular Linux host.
- **BusyBox** (Recommended: v1.36.1+). Essential for full command compatibility on Android.
  > [!TIP]
  > KernelSU and APatch users do not need to install BusyBox manually as they have built-in BusyBox support.

---

## Supported Distributions

| | | |
|:---:|:---:|:---:|
| ![Alpine Linux](https://img.shields.io/badge/Alpine_Linux-0D597F?style=for-the-badge&logo=alpine-linux&logoColor=white) | ![Arch Linux](https://img.shields.io/badge/Arch_Linux-1793D1?style=for-the-badge&logo=arch-linux&logoColor=white) | ![Debian](https://img.shields.io/badge/Debian-A81D33?style=for-the-badge&logo=debian&logoColor=white) |
| ![Fedora](https://img.shields.io/badge/Fedora-51A2DA?style=for-the-badge&logo=fedora&logoColor=white) | ![Kali Linux](https://img.shields.io/badge/Kali_Linux-557C94?style=for-the-badge&logo=kali-linux&logoColor=white) | ![Manjaro](https://img.shields.io/badge/Manjaro-35BF5C?style=for-the-badge&logo=manjaro&logoColor=white) |
| ![OpenSUSE](https://img.shields.io/badge/OpenSUSE-73BA25?style=for-the-badge&logo=opensuse&logoColor=white) | ![Rocky Linux](https://img.shields.io/badge/Rocky_Linux-10B981?style=for-the-badge&logo=rocky-linux&logoColor=white) | ![Trisquel](https://img.shields.io/badge/Trisquel-0D597F?style=for-the-badge&logo=gnu&logoColor=white) |
| ![Ubuntu](https://img.shields.io/badge/Ubuntu-E95420?style=for-the-badge&logo=ubuntu&logoColor=white) | ![Void Linux](https://img.shields.io/badge/Void_Linux-478061?style=for-the-badge&logo=void-linux&logoColor=white) | |

---

## Installation

`chroot-distro` requires Python 3.10 or newer.

### From PyPI (Recommended)
```sh
pip install chroot-distro
```

### From Local Checkout (Development)
```sh
git clone https://github.com/sabamdarif/chroot-distro
cd chroot-distro
pip install .          # Standard install
pip install -e .       # Editable install
```

---

## Quick Start

```bash
# List available distributions
sudo chroot-distro list

# Install Ubuntu 24.04 from Docker Hub
sudo chroot-distro install ubuntu:24.04

# Start an interactive root shell session inside the container
sudo chroot-distro login ubuntu

# Run a single command directly and exit
sudo chroot-distro login ubuntu -- apt update && apt install -y curl

# Reinstall the container (resets all in-container modifications)
sudo chroot-distro reset ubuntu

# Permanently delete the container and its rootfs
sudo chroot-distro remove ubuntu
```

---

## Commands Reference

The short command alias `cd` works everywhere `chroot-distro` does (provided it does not conflict with your shell's built-in `cd`).

Every command supports `-h` / `--help` / `--usage`, which prints responsive help formatted for your terminal width.

---

### `install` — Install a container

```
sudo chroot-distro install [OPTIONS] (IMAGE or PATH or URL)
Aliases: add, i, in, ins
```

Pull an OCI/Docker image from Docker Hub or a custom registry, extract a local archive file, or fetch a remote archive via HTTP/HTTPS to instantiate a container.

**Options:**

| Option | Description |
|---|---|
| `-n`, `--name NAME` | Set a custom local alias for the container. Defaults to the image name or archive filename. Must start with a letter/digit and contain only `a-z`, `0-9`, `_`, `.`, `-`. |
| `-a`, `--architecture ARCH` | Override target CPU architecture. Accepts native names (`aarch64`, `arm`, `i686`, `riscv64`, `x86_64`) or Docker platforms (`linux/arm64`, `linux/amd64`, etc.). Defaults to host architecture. |
| `-q`, `--quiet` | Suppress non-error output. |

#### From an OCI Registry
`IMAGE` uses standard Docker image references:
- Official image: `ubuntu:24.04` or `alpine` (uses `:latest` tag)
- User image: `myuser/myimage:tag`
- Custom registry: `ghcr.io/myorg/myimage:latest`

**Private registries** require credentials. Set `CD_DOCKER_AUTH=username:password` (or `username:PAT`) in your environment before running `install`.

Layers are cached in `/root/.cache/chroot-distro/oci_layers/` and reused on subsequent installations. If all layers and the manifest are cached, installation runs completely offline.

#### From a Local Archive or URL
Provide a path starting with `/`, `./`, `../`, or `~`, or a URL starting with `http://` or `https://`:
- **Plain rootfs tarball**: Auto-detected directory structure. Supports `gzip`, `bzip2`, `xz`, or `lzma` compression.
- **OCI image layout**: A tar archive (e.g. from `docker save`) containing an `oci-layout`. Extracted layers are applied in order with full whiteout semantics.

---

### `login` — Enter a container shell

```
sudo chroot-distro login [OPTIONS] CONTAINER [-- COMMAND ...]
Aliases: sh
```

Spawn an interactive login shell or execute a custom command inside the container. Command arguments after `--` are run inside the guest shell.

**Options:**

| Option | Description |
|---|---|
| `-u`, `--user USER` | Log in as USER (default: `root`). Accepts username (`name`), numeric UID (`uid`), or `name:group` / `uid:gid`. |
| `--shared-home` | Bind the host user's home directory to the container (mounted at the guest user's home, e.g. `/root` or `/home/user`). |
| `--shared-tmp` | Bind the host tmp directory (`$PREFIX/tmp` on Termux) to `/tmp` in the container. |
| `--shared-x11` | Bind the host X11 socket directory to `/tmp/.X11-unix` inside the container. |
| `-b`, `--bind SRC[:DST]` | Bind-mount a custom host path `SRC` to `DST` in the guest (repeatable). |
| `--hostname STRING` | Customize host name inside the container (default: `localhost`). |
| `-w`, `--work-dir PATH` | Initial guest working directory (default: user's home directory). |
| `-e`, `--env VAR=VALUE` | Inject environment variable into the guest (repeatable). |
| `--get-chroot-cmd` | Print the fully assembled `env` + `chroot` command line and exit without execution. |

**Android/Termux-Specific Options:**

| Option | Description |
|---|---|
| `--isolated` | Disables non-essential host bindings (SD Card, Termux home/app dirs, Android system paths). |
| `--minimal` | Minimal environment: only binds `/dev`, `/proc`, `/sys`. Disables supplementary Android GID mapping. |

---

### `run` — Run the image-defined entrypoint

```
sudo chroot-distro run [OPTIONS] CONTAINER [-- ARG ...]
```

Run the `Entrypoint` and/or `Cmd` defined in the container's OCI image manifest (acts like `docker run`). Arguments passed after `--` override the image's default `Cmd` parameters.

Supports all options of the [`login`](#login--enter-a-container-shell) command.

---

### `list` — List installed containers

```
chroot-distro list [OPTIONS]
Aliases: li, ls
```

Lists all installed chroot containers and displays their status. No root privileges are required to run this command.

| Option | Description |
|---|---|
| `-q`, `--quiet` | Print only container names, one per line. |

---

### `remove` — Delete a container

```
sudo chroot-distro remove [OPTIONS] CONTAINER
Aliases: rm
```

Permanently deletes the specified container and all of its data.

> [!WARNING]
> This command is irreversible and does not prompt for confirmation. It will safely unmount any active bind mounts before performing the recursive deletion.

| Option | Description |
|---|---|
| `-v`, `--verbose` | Log each deleted file. |
| `-q`, `--quiet` | Suppress non-error output. |

---

### `rename` — Rename a container

```
sudo chroot-distro rename OLDNAME NEWNAME
```

Renames an installed container from `OLDNAME` to `NEWNAME`.

---

### `reset` — Reinstall a container from scratch

```
sudo chroot-distro reset CONTAINER
```

Clears the container's rootfs and reinstalls it from the OCI image cached at install time.

> [!WARNING]
> All data stored inside the container will be lost. Only supported for containers originally installed from OCI images.

---

### `backup` — Archive a container

```
sudo chroot-distro backup [OPTIONS] CONTAINER
Aliases: bak, bkp
```

Creates a TAR archive of the container rootfs and manifest.

| Option | Description |
|---|---|
| `-o`, `--output FILE` | Write to `FILE` instead of stdout. Infers compression from extension (e.g. `.tar.xz`, `.tar.gz`). |
| `-c`, `--compress TYPE` | Force compression type: `gzip`, `bzip2`, `xz`, or `none`. |
| `-v`, `--verbose` | Log each archived file. |

---

### `restore` — Restore a container from a backup

```
sudo chroot-distro restore [OPTIONS] [BACKUP_FILE]
```

Restores a container from a backup TAR archive. If `BACKUP_FILE` is omitted, the archive is read from stdin. Auto-detects compression format.

---

### `copy` — Copy files to or from a container

```
sudo chroot-distro copy [OPTIONS] [CONTAINER:]SRC [CONTAINER:]DEST
Aliases: cp
```

Copy files/directories between the host filesystem and the container's rootfs, or between two containers. In-container paths are prefixed with the container name and a colon: `ubuntu:/etc/resolv.conf`.

| Option | Description |
|---|---|
| `-r`, `--recursive` | Copy directories recursively. |
| `-m`, `--move` | Move instead of copy (deletes source on success). |
| `-v`, `--verbose` | Log each copied file. |

---

### `sync` — Synchronize files to or from a container

```
sudo chroot-distro sync [OPTIONS] [CONTAINER:]SRC [CONTAINER:]DEST
```

Recursively synchronizes files and directories between the host and containers, copying only modified files. Writes atomically via temporary files.

| Option | Description |
|---|---|
| `-c`, `--checksum` | Compare files by size and CRC32 checksum instead of size and modification time. |
| `-d`, `--delete` | Delete files at the destination that do not exist in the source directory. |
| `-v`, `--verbose` | Log each synced/deleted file. |

---

### `clear-cache` — Delete the download cache

```
sudo chroot-distro clear-cache
Aliases: clear, cl
```

Deletes cached OCI layers, manifests, and build cache indices under root's cache directory. Re-downloads will be required for subsequent installs.

---

### `build` — Build an image from a Dockerfile

```
sudo chroot-distro build [OPTIONS] [PATH]
```

Build OCI-compatible image layers entirely on-device from a standard `Dockerfile` without requiring a running Docker daemon.

Supports standard instructions: `FROM`, `RUN`, `COPY`, `ADD`, `CMD`, `ENTRYPOINT`, `ENV`, `ARG`, `WORKDIR`, `USER`, etc. (BuildKit-specific instructions are rejected).

| Option | Description |
|---|---|
| `-f`, `--file PATH` | Use Dockerfile at `PATH` (use `-` for stdin). |
| `-t`, `--tag REF` | Image tag to assign (default: `<basename(PATH)>:latest`). |
| `--build-arg K=V` | Set build-time argument. |
| `--install-as NAME` | Directly install the built image as a container named `NAME` upon completion. |
| `-o`, `--output FILE` | Export the resulting image as an OCI layout archive. |
| `--no-cache` | Disable build caching. |

---

### `push` — Push a built image to a registry

```
sudo chroot-distro push [OPTIONS] IMAGE
```

Upload a locally built image directly from your manifest and layer cache to an OCI registry (Docker Hub, GHCR, etc.). Requires `CD_DOCKER_AUTH` to be exported for private repositories.

---

## How Chroot-Distro Works

`chroot-distro` performs Docker-like orchestration around two primary subsystems:

### 1. OCI Registry Client
- Implements OCI Distribution Spec v2 using Python's standard `urllib`.
- Validates downloaded OCI layer digests using `hashlib.sha256`.
- Extracts layers sequentially onto an empty rootfs directory with full support for OCI whiteouts (`.wh.<name>` and `.wh..wh..opq` markers).
- Automates container setup by configuring DNS (`resolv.conf`), hostname mappings (`hosts`), and registering standard Android GIDs in `/etc/group` (e.g. `aid_inet` for network access).

### 2. Mount & Session Management
Unlike `proot` which uses `ptrace` system call routing, `chroot-distro` mounts filesystems natively inside the container rootfs.
- **Session Counter**: A file-based session counter keeps track of concurrent `login` and `run` processes for each container.
- **Automated Mounting**: The first session entering the container performs a bind-mount (`mount --bind`) of `/dev`, `/proc`, `/sys`, and other host paths (or custom paths specified via `--bind`) into the rootfs. Concurrent sessions skip mounting.
- **Automated Unmounting**: When the last session exits (session counter drops to `0`), the utility automatically unmounts all bind mounts in reverse order.
- **Lazy Unmount Fallback**: If standard unmounting fails because a process inside the container is holding files open ("target is busy"), `chroot-distro` issues a lazy unmount (`umount -l`) to clean up the mount namespaces and prevent system lockups or file corruption.

---

## Storage Layout

Since the utility executes commands with root privileges (using `sudo`), the container files and caches are stored relative to root's home directory:

| Path Component | Location | Description |
|---|---|---|
| **Containers rootfs** | `/root/.local/share/chroot-distro/containers/<name>/rootfs/` | Guest system directories and files. |
| **OCI manifests** | `/root/.local/share/chroot-distro/containers/<name>/manifest.json` | Image configuration metadata. |
| **Active session locks** | `/root/.local/share/chroot-distro/locks/<name>.lock` | Manages concurrent access. |
| **Cached Layer Blobs** | `/root/.cache/chroot-distro/oci_layers/` | Cache directory for downloaded layers. |
| **Cached Manifests** | `/root/.cache/chroot-distro/oci_manifests/` | Cache directory for fetched image manifests. |

---

## Environment Variables

| Variable | Description |
|---|---|
| `CD_DOCKER_AUTH` | Credentials for OCI registries (in `username:password` or `username:PAT` format). `PD_DOCKER_AUTH` is also checked as a fallback. |
| `CD_FORCE_NO_COLORS` | Set to any value to disable ANSI terminal colors in the CLI output. |
| `XDG_DATA_HOME` | Customizes the base path for container data storage (defaults to `~/.local/share`). |
| `XDG_CACHE_HOME` | Customizes the base path for download/build cache (defaults to `~/.cache`). |
| `COLUMNS` | Fallback terminal width for help rendering. |

---

## Limitations

- **Performance vs Host**: Workloads run at native speed, but kernel-specific operations (e.g. loading kernel modules, mounting physical block devices, modifying iptables, or managing cgroups) are limited by the host kernel's security model and capabilities.
- **Persistent Bind Mounts**: Because we use native kernel bind mounts instead of PRoot virtual mounts, the paths are mounted directly onto the host. If a session crashes, or a program keeps files open, standard `umount` might fail. Although `chroot-distro` falls back to lazy `umount -l`, it is recommended to ensure your container processes are properly terminated before removing or modifying container files.
- **No nesting**: You cannot run `chroot-distro` inside another `chroot` or `proot` context.
- **No zstd-compressed layers**: Python's built-in `tarfile` library does not support `zstd` compression. OCI images built using `zstd` layers cannot be installed. Please choose an image tag compiled with standard `gzip` or `xz`.
- **Dockerfile Build Limitations**: `build` executes `RUN` steps via `chroot` (requires root privileges). BuildKit-exclusive features (such as `RUN --mount` or `COPY --link`) are not supported.

---

## Support the Project

If you find this project helpful and would like to support its development, consider donating to the creator. Your contributions help maintain and improve the project! ❤️

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

# Chroot-Distro

Chroot-Distro lets you run real Linux systems (Ubuntu, Debian, Alpine, Arch, and more) inside Termux on a rooted Android device, or on any regular Linux machine.

It works in three simple steps: it downloads an image from Docker Hub (or extracts a tarball you give it), unpacks it into a folder, and enters it using the Linux kernel's own `chroot` and `mount` features. Because it talks to the kernel directly, everything runs at native speed. It can also build images from a Dockerfile and push them to a registry.

Root access is required. On Termux, the root manager's `su` is used automatically. On regular Linux, a one-time `sudo chroot-distro setup` removes all future password prompts.

## Table of contents

1. [Introduction](#introduction)
2. [Commands reference](#commands-reference)
   * [`install`](#install)
   * [`login`](#login)
   * [`run`](#run)
   * [`list`](#list)
   * [`ps`](#ps)
   * [`copy`](#copy)
   * [`sync`](#sync)
   * [`rename`](#rename)
   * [`unmount`](#unmount)
   * [`kill`](#kill)
   * [`reset`](#reset)
   * [`backup`](#backup)
   * [`restore`](#restore)
   * [`diff`](#diff)
   * [`search`](#search)
   * [`setup`](#setup)
   * [`info`](#info)
   * [`help`](#help)
   * [`build`](#build)
   * [`push`](#push)
   * [`clear-cache`](#clear-cache)
   * [`remove`](#remove)
3. [Storage layout](#storage-layout)
4. [Environment variables](#environment-variables)
5. [Limitations](#limitations)
6. [Donate](#donate)

## Introduction

Chroot-Distro needs Python 3.10 or newer. It has no third-party dependencies.

### Install on Termux (Android)

1. Root your device (Magisk, KernelSU, APatch, or similar).
2. Install Termux from [F-Droid](https://f-droid.org/en/packages/com.termux/) or [GitHub Releases](https://github.com/termux/termux-app/releases).
3. Run:

```sh
pkg install python
pip install chroot-distro
```

No `sudo` or `tsu` package is needed.

### Install on regular Linux

```sh
sudo apt install python3-pip   # Debian/Ubuntu example
sudo pip install chroot-distro
```

Install with `sudo` (system-wide), not `pip install --user`. The passwordless daemon runs the code as root, so it refuses user-writable installs.

### Passwordless setup (Linux only)

Run this once so you never have to type a password again:

```sh
sudo chroot-distro setup
```

It creates a `chroot-distro` group, adds you to it, and starts a small root service (works with systemd, OpenRC, runit, dinit, and sysvinit). Log out and back in (or run `newgrp chroot-distro`) and you are done.

Add more users later with `sudo usermod -aG chroot-distro <username>`. Remove the service with `sudo chroot-distro setup --uninstall`.

> [!WARNING]
> Members of the `chroot-distro` group get root-equivalent access, exactly like the `docker` group. Only add people you trust.

### Quick start

```sh
chroot-distro install ubuntu:24.04     # download and install Ubuntu
chroot-distro login ubuntu             # open a shell inside it
chroot-distro list                     # see what is installed
chroot-distro remove ubuntu            # delete it
```

## Commands reference

Every command accepts `-h` / `--help`. Run `chroot-distro -V` to print the version.

### install

```
chroot-distro install [OPTIONS] IMAGE
Aliases: add, i, in, ins
```

Create a container. `IMAGE` can be:

| Source | Example |
|---|---|
| Docker Hub image | `ubuntu:24.04`, `alpine` |
| Other registry | `ghcr.io/foo/bar:latest` |
| Local file | `./rootfs.tar.gz`, `./image.oci.tar` |
| Web link | `https://example.com/rootfs.tar.xz` |

| Option | Description |
|---|---|
| `-n`, `--name NAME` | Give the container a custom name. Default is the image name. Needed to install the same image twice. |
| `-a`, `--architecture ARCH` | Install for a different CPU type (`aarch64`, `x86_64`, `linux/arm64`, ...). Default is your device's CPU. |
| `--allow-insecure` | Skip TLS certificate checks when downloading. Only for registries with self-signed certificates. |
| `-q`, `--quiet` | Only show errors. |

For private images, set `CD_DOCKER_AUTH` first:

```sh
export CD_DOCKER_AUTH=myuser:mypassword
chroot-distro install myuser/private-image:tag
```

Downloaded layers are cached, so installing the same image again works offline.

A container for another CPU needs QEMU's user-mode emulator on the host: install
`qemu-user-static` (Linux) or `qemu-user-aarch64` and friends (Termux). `login`
then registers it with the kernel's `binfmt_misc` the first time you enter the
container, and the registration stays until the host reboots. `chroot-distro
info` lists which architectures are covered. Nothing to install for your CPU's
own 32-bit half: `i686` on `x86_64` and `arm` on `aarch64` run directly.

### login

```
chroot-distro login [OPTIONS] CONTAINER [-- COMMAND ...]
Aliases: sh
```

Open a shell inside a container. Add `--` followed by a command to run that command instead of a shell:

```sh
chroot-distro login ubuntu
chroot-distro login ubuntu -- uname -a
```

| Option | Description |
|---|---|
| `-u`, `--user USER` | Log in as this user instead of root. Accepts a name, `name:group`, a numeric `uid`, or `uid:gid`. |
| `--isolated` | Maximum isolation: nothing from the host is shared, and the container gets its own mount, PID, UTS, and IPC namespaces. All `--shared-*` and `--bind` flags are ignored in this mode. Needs kernel namespace support. |
| `--minimal` | Bare minimum mode: only `/dev`, `/proc`, `/sys` (plus `/run`, `/dev/pts`, `/dev/shm` when present) and a stripped environment. Cannot be combined with `--isolated`. |
| `--shared-home` | Make your host home folder available inside the container. |
| `--shared-tmp` | Share the host `/tmp` with the container. By default the container gets its own empty `/tmp`. |
| `--shared-display` | Share the host screen (X11/Wayland), audio, and D-Bus, so GUI apps work. `--shared-x11` is an accepted alias. |
| `-b`, `--bind SRC[:DEST[:OPTIONS]]` | Make any host folder available inside the container. Optional mount options like `ro` or `ro,nosuid`. Can be given more than once. |
| `-w`, `--work-dir PATH` | Start in this folder instead of the user's home. |
| `-e`, `--env VAR=VALUE` | Set an environment variable inside the container. Can be given more than once. |
| `--get-chroot-cmd` | Print the exact chroot command that would run, without running it. |

If you want namespace isolation but still keep all the normal shared folders, set `CD_USE_NS=1` instead of using `--isolated`.

Several sessions of one container share its options. A session that joins a container someone is already logged into gets that container's `--bind` mounts, `--shared-*` folders and `-e`/`--env` values, and whatever it asks for on top is added to the running container, so a second `login` no longer needs an `unmount` to bring a folder in. Two exceptions: a `--bind` whose destination the running container already fills from another source is ignored (with a warning), and `--isolated` shares nothing, so asking for it while a normal session is running is still an error. `CD_USE_NS` cannot be turned on for a container that is already running either, and a mismatch there is a warning.

GPU acceleration (AMD, Intel, NVIDIA) is detected and set up automatically on regular Linux. No flag needed.

### run

```
chroot-distro run [OPTIONS] CONTAINER [-- ARG ...]
```

Run the start command (Entrypoint/Cmd) defined by the container's image, like `docker run`. Mainly for server images (nginx, nextcloud, databases). Only works for containers installed from Docker/OCI images.

`run` accepts all `login` options above, plus:

| Option | Description |
|---|---|
| `--entrypoint EXECUTABLE` | Run this program instead of the image's Entrypoint. Arguments after `--` become its arguments. |
| `-d`, `--detach` | Run in the background and return immediately. Output goes to a log file (path is printed). Stop it with `chroot-distro kill CONTAINER`. |

```sh
chroot-distro run nextcloud
chroot-distro run -d nextcloud
```

### list

```
chroot-distro list [OPTIONS]
Aliases: li, ls
```

Show installed containers with their size, image source, and whether they are in use.

| Option | Description |
|---|---|
| `-v`, `--verbose` | Also show image details: source URL, image type, default user, working directory, and exposed ports. |
| `-q`, `--quiet` | Print only container names, one per line. |

### ps

```
chroot-distro ps [OPTIONS]
```

Show active sessions: PID, container, type (`login` or `run`), user, uptime, and command. Detached sessions are marked with `*`.

| Option | Description |
|---|---|
| `-q`, `--quiet` | Print only PIDs, one per line. Useful in scripts. |

### copy

```
chroot-distro copy [OPTIONS] [CONTAINER:]SRC [CONTAINER:]DEST
Aliases: cp
```

Copy files between the host and a container, or between two containers. Container paths use the `name:path` form.

Ownership (numeric uid/gid), permissions and timestamps are preserved; `--chown` sets the owner by name on the destination side instead. Symlinks are copied as symlinks; hardlinks become independent copies; device nodes, FIFOs and sockets are skipped with a warning.

| Option | Description |
|---|---|
| `-r`, `--recursive` | Copy folders with everything inside them. |
| `-m`, `--move` | Move instead of copy (source is deleted after). |
| `--chown USER[:GROUP]` | Give every transferred entry this owner instead of the source's ids. Names are looked up on the destination side — the container's `/etc/passwd` and `/etc/group` for a `name:path` destination, the host's otherwise — so `--chown arif` means whatever `arif` is over there. Numbers are used as they stand, and `:GROUP` changes only the group. |
| `-v`, `--verbose` | Show each copied file. |
| `-q`, `--quiet` | Only show errors. |

```sh
chroot-distro copy ./file.txt ubuntu:/root/file.txt
chroot-distro copy -r ./project ubuntu:/home/user/ --chown user
```

### sync

```
chroot-distro sync [OPTIONS] [CONTAINER:]SRC [CONTAINER:]DEST
```

Like `copy`, but only transfers files that changed. Always recursive. Files are compared by size and modification time.

Ownership, permissions and timestamps are preserved for directories as well as files, and a change to any of them alone is applied without rewriting the file. With `--chown` the owner it names stands in for the source's, so a destination already carrying it is left alone.

| Option | Description |
|---|---|
| `-c`, `--checksum` | Compare by checksum instead of modification time. Slower but more precise. |
| `-d`, `--delete` | Also delete files at the destination that no longer exist at the source. |
| `--chown USER[:GROUP]` | Give every transferred entry this owner instead of the source's ids. Names are looked up on the destination side — the container's `/etc/passwd` and `/etc/group` for a `name:path` destination, the host's otherwise — so `--chown arif` means whatever `arif` is over there. Numbers are used as they stand, and `:GROUP` changes only the group. |
| `-v`, `--verbose` | Show each synced or deleted file. |
| `-q`, `--quiet` | Only show errors. |

```sh
chroot-distro sync ./dotfiles/ ubuntu:/home/user/ --chown user:user
```

### rename

```
chroot-distro rename OLDNAME NEWNAME
```

Rename a container.

| Option | Description |
|---|---|
| `-q`, `--quiet` | Only show errors. |

### unmount

```
chroot-distro unmount CONTAINER
Aliases: umount, um
```

Cleanly end all sessions of a container and remove its mounts. The gentle version of `kill`.

### kill

```
chroot-distro kill (CONTAINER | PID)
Aliases: k, stop
```

Force-stop a running container, like `docker kill`. Accepts a container name or a session PID from `chroot-distro ps`. All its processes are terminated and everything is unmounted. Container data is kept.

### reset

```
chroot-distro reset CONTAINER
```

Wipe a container and reinstall it fresh from its original image. All data inside is lost. Only works for containers installed from Docker/OCI images.

| Option | Description |
|---|---|
| `-q`, `--quiet` | Only show errors. |

### backup

```
chroot-distro backup [OPTIONS] CONTAINER
Aliases: bak, bkp
```

Save a container as a TAR archive. Without `--output`, the archive goes to stdout so you can pipe it.

| Option | Description |
|---|---|
| `-o`, `--output FILE` | Write to a file. Compression is picked from the extension (`.tar.gz`, `.tar.xz`, ...). Will not overwrite an existing file. |
| `-c`, `--compress TYPE` | Force compression: `gzip`, `bzip2`, `xz`, or `none`. |
| `-v`, `--verbose` | Show each archived file. |
| `-q`, `--quiet` | Only show errors. |

```sh
chroot-distro backup ubuntu -o ubuntu.tar.xz
chroot-distro backup ubuntu | gpg -c > ubuntu.tar.gpg
```

### restore

```
chroot-distro restore [OPTIONS] [BACKUP_FILE]
```

Bring back a container from a backup archive. Without a file, it reads from stdin. Compression is detected automatically.

| Option | Description |
|---|---|
| `-v`, `--verbose` | Show each extracted file. |
| `-q`, `--quiet` | Only show errors. |

```sh
chroot-distro restore ubuntu.tar.xz
gpg -d ubuntu.tar.gpg | chroot-distro restore
```

### diff

```
chroot-distro diff CONTAINER
```

Show what changed inside a container compared to its original image, like `docker diff`. `A` means added, `C` changed, `D` deleted. Needs the image layers to still be in the cache, so avoid `clear-cache` if you want `diff` to keep working.

### search

```
chroot-distro search [OPTIONS] TERM
Aliases: find, se
```

Search Docker Hub. Shows image name, stars, official status, and a short description.

| Option | Description |
|---|---|
| `-l`, `--limit N` | Show up to N results (default 25, max 100). |

### setup

```
chroot-distro setup [OPTIONS]
```

One-time passwordless setup on regular Linux. See [Passwordless setup](#passwordless-setup-linux-only). Not needed on Termux.

| Option | Description |
|---|---|
| `--user USERNAME` | Add this user to the `chroot-distro` group instead of the user who ran the command. |
| `--uninstall` | Stop and remove the daemon service. The group is kept. |
| `-q`, `--quiet` | Only show errors. |

### info

```
chroot-distro info
Aliases: version-info, nf
```

Print a diagnostics report: versions, device details, host capabilities, installed containers, and basic health checks. Attach it when filing a bug report.

### help

```
chroot-distro help [COMMAND]
Aliases: h, he, hel
```

Show detailed help for a command, or general usage when no command is given.

### build

```
chroot-distro build [OPTIONS] [PATH]
```

Build an image from a Dockerfile, like `docker build` but without Docker. `PATH` is the folder with your Dockerfile (default: current folder). The result is stored locally, so `chroot-distro install <tag>` installs it offline.

| Option | Description |
|---|---|
| `-f`, `--file PATH` | Use a Dockerfile at a different location. Pass `-` to read it from stdin. |
| `-t`, `--tag REF` | Name the image (like `myapp:1.0`). Can be given more than once. |
| `--build-arg K=V` | Set a build-time `ARG`. Can be given more than once. |
| `-a`, `--architecture ARCH` | Build for a different CPU type. Default is your device's CPU. |
| `--target STAGE` | Stop at a named stage of a multi-stage build. |
| `-o`, `--output FILE` | Also save the image as an OCI tarball (`.oci.tar`, `.oci.tar.gz`, `.oci.tar.xz`). Can be given more than once. |
| `--install-as NAME` | Install the built image as a container right after the build. |
| `--secret id=NAME[,src=PATH]` | Give a secret to `RUN --mount=type=secret` steps. Without `src=`, the value comes from the environment variable `NAME`. Secrets never end up in the image. |
| `--ssh ID[=SOCK]` | Give an SSH agent socket to `RUN --mount=type=ssh` steps. Default socket is `$SSH_AUTH_SOCK`. |
| `--no-cache` | Rebuild every step from scratch instead of reusing cached steps. |
| `--progress MODE` | Output style: `auto`, `plain`, `tty`, or `rawjson`. |
| `-v`, `--verbose` | Show each instruction and full `RUN` output. |
| `-q`, `--quiet` | Only show errors. |

`RUN` steps need root because they execute inside the half-built image. `RUN --mount` with `type=bind`, `cache`, `tmpfs`, `secret`, and `ssh` is supported. `RUN --network=none`, `RUN --security`, `COPY --link`, and `COPY --parents` are not, and fail with a clear error.

A `.dockerignore` file in the context excludes files from `COPY` and `ADD`, with Docker's own rules: `*` and `?` stop at a `/`, `**` spans any number of folders, `!` puts a file back, the last matching line decides, and naming a folder covers everything inside it.

`FROM --platform` picks one stage's platform, so `FROM --platform=$BUILDPLATFORM` builds that stage for your own CPU while the image stays the one `--architecture` asked for. An emulator is then only needed for a stage that has a `RUN` *and* targets a foreign CPU. `TARGETPLATFORM`, `TARGETOS`, `TARGETARCH`, `TARGETVARIANT` and the matching `BUILD*` names are set automatically, and like Docker they live outside the stages: a bare `ARG TARGETARCH` inside a stage is what lets a `RUN` there read one.

```sh
chroot-distro build -t myapp:1.0 --install-as myapp .
```

### push

```
chroot-distro push [OPTIONS] IMAGE
```

Upload an image you built with `build -t` to Docker Hub or another registry. Layers already on the registry are skipped.

| Option | Description |
|---|---|
| `-a`, `--architecture ARCH` | Push the image built for that CPU type. Default is your device's CPU. |
| `--allow-insecure` | Skip TLS certificate checks. Only for registries with self-signed certificates. |
| `-q`, `--quiet` | Only show errors. |

Set `CD_DOCKER_AUTH=username:password` before pushing to a private repository.

### clear-cache

```
chroot-distro clear-cache [OPTIONS]
Aliases: clear, cl
```

Delete all cached downloads (image layers, manifests, build cache) and show how much space was freed. After this, installing an image needs the network again, and `diff` stops working for existing containers.

| Option | Description |
|---|---|
| `--build-cache` | Drop the build cache index and the layer blobs only it was pinning. |
| `-v`, `--verbose` | Show each deleted file. |
| `-q`, `--quiet` | Only show errors. |

Every `RUN` a build executes is recorded against the layer it produced, so a later build with the same parent, instruction and inputs reuses it. Nothing ever evicts those entries, and every edit to a Dockerfile strands the ones before it, so the build cache is the part that only grows.

```sh
# Reclaim the build cache, keep the downloaded images
chroot-distro clear-cache --build-cache
```

This removes the index and then deletes the layers nothing else points at. The layers of images you still have are kept, so what goes is the build's own bookkeeping, the intermediates no image held on to, and any leftover blob from a killed download. The next `build` re-runs every step. It refuses to run while another `chroot-distro` command holds a lock, since a build in progress has recorded steps whose layers this would unpin. To skip cache lookups for a single build without deleting anything, use `build --no-cache` instead — note that it still records what it builds.

### remove

```
chroot-distro remove [OPTIONS] CONTAINER
Aliases: rm
```

Delete a container and all its data. There is no confirmation and no undo. Active sessions are unmounted first.

| Option | Description |
|---|---|
| `-v`, `--verbose` | Show each deleted file. |
| `-q`, `--quiet` | Only show errors. |

## Storage layout

Everything lives in one data folder:

| Platform | Data folder | Cache folder |
|---|---|---|
| Termux | `$PREFIX/var/lib/chroot-distro/` | `$PREFIX/var/lib/chroot-distro/cache/` |
| Regular Linux | `~/.local/share/chroot-distro/` | `~/.cache/chroot-distro/` |

On regular Linux, commands run as root, so the folders are usually under `/root/` unless you set `XDG_DATA_HOME` / `XDG_CACHE_HOME`.

Inside the data folder:

| Path | Contents |
|---|---|
| `containers/<name>/rootfs/` | The container's filesystem |
| `containers/<name>/manifest.json` | Image info used by `reset` and `run` |
| `sessions/` | Active session records used by `ps` |
| `locks/` | Lock files preventing conflicting commands |
| `cache/oci_layers/` | Downloaded image layers |
| `cache/oci_manifests/` | Downloaded image manifests |

## Environment variables

All of these are optional.

| Variable | Effect |
|---|---|
| `CD_DOCKER_AUTH` | Registry login as `username:password` (or `username:token`). The colon is required. Used by `install`, `build`, and `push`. |
| `CD_DOWNLOAD_WORKERS` | How many layers to download at once (default 4, max 10). |
| `CD_DOWNLOAD_RATE_LIMIT` | Download speed limit, like `5M` for 5 MiB/s. Default is unlimited. |
| `CD_DOWNLOAD_MAX_RETRIES` | Retries per failed download (default 3, max 20). |
| `CD_USER` | Default user for `login`/`run` when `--user` is not given. |
| `CD_WORKDIR` | Default working directory for `login`/`run` when `--work-dir` is not given. |
| `CD_ENV` | Extra guest environment variables, one `VAR=VALUE` per line. `--env` wins on conflict. |
| `CD_ENTRYPOINT` | Default entrypoint for `run` when `--entrypoint` is not given. |
| `CD_USE_NS` | Set to `1` to give every `login`/`run` its own namespaces while keeping all normal shared folders. |
| `CD_USE_ISOLATION` | Set to `1` to force maximum isolation, same as `--isolated`. Also the only way to isolate `build` `RUN` steps. |
| `CD_FORCE_NO_COLORS` | Disable colored output. |
| `TERMUX__PREFIX` | Override the Termux prefix path. |
| `TERMUX__HOME` | Override the Termux home path used by `--shared-home`. |
| `TERMUX_APP__PACKAGE_NAME` | Termux app package name (default `com.termux`). |
| `XDG_DATA_HOME`, `XDG_CACHE_HOME` | Move the data and cache folders on regular Linux. |

## Limitations

- **Root is required.** The kernel's `chroot` and `mount` features need it. There is no rootless mode, and no support for non-rooted Android.
- **Network is shared with the host by design.** Containers use your Wi-Fi, mobile data, and VPN directly. There is no network isolation, even with `--isolated`.
- **GPU is shared by design.** GPU access is automatic whenever supported hardware is detected.
- **No full init systems.** `systemd` and similar will not work inside containers. Individual long-running programs are fine.
- **Isolation is partial.** `--isolated` covers mount, PID, UTS, and IPC namespaces. It is not a full container runtime like Docker or Podman.
- **Builds are not full BuildKit.** `RUN` steps execute under chroot. A few BuildKit features are rejected with an error, and multi-platform images are not produced.
- **`push` is single-architecture.** Build and push once per CPU type.
- **Foreign architectures need the kernel's help.** Emulation goes through `binfmt_misc`, so a kernel built without `CONFIG_BINFMT_MISC` cannot run an image for another CPU. `chroot-distro info` reports it.
- **Backups capture files only.** Running programs are not saved by `backup`/`restore`.
- **Registry login is env-var only.** Set `CD_DOCKER_AUTH`. Docker's `config.json` credential helpers are not read.

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

- [proot-distro](https://github.com/termux/proot-distro) - cli design, inspiration, and a lot more. Commands and syntax are intentionally
  kept close to proot-distro's so the experience feels familiar, and substantial
  parts of the implementation are ported directly from it and adapted to fit
  this project.
- [pyLoad](https://github.com/pyload/pyload) — downloader improvements.
- [distrobox](https://github.com/89luca89/distrobox/) - shared-display option improvements.
- [Magisk-Modules-Alt-Repo/chroot-distro](https://github.com/Magisk-Modules-Alt-Repo/chroot-distro) - some info about chroot on android.
- [ravindu644/Ubuntu-Chroot](https://github.com/ravindu644/Ubuntu-Chroot) - some info about chroot on android.

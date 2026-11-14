# Chroot-Distro

[![Repo Size](https://img.shields.io/github/repo-size/sabamdarif/chroot-distro)](https://github.com/sabamdarif/chroot-distro)
[![GitHub License](https://img.shields.io/github/license/sabamdarif/chroot-distro)](https://github.com/sabamdarif/chroot-distro/blob/main/LICENSE)
[![PyPI Downloads](https://static.pepy.tech/personalized-badge/chroot-distro?period=monthly&units=INTERNATIONAL_SYSTEM&left_color=BLACK&right_color=GREEN&left_text=downloads%2Fmonth)](https://pepy.tech/projects/chroot-distro)

Chroot-Distro lets you run real Linux systems (Ubuntu, Debian, Alpine, Arch, and more) on any Linux host: a regular Linux machine, or `Termux` on a rooted Android device.

It works in three simple steps: it downloads an image from Docker Hub (or extracts a tarball you give it), unpacks it into a folder, and enters it using the Linux kernel's own `chroot` and `mount` features. Because it talks to the kernel directly, everything runs at native speed. It can also build images from a Dockerfile and push them to a registry.

**Root access is required.**

## Table of contents

1. [Introduction](#introduction)
2. [Commands reference](#commands-reference)
    - [`install`](#install)
    - [`login`](#login)
    - [`run`](#run)
    - [`list`](#list)
    - [`ps`](#ps)
    - [`copy`](#copy)
    - [`sync`](#sync)
    - [`rename`](#rename)
    - [`unmount`](#unmount)
    - [`kill`](#kill)
    - [`reset`](#reset)
    - [`backup`](#backup)
    - [`restore`](#restore)
    - [`diff`](#diff)
    - [`search`](#search)
    - [`info`](#info)
    - [`help`](#help)
    - [`build`](#build)
    - [`push`](#push)
    - [`clear-cache`](#clear-cache)
    - [`remove`](#remove)
3. [JSON output](#json-output)
4. [Storage layout](#storage-layout)
5. [Environment variables](#environment-variables)
6. [Limitations](#limitations)
7. [Donate](#donate)

## Introduction

Chroot-Distro needs Python 3.10 or newer. It has no third-party dependencies, apart
from `backports-zstd` for below Python 3.14, which is what gives the zstd support.

### Install on regular Linux

```sh
sudo apt install python3-pip   # Debian/Ubuntu example
sudo pip install chroot-distro --break-system-packages --root-user-action=ignore
```

Commands that need root use the first available tool in this order: `sudo`,
`doas`, `pkexec`, `su`. Help, version and `search` run without elevation.

### Install on Termux (Android)

1. Root your device (Magisk, KernelSU, APatch, or similar).
2. Install Termux from [F-Droid](https://f-droid.org/en/packages/com.termux/) or [GitHub Releases](https://github.com/termux/termux-app/releases).
3. Run:

```sh
pkg install python
pip install chroot-distro
```

No `sudo` or `tsu` package is needed: the root manager's `su` is used directly.

### Quick start

```sh
chroot-distro install ubuntu:24.04     # download and install Ubuntu
chroot-distro login ubuntu             # open a shell inside it
chroot-distro list                     # see what is installed
chroot-distro remove ubuntu            # delete it
```

## Commands reference

An optional standalone `--` can appear before the command name.
Every command accepts `-h` and `--help` before its own first standalone `--`.
These flags show help before validating command arguments.
Run `chroot-distro -V` or `chroot-distro --version` to print the version.

### install

```
chroot-distro install [OPTIONS] IMAGE
Aliases: add, i, in, ins
```

Create a container. `IMAGE` can be:

| Source           | Example                              |
| ---------------- | ------------------------------------ |
| Docker Hub image | `ubuntu:24.04`, `alpine`             |
| Other registry   | `ghcr.io/foo/bar:latest`             |
| Local file       | `./rootfs.tar.gz`, `./image.oci.tar` |
| Web link         | `https://example.com/rootfs.tar.xz`  |

References follow Docker's own grammar, so `localhost:5000/foo` names a registry on
this machine. Pinning an image by digest (`debian@sha256:...`) is not supported yet.

OCI archives must provide matching sizes and SHA-256 digests for the manifests,
configs and layers used during install. A verified cached layer can supply a
layer missing from the archive.

The default container name for an archive comes from its filename, with the
recognized extension removed. For a URL, the filename comes from its path.
Use `--name` if the URL path has no filename.

| Option                      | Description                                                                                                                                                              |
| --------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `-n`, `--name NAME`         | Give the container a custom name. Needed to install the same image twice. `--override-alias` is an accepted alias. |
| `-a`, `--architecture ARCH` | Install for a different CPU type (`aarch64`, `x86_64`, `linux/arm64`, ...). Default is your host's CPU.                                                                  |
| `--allow-insecure`          | Permit insecure transport when downloading: an untrusted certificate, or a redirect from HTTPS to plain HTTP. Only for sources you trust; Docker Hub is always verified. |
| `-q`, `--quiet`             | Only show errors.                                                                                                                                                        |

For private images, set `CD_DOCKER_AUTH` first:

```sh
export CD_DOCKER_AUTH=myuser:mypassword
chroot-distro install myuser/private-image:tag
```

The password half can also be a personal access token (`myuser:ghp_xxxxxxxx`).
Credentials are checked before the download starts and go only to that registry
and its login service.

**Pull rate limits.** Anonymous Docker Hub pulls are limited per IP address, so
shared networks often hit them. A "too many requests" error (HTTP 429) names the
limit and when to retry; logging in with `CD_DOCKER_AUTH` gets a limit of its
own. Proxies like `docker.n8n.io` share Docker Hub's anonymous limit, so install
the image straight from Docker Hub instead:

```sh
# Instead of docker.n8n.io/n8nio/n8n:latest
chroot-distro install n8nio/n8n:latest
```

A container for another CPU needs QEMU's user-mode emulator on the host:
install `qemu-user-static` (Linux) or `qemu-user-ARCH` (Termux); `login`
registers it with the kernel on first use. `chroot-distro info` lists which
architectures are covered.

### login

```
chroot-distro login [OPTIONS] CONTAINER [-- COMMAND ...]
Aliases: sh
```

Open a shell inside a container. Put a command after `--` to run it instead.
Bare command words before `--` are passed first. Put guest options after `--`.

When stdin is a terminal, `login` forwards guest terminal output to stdout.
If forwarding fails, `login` closes the guest PTY and exits with status 1
after the guest wait and session cleanup. The relay keeps handling SIGTERM,
SIGINT and SIGHUP while waiting for the guest after closing the PTY.

```sh
chroot-distro login ubuntu
chroot-distro login ubuntu -- uname -a
```

| Option                              | Description                                                                                                                                                                                                                                     |
| ----------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `-u`, `--user USER`                 | Log in as this user instead of root. Accepts a name, `name:group`, a numeric `uid`, or `uid:gid`.                                                                                                                                               |
| `--isolated`                        | Maximum isolation: own mount, PID, UTS and IPC namespaces, and no host path shared except `/sys`. `--shared-*` and `--bind` are ignored. `--isolate` is an alias.                                                                               |
| `--minimal`                         | Bare minimum mode: fresh `/dev`, `/proc`, `/sys` and `/dev/shm` and a stripped environment, nothing else. Cannot be combined with `--isolated`.                                                                                                 |
| `--no-new-privs`                    | Prevent guest programs from gaining privileges through setuid binaries or file capabilities.                                                                                                                                                    |
| `--shared-home`                     | Make your host home folder available inside the container.                                                                                                                                                                                      |
| `--shared-tmp`                      | Share the host `/tmp` with the container. By default the container gets its own empty `/tmp`.                                                                                                                                                   |
| `--shared-display`                  | Share the host screen (X11/Wayland), audio, and D-Bus, so GUI apps work. `--shared-x11` is an accepted alias.                                                                                                                                   |
| `-b`, `--bind SRC[:DEST[:OPTIONS]]` | Make any host folder available inside the container, with optional mount options like `ro,nosuid`. A single device node under `/dev` is also allowed, e.g. `--bind /dev/ttyUSB0` (Docker's `--device` equivalent). Can be given more than once. |
| `-w`, `--work-dir PATH`             | Start in this folder instead of the user's home.                                                                                                                                                                                                |
| `-e`, `--env VAR=VALUE`             | Set an environment variable inside the container. Can be given more than once.                                                                                                                                                                  |
| `--get-chroot-cmd`                  | Print the exact chroot command that would run, without running it.                                                                                                                                                                              |

Set `CD_USE_NS=1` for namespace isolation while keeping the normal shared folders, instead of `--isolated`.

Every mode mounts fresh pseudo-filesystems instead of binding the host's: a minimal `/dev`, fresh `/dev/pts`, `/dev/shm` and `/proc`, and a read-only `/sys`, following Docker's defaults (`/proc/kcore` and `/proc/keys` masked, `/proc/sys` read-only). When the kernel or SELinux refuses one, the host tree is bound with a warning.

Single-instance devpts kernels share the host's `/dev/pts` with the guest. When chroot-distro supplies the guest's `/dev`, it creates a legacy `/dev/ptmx` device so guest programs can allocate pseudoterminals.

On Termux, Android mounts `/data` with `nosuid`, so a default login binds the container's rootfs onto itself with `suid` and `exec` enabled, letting setuid binaries like `sudo` work without touching Android's mount flags. `--shared-tmp` binds `$PREFIX/tmp` as it is; make it world-writable yourself if a non-root guest user must write there.

A second `login` to a busy container joins the running session and adds whatever extra `--bind`/`--shared-*`/`--env` it asks for, so no `unmount` is needed to bring a folder in. Conflicting `--bind` destinations are ignored with a warning; `--isolated` and `CD_USE_NS` cannot be turned on for a container that is already running.

GPU acceleration needs no flag on regular Linux: AMD/Intel render nodes (`/dev/dri/*`) and a host NVIDIA driver's devices, libraries and tools are bound in automatically. On Termux `login` binds no GPU nodes.

### run

```
chroot-distro run [OPTIONS] CONTAINER [-- ARG ...]
```

Run the start command (Entrypoint/Cmd) defined by the container's image, like `docker run`. Mainly for server images (nginx, nextcloud, databases). Only works for containers installed from Docker/OCI images.

`run` is the only way into an image that ships no shell (`scratch`, distroless): `login` refuses those and points here.

Foreground `run` uses the same [terminal output handling as `login`](#login).

`run` accepts all `login` options above, plus:

| Option                    | Description                                                                                                                             |
| ------------------------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| `--entrypoint EXECUTABLE` | Run this program instead of the image's Entrypoint. Arguments after `--` become its arguments.                                          |
| `-d`, `--detach`          | Run in the background and return immediately. Output goes to a log file (path is printed). Stop it with `chroot-distro kill CONTAINER`. |

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

| Option            | Description                                                                                                                                   |
| ----------------- | --------------------------------------------------------------------------------------------------------------------------------------------- |
| `-v`, `--verbose` | Also show image details: source URL, image type, default user, working directory, and exposed ports.                                          |
| `-q`, `--quiet`   | Print only container names, one per line.                                                                                                     |
| `--json`          | Print one JSON document on stdout instead of the table, with every field `-v` shows plus `size_bytes`. Mutually exclusive with `-v` and `-q`. |

### ps

```
chroot-distro ps [OPTIONS]
```

Show active sessions: PID, container, type (`login` or `run`), user, uptime, and command. Detached sessions are marked with `*`.

| Option          | Description                                                                                                                                         |
| --------------- | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| `-q`, `--quiet` | Print only PIDs, one per line. Useful in scripts.                                                                                                   |
| `--json`        | Print one JSON document on stdout: every session record with `uptime_seconds`, plus orphaned processes per container. Mutually exclusive with `-q`. |

### copy

```
chroot-distro copy [OPTIONS] [CONTAINER:]SRC [CONTAINER:]DEST
Aliases: cp
```

Copy files between the host and a container, or between two containers. Container paths use the `name:path` form.

Ownership (numeric uid/gid), permissions and timestamps are preserved; `--chown` sets the owner by name on the destination side instead. Symlinks are copied as symlinks; hardlinks become independent copies; device nodes, FIFOs and sockets are skipped with a warning.

| Option                 | Description                                                                                                                                                                                                                          |
| ---------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `-r`, `--recursive`    | Copy folders with everything inside them.                                                                                                                                                                                            |
| `-m`, `--move`         | Move instead of copy (source is deleted after).                                                                                                                                                                                      |
| `--chown USER[:GROUP]` | Give every transferred entry this owner instead of the source's ids. Names are looked up on the destination side, so `--chown arif` means whatever `arif` is there. Numbers are used as they stand; `:GROUP` changes only the group. |
| `-v`, `--verbose`      | Show each copied file.                                                                                                                                                                                                               |
| `-q`, `--quiet`        | Only show errors.                                                                                                                                                                                                                    |

```sh
chroot-distro copy ./file.txt ubuntu:/root/file.txt
chroot-distro copy -r ./project ubuntu:/home/user/ --chown user
```

### sync

```
chroot-distro sync [OPTIONS] [CONTAINER:]SRC [CONTAINER:]DEST
```

Like `copy`, but only transfers files that changed. Always recursive. Files are compared by size and modification time. Metadata-only changes (permissions, timestamps) are applied without rewriting the file.

| Option                 | Description                                                                                                                                                                                                                          |
| ---------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `-c`, `--checksum`     | Compare by checksum instead of modification time. Slower but more precise.                                                                                                                                                           |
| `-d`, `--delete`       | Also delete files at the destination that no longer exist at the source.                                                                                                                                                             |
| `--chown USER[:GROUP]` | Give every transferred entry this owner instead of the source's ids. Names are looked up on the destination side, so `--chown arif` means whatever `arif` is there. Numbers are used as they stand; `:GROUP` changes only the group. |
| `-v`, `--verbose`      | Show each synced or deleted file.                                                                                                                                                                                                    |
| `-q`, `--quiet`        | Only show errors.                                                                                                                                                                                                                    |

```sh
chroot-distro sync ./dotfiles/ ubuntu:/home/user/ --chown user:user
```

### rename

```
chroot-distro rename OLDNAME NEWNAME
```

Rename a container.

| Option          | Description       |
| --------------- | ----------------- |
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

| Option          | Description       |
| --------------- | ----------------- |
| `-q`, `--quiet` | Only show errors. |

### backup

```
chroot-distro backup [OPTIONS] CONTAINER
Aliases: bak, bkp
```

Save a container as a TAR archive. Without `--output`, the archive goes to stdout so you can pipe it.
If stdout is unavailable or its pipe closes during the backup, the command exits with status 1.

| Option                  | Description                                                                                                                 |
| ----------------------- | --------------------------------------------------------------------------------------------------------------------------- |
| `-o`, `--output FILE`   | Write to a file. Compression is picked from the extension (`.tar.gz`, `.tar.xz`, ...). Will not overwrite an existing file. |
| `-c`, `--compress TYPE` | Force compression: `gzip`, `bzip2`, `xz`, or `none`.                                                                        |
| `-v`, `--verbose`       | Show each archived file.                                                                                                    |
| `-q`, `--quiet`         | Only show errors.                                                                                                           |

```sh
chroot-distro backup ubuntu -o ubuntu.tar.xz
chroot-distro backup ubuntu | gpg -c > ubuntu.tar.gpg
```

> A backup archive also works as an [`install`](#install) source, which lets you bring it in under a new name with `--name`. `restore` reuses the name baked into the archive.

### restore

```
chroot-distro restore [OPTIONS] [BACKUP_FILE]
```

Bring back a container from a backup archive. Without a file, it reads from stdin. Compression is detected automatically. It reuses the container name baked into the archive and refuses to overwrite a container that is already installed; remove that one first, or install the archive under a new name with `install --name`.

| Option            | Description               |
| ----------------- | ------------------------- |
| `-v`, `--verbose` | Show each extracted file. |
| `-q`, `--quiet`   | Only show errors.         |

```sh
chroot-distro restore ubuntu.tar.xz
gpg -d ubuntu.tar.gpg | chroot-distro restore
```

### diff

```
chroot-distro diff [OPTIONS] CONTAINER
```

Show what changed inside a container compared to its original image, like `docker diff`. `A` means added, `C` changed, `D` deleted. Needs the image layers to still be in the cache, so avoid `clear-cache` if you want `diff` to keep working.
The text output escapes backslashes and nonprintable characters in paths. The JSON document preserves the original paths.

| Option   | Description                                                                                                           |
| -------- | --------------------------------------------------------------------------------------------------------------------- |
| `--json` | Print one JSON document on stdout: the container name and its `added`, `modified` and `deleted` paths, each absolute. |

### search

```
chroot-distro search [OPTIONS] TERM
Aliases: find, se
```

Search Docker Hub. Shows image name, stars, official status, and a short description.

| Option            | Description                                 |
| ----------------- | ------------------------------------------- |
| `-l`, `--limit N` | Show up to N results (default 25, max 100). |
| `-q`, `--quiet`   | Only show errors.                           |

### info

```
chroot-distro info [OPTIONS]
Aliases: version-info, nf
```

| Option   | Description                                                                                      |
| -------- | ------------------------------------------------------------------------------------------------ |
| `--json` | Print the same report as one JSON document on stdout, one key per section the text report shows. |

Print a diagnostics report: versions, host details, capabilities, kernel support, installed containers, and basic health checks. Attach it when filing a bug report.

It always runs as root. The kernel support section is probed by trying each feature, not read from a kernel build config. A `scratch` or distroless image ships no shell, so its architecture is read from the image manifest instead.

### help

```
chroot-distro help [COMMAND]
Aliases: h, he, hel
```

Show detailed help for a command or alias, or general usage when no command is given.
For example, `chroot-distro help info` shows the same page as `chroot-distro info --help`.

### build

```
chroot-distro build [OPTIONS] [PATH]
```

Build an image from a Dockerfile, like `docker build` but without Docker. `PATH` is the folder with your Dockerfile (default: current folder). The result is stored locally, so `chroot-distro install <tag>` installs it offline.

| Option                            | Description                                                                                                                                                                            |
| --------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `-f`, `--file PATH`               | Use a Dockerfile at a different location. Pass `-` to read it from stdin.                                                                                                              |
| `-t`, `--tag REF`                 | Name the image (like `myapp:1.0`), without a digest. Can be given more than once.                                                                                                      |
| `--build-arg K=V`                 | Set a build-time `ARG`. Can be given more than once.                                                                                                                                   |
| `--build-context name=VALUE`      | Give a name to another source the Dockerfile can use. `VALUE` is a local folder or an image reference. See [Named build contexts](#named-build-contexts). Can be given more than once. |
| `-a`, `--architecture ARCH`       | Build for a different CPU type. Default is your host's CPU. The one-platform spelling of `--platform`.                                                                                 |
| `--platform LIST`                 | Build one image per platform, comma-separated (`linux/amd64,linux/arm64`). Can be given more than once.                                                                                |
| `--target STAGE`                  | Stop at a named stage of a multi-stage build.                                                                                                                                          |
| `-o`, `--output FILE`             | Also save the image as an OCI tarball (`.oci.tar`, `.oci.tar.gz`, `.oci.tar.xz`). Can be given more than once.                                                                         |
| `--export type=...,dest=...`      | Export the rootfs itself: `type=local,dest=DIR` as a directory, `type=tar,dest=FILE` as a plain tarball. One platform, your own CPU. More than once.                                   |
| `--install-as NAME`               | Install the built image under a new container name after the build.                                                                                                                      |
| `--secret id=NAME[,src=PATH]`     | Give a secret to `RUN --mount=type=secret` steps. Without `src=`, the value comes from the environment variable `NAME`. Secrets never end up in the image.                             |
| `--ssh ID[=SOCK]`                 | Give an SSH agent socket to `RUN --mount=type=ssh` steps. Default socket is `$SSH_AUTH_SOCK`.                                                                                          |
| `--no-cache`                      | Rebuild every step from scratch instead of reusing cached steps.                                                                                                                       |
| `--allow-insecure`                | Allow untrusted certificates and plain HTTP when importing or exporting registry build cache. Docker Hub always uses verified HTTPS. |
| `--cache-from type=local,src=DIR` | Reuse the cached steps a `--cache-to` saved in `DIR`. `type=registry,ref=REF` reads a registry instead. Can be given more than once.                                                   |
| `--cache-to type=local,dest=DIR`  | Save this build's cached steps into `DIR`. `type=registry,ref=REF` pushes them to a registry. Can be given more than once.                                                             |
| `--progress MODE`                 | Output style: `auto`, `plain`, `tty`, or `rawjson`.                                                                                                                                    |
| `-v`, `--verbose`                 | Show each instruction and full `RUN` output.                                                                                                                                           |
| `-q`, `--quiet`                   | Only show errors.                                                                                                                                                                      |

`RUN` steps need root because they execute inside the half-built image.

#### Dockerfile support

Every instruction is supported: `ADD`, `ARG`, `CMD`, `COPY`, `ENTRYPOINT`, `ENV`, `EXPOSE`, `FROM`, `HEALTHCHECK`, `LABEL`, `MAINTAINER`, `ONBUILD`, `RUN`, `SHELL`, `STOPSIGNAL`, `USER`, `VOLUME`, `WORKDIR`. So are multi-stage builds with named stages, `ARG` and `ENV` expansion, the `# escape` and `# check` parser directives, and here-docs.

| Feature              | What it does here                                                                                                                                                   |
| -------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `RUN --mount`        | `type=bind`, `cache`, `tmpfs`, `secret` and `ssh`. Every field is variable-expanded, so `target=$DIR` works.                                                        |
| `RUN --network`      | `host` and `default`. The container always shares your network.                                                                                                     |
| `COPY` / `ADD` flags | `--from`, `--chown`, `--chmod`, and `--parents` on `COPY`.                                                                                                          |
| `ADD` sources        | Files, folders, `http://` and `https://` URLs, and tar archives, which are unpacked as Docker unpacks them.                                                         |
| Here-docs            | On `RUN`, `COPY` and `ADD`. A `RUN` body starting with `#!` runs as a script under the interpreter it names; a `COPY <<EOF /etc/conf` writes the body to that file. |
| `ONBUILD`            | Recorded for whoever builds `FROM` your image. Triggers fire once, for the next build, and are not passed on again.                                                 |
| `HEALTHCHECK`        | Recorded in the image, options and all, for a runtime that runs checks. chroot-distro never runs one.                                                               |
| `SHELL`              | Sets what a shell-form `RUN`, `CMD` and `ENTRYPOINT` are wrapped in. JSON form only, like Docker.                                                                   |

These fail with a clear error rather than being ignored:

| Not supported                                             | Reason                                                                                                                                    |
| --------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- |
| `RUN --network=none`                                      | Needs network namespaces, which chroot-distro does not provide.                                                                           |
| `RUN --security`                                          | Comes after the isolation work.                                                                                                           |
| `COPY --link`                                             | A BuildKit-only way of rebasing layers.                                                                                                   |
| `COPY --checksum`, `ADD --keep-git-dir`                   | Not implemented.                                                                                                                          |
| `ADD` or `--build-context` from a git repository          | Not implemented. The error names the alternative: the host's archive URL for `ADD`, or a checkout passed as a local folder for a context. |
| `--cache-from`/`--cache-to` other than `local`/`registry` | Those two are what move a cache, see [Cache import and export](#cache-import-and-export).                                                 |
| Provenance, SBOM, and remote build contexts               | Not implemented.                                                                                                                          |

A `# syntax=` line naming anything but `docker/dockerfile` asks for a frontend program that this cannot fetch or run. The build warns and reads the file as an ordinary Dockerfile.

A `.dockerignore` file in the context excludes files from `COPY` and `ADD`, with Docker's own rules: `*` and `?` stop at a `/`, `**` spans any number of folders, `!` puts a file back, the last matching line decides, and naming a folder covers everything inside it.

#### Named build contexts

`--build-context name=VALUE` lets the Dockerfile pull from somewhere other than the folder you passed to `build`, the way `docker buildx` does:

```sh
chroot-distro build -t myapp --build-context assets=../shared-assets .
```

A Dockerfile then refers to the name from `FROM` or from `COPY --from=`:

```dockerfile
FROM alpine
COPY --from=assets logo.png /usr/share/myapp/
FROM assets AS bundled   # a local folder: scratch plus the tree copied in
```

The value is a local folder or an image reference. A folder is read like the main build context, with its own `.dockerignore`; a stage `FROM` one starts empty and copies the folder in. An image reference is pulled and used as a base. A stage declared with `AS` in the same Dockerfile still wins over a same-named context, as in Docker. Git URLs are refused (there is no git client here): clone the repository yourself and pass the checkout as a local folder.

#### Platforms and output

`FROM --platform` picks one stage's platform, so `FROM --platform=$BUILDPLATFORM` builds that stage for your own CPU while the image stays on the build's platform. `TARGETPLATFORM`, `TARGETARCH` and the other `BUILD*`/`TARGET*` names are set automatically; a bare `ARG TARGETARCH` inside a stage is what lets a `RUN` there read one.

`--platform linux/amd64,linux/arm64` builds one image per platform, one after another, in the order you asked. Two spellings of one platform (`linux/arm64` and `linux/aarch64`) are one image. Each platform is built on its own; if one fails, the build stops and publishes nothing.

Where those images end up:

- `--output` writes one archive holding an OCI image index over every platform, sharing common layers. `docker load` reads the first platform out of it; `chroot-distro install FILE` picks the one matching your CPU.
- Every `--tag` records every platform in the local cache: `install myapp:1.0` installs yours, `install myapp:1.0 -a arm64` the other.
- `--install-as` installs one container, so it takes the platform your host can run and refuses a set with nothing your host runs.

```sh
chroot-distro build -t myapp:1.0 --install-as myapp .
chroot-distro build -t myapp:1.0 --platform linux/amd64,linux/arm64 -o myapp.oci.tar .
```

#### Exporting the rootfs

`--output` writes the image: the manifest, config and layers a registry or `docker load` reads. To get the filesystem alone, use `--export`, which writes the rootfs for your own CPU's platform:

```sh
chroot-distro build -t myapp:1.0 --export type=tar,dest=rootfs.tar.gz .
chroot-distro build -t myapp:1.0 --export type=local,dest=./rootfs .
```

`type=tar` writes a plain tarball (compression picked from the extension), `type=local` a plain directory. Both hold the rootfs the image describes and nothing else: no manifest, no layer blobs. Ownership stays numeric, so an image built for a non-root user extracts correctly. Neither destination may already exist.

#### Cache import and export

`build` remembers every `RUN` it executed, but only on the machine that ran it. `--cache-to` writes what this build's steps produced somewhere else, and `--cache-from` reads it back, so a fresh CI runner can start with the cache the last one finished with.

```sh
# A folder on disk
chroot-distro build -t myapp:1.0 \
    --cache-from type=local,src=.buildcache \
    --cache-to type=local,dest=.buildcache .

# A registry, for a cache shared across machines
chroot-distro build -t myapp:1.0 \
    --cache-from type=registry,ref=ghcr.io/me/myapp-cache:latest \
    --cache-to type=registry,ref=ghcr.io/me/myapp-cache:latest .
```

Both backends hold the same document with a `build-cache.json` listing the steps and one blob per layer. `type=local` keeps it in a folder (`src=` or `dest=`). `type=registry` stores it as a single OCI artifact at `ref=`. Use a tag reference such as `ghcr.io/me/cache:latest`. Omitting the tag selects `latest`. Set `CD_DOCKER_AUTH` for a private registry. You can repeat either backend and import what the other exported.

- Only the steps this build ran are exported, and an export only adds to what the target already holds; delete the target to start over.
- A folder that is not there yet imports nothing (no error); one that is there and is not a cache folder stops the build.
- Layers are checksum-checked on the way in, but the source can still lie about which step a layer belongs to, so point `--cache-from` only at one you trust.
- `--no-cache` skips the import; the export still runs.

### push

```
chroot-distro push [OPTIONS] IMAGE
```

Upload an image you built with `build -t` to Docker Hub or another registry. Layers already on the registry are skipped.

| Option                      | Description                                                                                                                                                |
| --------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `-a`, `--architecture ARCH` | Push the image built for that CPU type. Default is your host's CPU.                                                                                        |
| `--allow-insecure`          | Permit insecure transport: an untrusted certificate, or a redirect from HTTPS to plain HTTP. Only for registries you trust; Docker Hub is always verified. |
| `-q`, `--quiet`             | Only show errors.                                                                                                                                          |

Set `CD_DOCKER_AUTH=username:password` before pushing to a private repository. The password half can be a personal access token, which is what GHCR wants. A "too many requests" answer (HTTP 429) stops the push with a message saying whose limit it is; a short wait the registry asks for is waited out automatically.

### clear-cache

```
chroot-distro clear-cache [OPTIONS]
Aliases: clear, cl
```

Delete all cached downloads (image layers, manifests, build cache) and show how much space was freed. After this, installing an image needs the network again, and `diff` stops working for existing containers.

| Option            | Description                                                                                     |
| ----------------- | ----------------------------------------------------------------------------------------------- |
| `--build-cache`   | Drop the build cache index and the layer blobs only it was pinning.                             |
| `--keep SIZE`     | With `--build-cache`, evict least-recently-used entries past `SIZE` instead of dropping it all. |
| `-v`, `--verbose` | Show each deleted file.                                                                         |
| `-q`, `--quiet`   | Only show errors.                                                                               |

Every `RUN` a build executes is recorded against the layer it produced, so a later build with the same inputs reuses it. Without a cap nothing evicts these entries, so the build cache only grows.

```sh
# Reclaim the build cache, keep the downloaded images
chroot-distro clear-cache --build-cache

# Or trim it to 500 MiB, dropping the least-recently-used steps first
chroot-distro clear-cache --build-cache --keep 500M
```

Without `--keep` this removes the index and then deletes the layers nothing else points at; the layers of images you still have are kept, and the next `build` re-runs every step. With `--keep`, only the least-recently-used entries past `SIZE` are evicted. It refuses to run while another `chroot-distro` command holds a lock. To skip cache lookups for a single build without deleting anything, use `build --no-cache`.

Set `CD_BUILD_CACHE_MAX` (for example `CD_BUILD_CACHE_MAX=1G`) and every `build` prunes itself against that cap when it finishes, so the cache stays bounded without a manual `clear-cache`.

A folder written by `build --cache-to` is yours, not part of this cache; delete it yourself when you want it gone.

### remove

```
chroot-distro remove [OPTIONS] CONTAINER
Aliases: rm
```

Delete a container and all its data. There is no confirmation and no undo. Active sessions are unmounted first.

| Option            | Description             |
| ----------------- | ----------------------- |
| `-v`, `--verbose` | Show each deleted file. |
| `-q`, `--quiet`   | Only show errors.       |

## JSON output

`list`, `ps`, `diff` and `info` take `--json` and write one JSON document to stdout. Human output, progress and warnings stay on stderr, so `chroot-distro list --json | jq .` works without filtering.

Every document, success or failure, is an object carrying the schema version and the command that produced it:

```jsonc
{"schema": 1, "command": "list", "containers": [ ... ], "incomplete": []}

// on failure, exit code 1
{"schema": 1, "command": "diff", "error": "container 'nope' is not installed."}
```

If an elevation tool fails before starting chroot-distro as root, that tool
controls the diagnostic and exit status. In that case stdout may be empty.
Failures handled by chroot-distro, including failure to launch the elevation
tool, use the JSON error document.

Human `list` and `ps` tables, backup messages, and plain and TTY build events
escape control characters in names and other values they display. Displayed
container names and filesystem paths also escape literal backslashes.
JSON output and tar archives preserve the original values.

The stderr diagnostic escapes control characters. If stdout is unavailable or
its pipe closes while writing a JSON document, the version line, quiet `list`
or `ps` output, `--get-chroot-cmd` output, or raw JSON build events,
chroot-distro exits with status 1.

`schema` is bumped only when a key is renamed, removed or changes type, so a consumer can ignore keys it does not know and keep working. Field rules: a byte count is an integer named `*_bytes` with its formatted twin beside it, a duration is `*_seconds`, a path is absolute, a flag is a real `true`/`false`, an unknown value is `null`, and a list is always present even when empty.

```sh
chroot-distro list --json | jq -r '.containers[] | "\(.name) \(.status)"'
chroot-distro ps --json | jq '.sessions[] | select(.detached)'
chroot-distro diff ubuntu --json | jq -r '.added[]'
```

## Storage layout

Everything lives in one data folder, plus a cache folder that is separate on Linux
and nested inside the data folder on Termux:

| Platform      | Data folder                      | Cache folder                           |
| ------------- | -------------------------------- | -------------------------------------- |
| Termux        | `$PREFIX/var/lib/chroot-distro/` | `$PREFIX/var/lib/chroot-distro/cache/` |
| Regular Linux | `~/.local/share/chroot-distro/`  | `~/.cache/chroot-distro/`              |

On regular Linux, commands that access the store run as root. The default
folders are usually under `/root/`. Set `XDG_DATA_HOME` and `XDG_CACHE_HOME`
to use other base directories. If a previous sudo invocation used your home
directory, point those variables to the previous bases, typically your
`.local/share` and `.cache`, to reopen that store.

Shell completion reads container names with your shell's permissions. On
regular Linux, an unelevated shell uses the root account's data directory
unless you set `XDG_DATA_HOME` to another base. If your shell cannot read the
store, run `chroot-distro list --quiet` to see the installed names.

Inside the data folder:

| Path                              | Contents                                   |
| --------------------------------- | ------------------------------------------ |
| `containers/<name>/rootfs/`       | The container's filesystem                 |
| `containers/<name>/manifest.json` | Image info used by `reset` and `run`       |
| `sessions/`                       | Active session records used by `ps`        |
| `locks/`                          | Lock files preventing conflicting commands |

Inside the cache folder:

| Path             | Contents                   |
| ---------------- | -------------------------- |
| `oci_layers/`    | Downloaded image layers    |
| `oci_manifests/` | Downloaded image manifests |

## Environment variables

All of these are optional.

| Variable                          | Effect                                                                                                                                                                                                                             |
| --------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `CD_DOCKER_AUTH`                  | Registry login as `username:password`, where the password is a personal access token on most registries. The colon is required, so a bare token is refused. Used by `install`, `build`, and `push`.                                |
| `CD_DOWNLOAD_WORKERS`             | How many layers to download at once (default 4, max 10).                                                                                                                                                                           |
| `CD_DOWNLOAD_RATE_LIMIT`          | Download speed limit, like `5M` for 5 MiB/s. Default is unlimited.                                                                                                                                                                 |
| `CD_DOWNLOAD_MAX_RETRIES`         | Retries per failed download (default 3, max 20).                                                                                                                                                                                   |
| `CD_BUILD_CACHE_MAX`              | Build-cache size cap, like `1G`. A `build` prunes least-recently-used steps past it once it finishes. Default is no cap.                                                                                                           |
| `CD_USER`                         | Default user for `login`/`run` when `--user` is not given.                                                                                                                                                                         |
| `CD_WORKDIR`                      | Default working directory for `login`/`run` when `--work-dir` is not given.                                                                                                                                                        |
| `CD_ENV`                          | Extra guest environment variables, one `VAR=VALUE` per line. `--env` wins on conflict.                                                                                                                                             |
| `CD_ENTRYPOINT`                   | Default entrypoint for `run` when `--entrypoint` is not given.                                                                                                                                                                     |
| `CD_USE_NS`                       | Set to `1` to give every `login`/`run` and `build` `RUN` step its own namespaces while keeping all normal shared folders.                                                                                                          |
| `CD_USE_ISOLATION`                | Set to `1` to force maximum isolation, same as `--isolated`. For `build`, which has no flag, it isolates the `RUN` steps; wins over `CD_USE_NS` when both are set.                                                                 |
| `CD_NO_NEW_PRIVS`                 | Set to `1` to set `PR_SET_NO_NEW_PRIVS` for every `login`/`run`, same as `--no-new-privs`: setuid binaries in the container cannot gain privileges.                                                                                |
| `CD_NO_SECCOMP`                   | Set to `1` to skip the seccomp denylist filter for `login`/`run`. The default filter blocks syscalls a distro never touches (`io_uring`, `bpf`, module loading, `keyctl`, raw I/O); set this if a guest program needs one of them. |
| `CD_FORCE_NO_COLORS`              | Disable colored output.                                                                                                                                                                                                            |
| `TERMUX__PREFIX`                  | Override the Termux prefix path.                                                                                                                                                                                                   |
| `TERMUX__HOME`                    | Override the Termux home path used by `--shared-home`.                                                                                                                                                                             |
| `TERMUX_APP__PACKAGE_NAME`        | Termux app package name (default `com.termux`).                                                                                                                                                                                    |
| `XDG_DATA_HOME`, `XDG_CACHE_HOME` | Move the data and cache folders on regular Linux.                                                                                                                                                                                  |

## Limitations

- **No full init systems.** `systemd` and similar will not work inside containers. Individual long-running programs are fine.
- **Isolation is partial.** `--isolated` covers mount, PID, UTS, and IPC namespaces (no network isolation). It is not a full container runtime like Docker or Podman.
- **`--isolated` writes land as the container uid.** Where the kernel and `/etc/subuid` allow it, the guest's processes run as unprivileged host uids through an idmapped mount, so a file the guest creates carries the same host uid it shows inside. This scopes the guest's privileges; it does not protect the rootfs from the guest.
- **Default mode has no boundary.** Without `--isolated` or `CD_USE_NS` the guest runs as host root: `/proc` lists host processes, and `/proc/<pid>/root` reaches the host filesystem of any listed process. Use the namespace modes when the guest is not your own.
- **The capability drop spares what desktop programs need.** The bounding set keeps `CAP_SYS_ADMIN` (mounts, FUSE) and `CAP_SYS_CHROOT` (the setuid sandbox helpers of Chromium and Electron), so a namespace mode is the boundary for a guest you do not trust.
- **Builds are not full BuildKit.** `RUN` steps execute under chroot, few BuildKit features are not supported so they are rejected with an error.
- **`push` is single-architecture.** `build --platform` produces several platforms at once, but each is pushed on its own with `push -a`.
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
- [pyLoad](https://github.com/pyload/pyload) - downloader improvements.
- [distrobox](https://github.com/89luca89/distrobox/) - shared-display option improvements.
- [Magisk-Modules-Alt-Repo/chroot-distro](https://github.com/Magisk-Modules-Alt-Repo/chroot-distro) - some info about chroot on android.
- [ravindu644/Ubuntu-Chroot](https://github.com/ravindu644/Ubuntu-Chroot) - some info about chroot on android.

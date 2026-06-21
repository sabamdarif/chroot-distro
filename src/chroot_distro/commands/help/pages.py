import typing

from chroot_distro.constants import (
    CANONICAL_PROGRAM_NAME,
    IS_TERMUX,
    PROGRAM_NAME,
    TERMUX_APP_PACKAGE,
)

_ISOLATED_OPT = (
    "--isolated",
    "Enable Isolated Mode: fewer host bind mounts plus Linux namespace isolation "
    "(mount, PID, UTS, IPC via unshare/nsenter). On Termux, skip Android system, "
    "storage, and $PREFIX bindings unless requested with --shared-* or --bind. "
    "On Linux, skip default /tmp and display sharing unless --shared-tmp or "
    "--shared-display. Not a full container runtime (no network namespace).",
)
_MINIMAL_OPT = (
    "--minimal",
    "Bare minimum chroot: bind only core pseudo-filesystems (/dev, /proc, /sys, "
    "and /run, /dev/pts, /dev/shm when present). Stripped guest environment. "
    "Mutually exclusive with --isolated.",
)

HELP_PAGES: dict[str, dict[str, typing.Any]] = {
    "build": {
        "usage": "build [OPTIONS] [PATH]",
        "summary": (
            "Build an OCI/Docker-compatible image from a Dockerfile."
            "\n\n"
            "PATH is the build context directory containing the "
            "Dockerfile (default: '.'). All COPY/ADD source paths "
            "resolve relative to it. A '.dockerignore' file in the "
            "context excludes patterns from COPY/ADD."
            "\n\n"
            "By default the image is stored in the local manifest "
            "cache under the tag given by --tag (default: the "
            "basename of PATH plus ':latest'). Once stored, "
            f"'{PROGRAM_NAME} install <tag>' resolves the tag against "
            "the cache first and installs entirely offline."
            "\n\n"
            "Use --output FILE to additionally write a standalone "
            "OCI image-layout tarball that 'docker load' or "
            f"'{PROGRAM_NAME} install FILE' also understands."
            "\n\n"
            "Use --install-as NAME to turn the freshly built image "
            "into a container in one step."
        ),
        "options": [
            ("-h, --help", "Show this help."),
            (
                "-f, --file [PATH]",
                "Use a Dockerfile at PATH instead of <PATH>/Dockerfile. "
                "Pass '-' to read the Dockerfile from standard input.",
            ),
            ("-t, --tag [REF]", "Image reference to assign. Repeatable. Defaults to '<basename(PATH)>:latest'."),
            (
                "--build-arg [K=V]",
                "Set a build-time ARG. Only ARGs declared in the Dockerfile are honoured. Repeatable.",
            ),
            (
                "-a, --architecture [ARCH]",
                "Target CPU architecture (default: host architecture). "
                f"Accepts {PROGRAM_NAME} names (aarch64, arm, i686, "
                "riscv64, x86_64) or Docker platform strings "
                "(linux/arm64, linux/amd64, ...).",
            ),
            ("--target [STAGE]", "Stop after the named stage of a multi-stage build."),
            (
                "-o, --output [FILE]",
                "Write the built image as an OCI tarball to FILE. "
                "Compression is inferred from the extension "
                "(.oci.tar, .oci.tar.gz, .oci.tar.xz). Repeatable.",
            ),
            ("--install-as [NAME]", "Install the built image as a container named NAME after the build completes."),
            ("--no-cache", "Disable build-step caching. Each instruction is executed fresh."),
            ("-v, --verbose", "Echo each instruction and stream RUN output to the terminal."),
            ("-q, --quiet", "Suppress non-error output. Mutually exclusive with --verbose."),
        ],
        "examples": [
            f"{PROGRAM_NAME} build -t myapp:1.0 .",
            f"{PROGRAM_NAME} build -t myapp:1.0 --output myapp.oci.tar.gz .",
            f"{PROGRAM_NAME} build -t myapp --install-as myapp .",
            f"{PROGRAM_NAME} build -f Dockerfile.arm --architecture aarch64 .",
        ],
        "footer": [
            {
                "title": "ROOT REQUIREMENT",
                "intro": (
                    "Since chroot-distro uses the host's native chroot "
                    "mechanism, running 'build' with 'RUN' instructions "
                    "executes commands against the in-progress rootfs "
                    "using chroot, which requires root privileges."
                ),
            },
            {
                "title": "AFTER BUILD",
                "intro": (
                    "Without --output and --install-as, the image is "
                    "stored only in the local cache. "
                    f"'{PROGRAM_NAME} install <tag>' resolves the "
                    "tag against the cache first; install proceeds "
                    "without network access when the manifest and "
                    "all layers are cached."
                ),
            },
            {
                "title": "LIMITATIONS",
                "intro": (
                    "RUN steps run under chroot, not a fully isolated container "
                    "runtime. BuildKit-only features (RUN --mount, --network, "
                    "--security; COPY --link, --parents) are rejected with an "
                    "error. Multi-platform manifest lists are not produced."
                ),
            },
        ],
    },
    "push": {
        "usage": "push [OPTIONS] IMAGE",
        "summary": (
            "Push a locally built image to a Docker/OCI registry. The "
            "image must have been produced by '"
            f"{PROGRAM_NAME} build -t IMAGE' first; the manifest and "
            "blobs are read straight from the local cache."
            "\n\n"
            "IMAGE is the same reference passed to 'build -t', for "
            "example 'myuser/myapp:1.0' (Docker Hub) or "
            "'ghcr.io/myorg/myapp:1.0' (custom registry). When no tag "
            "component is present, ':latest' is appended."
            "\n\n"
            "By default the architecture matches the host. Use "
            "--architecture to push an image built for a different "
            "target arch (the manifest cache is keyed by IMAGE+arch)."
            "\n\n"
            "Layers and the image config blob that are already present "
            "on the registry are detected via HEAD requests and "
            "skipped, so re-pushing an unchanged image transfers only "
            "the small manifest."
            "\n\n"
            "Private repositories require authentication. Set "
            'CD_DOCKER_AUTH="user:password" (or '
            '"user:personal-access-token") before running push. '
            "Self-hosted registries that allow anonymous push do not "
            "need CD_DOCKER_AUTH set."
        ),
        "options": [
            ("-h, --help", "Show this help."),
            (
                "-a, --architecture [ARCH]",
                "Push the manifest built for the given architecture. "
                f"Accepts {PROGRAM_NAME} names (aarch64, arm, i686, "
                "riscv64, x86_64) or Docker platform strings "
                "(linux/arm64, linux/amd64, ...). Default: host "
                "architecture.",
            ),
            ("-q, --quiet", "Suppress non-error output."),
        ],
        "examples": [
            f"{PROGRAM_NAME} push myuser/myapp:1.0",
            f"{PROGRAM_NAME} push ghcr.io/myorg/myapp:1.0",
            f"{PROGRAM_NAME} push --architecture aarch64 myuser/myapp:1.0",
        ],
        "footer": [
            {
                "title": "AUTHENTICATION",
                "intro": (
                    "Set CD_DOCKER_AUTH in 'username:password' format "
                    "before running push. The colon is mandatory; "
                    "bare tokens without a username cannot be used "
                    "because registry auth requires a token exchange "
                    "with Basic credentials. For GitHub Container "
                    "Registry, use a personal access token with the "
                    "'write:packages' scope as the password."
                ),
                "examples": [
                    "export CD_DOCKER_AUTH=user:password",
                    f"{PROGRAM_NAME} push ghcr.io/myorg/myapp:1.0",
                ],
            },
        ],
    },
    "backup": {
        "usage": "backup [OPTIONS] CONTAINER",
        "aliases": ("bak", "bkp"),
        "summary": (
            "Back up a specified container into a TAR archive. "
            "Compression is determined by the output file extension or "
            "by the --compress option. Output to stdout is "
            "uncompressed by default."
        ),
        "options": [
            ("-h, --help", "Show this help."),
            (
                "-c, --compress [TYPE]",
                "Force a specific compression algorithm, overriding the "
                "file extension. Supported values: gzip, bzip2, xz, none.",
            ),
            (
                "-o, --output [FILE]",
                "Write the archive to FILE instead of stdout. When "
                "--compress is not given, compression is inferred from "
                "the file extension like tar.gz or txz.",
            ),
            ("-v, --verbose", "Log each file name as it is added to the archive."),
            ("-q, --quiet", "Suppress non-error output. Mutually exclusive with --verbose."),
        ],
        "examples": [
            f"{PROGRAM_NAME} backup ubuntu --output ~/ubuntu.tar.xz",
        ],
    },
    "clear-cache": {
        "usage": "clear-cache",
        "aliases": ("clear", "cl"),
        "summary": ("Remove all files from downloads cache (e.g. Docker image layers)."),
        "options": [
            ("-h, --help", "Show this help."),
            ("-v, --verbose", "Log each removed file."),
            ("-q, --quiet", "Suppress non-error output. Mutually exclusive with --verbose."),
        ],
    },
    "copy": {
        "usage": "copy [OPTIONS] [DIST:]SRC [DIST:]DEST",
        "aliases": ("cp",),
        "summary": (
            "Copy files between the host filesystem and a chroot "
            "container. Both source and destination may be a local "
            "path or a 'container:path' reference."
        ),
        "options": [
            ("-h, --help", "Show this help."),
            ("-m, --move", "Delete source file after a successful copy."),
            ("-r, --recursive", "Recursive mode for copying directories."),
            ("-v, --verbose", "Log each copied file."),
            ("-q, --quiet", "Suppress non-error output. Mutually exclusive with --verbose."),
        ],
        "examples": [
            f"{PROGRAM_NAME} copy ./file.txt ubuntu:/root/file.txt",
        ],
        "footer": [
            {
                "title": "NOTES",
                "intro": (
                    "Directories '.' or '..' are only accepted as "
                    "source, not as destination. Glob patterns are "
                    "not supported."
                ),
            },
        ],
    },
    "install": {
        "usage": "install [OPTIONS] (IMAGE:TAG or URL or FILE)",
        "aliases": ("add", "i", "in", "ins"),
        "summary": (
            "Create a chroot container from a given source: Docker image, "
            "OCI image archive, rootfs tarball or a web URL providing "
            "either of supported archive file formats."
            "\n\n"
            "Installation from Docker image require specifying a reference, "
            "for example 'ubuntu:24.04'. Official images can be specified by "
            "name alone ('ubuntu'), while user images require the "
            "'user/image' form. If no tag (version) specified, the 'latest' "
            "will be used instead."
            "\n\n"
            "By default Docker images will be pulled from Docker Hub. Custom "
            "registry needs to be specified as part of image reference. "
            "Example: 'ghcr.io/foo/bar:tag'."
            "\n\n"
            "Layers are cached locally and reused on subsequent "
            "installs of the same image."
            "\n\n"
            "Container name is being determined from name of Docker image "
            "or rootfs archive file. To be able install multiple instances "
            "of same distribution, you need to override name using a command "
            "line option."
            "\n\n"
            "Private images require authentication. Set the environment "
            'variable CD_DOCKER_AUTH="user:password" before running '
            "the install command. Some registries use a personal access "
            "token instead of password."
        ),
        "options": [
            ("-h, --help", "Show this help."),
            (
                "-n, --name [NAME]",
                "Set a custom name for the container. Must start with "
                "alphanumeric character and then may contain only latin "
                "letters, numbers and special symbols dot, minus, underscore. "
                "Default equals to image name without tag and registry prefix.",
            ),
            (
                "-a, --architecture [ARCH]",
                "Override the target CPU architecture. Accepts native "
                "names (aarch64, arm, i686, riscv64, x86_64) or Docker "
                "platform strings (linux/arm64, linux/amd64, linux/arm/v7, "
                "linux/386, linux/riscv64).",
            ),
            ("-q, --quiet", "Suppress non-error output."),
        ],
        "examples": [
            f"{PROGRAM_NAME} install ubuntu:24.04",
            f"{PROGRAM_NAME} install -a x86_64 debian",
            f"{PROGRAM_NAME} install -n dist https://example.com/rootfs.tar",
            f"{PROGRAM_NAME} install -n dist ~/rootfs.tgz",
        ],
    },
    "list": {
        "usage": "list [OPTIONS]",
        "aliases": ("li", "ls"),
        "summary": (
            "List installed chroot containers with rootfs size, image "
            "source (from manifest.json when available), and busy/idle status."
        ),
        "options": [
            ("-h, --help", "Show this help."),
            ("-q, --quiet", "Print only container names, one per line."),
        ],
    },
    "login": {
        "usage": "login [OPTIONS] CONTAINER [-- COMMAND]",
        "aliases": ("sh",),
        "summary": (
            "Start interactive shell configured for a given account "
            "configured in /etc/passwd. Alternatively user can specify "
            "a custom command to use instead of default shell after "
            "command line separator ('--')."
            "\n\n"
            "Since chroot-distro runs real chroot processes, root permissions "
            "are required to mount directories and perform chroot."
        ),
        "options": [
            ("-h, --help", "Show this help."),
            (
                "-u, --user [USER]",
                "User identity to switch to instead of root. Accepted forms: "
                "'name' (username from /etc/passwd), "
                "'name:group' (username and group name from /etc/passwd and /etc/group), "
                "'uid' (numeric UID), "
                "'uid:gid' (numeric UID and GID).",
            ),
            _ISOLATED_OPT,
            _MINIMAL_OPT,
            (
                "--shared-home",
                "Bind host home directory into the container."
                + (" Takes priority over Isolated Mode. Already included in default mode." if IS_TERMUX else ""),
            ),
            (
                "--shared-tmp",
                "Bind host tmp directory to /tmp."
                + (
                    " Takes priority over Isolated Mode. Already included in default mode."
                    if IS_TERMUX
                    else " On Linux, included by default unless --isolated."
                ),
            ),
            (
                "--shared-display",
                "Share X11, Wayland, sound (PulseAudio/PipeWire), and D-Bus with the container."
                + (
                    " Takes priority over Isolated Mode. Already included in default mode. --shared-x11 accepted as alias."
                    if IS_TERMUX
                    else " On Linux, opt-in only. Forwards DISPLAY, XAUTHORITY, XDG_RUNTIME_DIR, WAYLAND_DISPLAY, PULSE_SERVER, and DBUS_SESSION_BUS_ADDRESS. --shared-x11 accepted as a backward-compatible alias."
                ),
            ),
            (
                "-b, --bind [SRC[:DEST[:OPTIONS]]]",
                "Custom filesystem binding. The optional third field OPTIONS "
                "is a comma-separated list of mount options applied via "
                "remount (e.g. 'ro', 'ro,nosuid'); SELinux relabel flags z/Z "
                "are accepted for docker-compat but ignored in a plain "
                "chroot. Can be specified multiple times."
                + (" Takes priority over Isolated Mode." if IS_TERMUX else " Honored in all modes."),
            ),
            ("-w, --work-dir [PATH]", "Set the initial working directory."),
            ("-e, --env VAR=VALUE", "Set an environment variable. Can be specified multiple times."),
            ("--get-chroot-cmd", "Print the fully assembled chroot command line and exit without running it."),
        ],
        "footer": [
            *(
                [
                    {
                        "title": "HOST BINDINGS",
                        "intro": ("Without --isolated, the following host paths are bound inside the container:"),
                        "bullets": [
                            ("/apex", None),
                            ("/data/dalvik-cache", None),
                            (f"/data/data/{TERMUX_APP_PACKAGE}", None),
                            ("/linkerconfig/ld.config.txt", None),
                            ("/linkerconfig/com.android.art/ld.config.txt", None),
                            ("/mnt/sdcard", None),
                            ("/odm", None),
                            ("/product", None),
                            ("/sdcard", None),
                            ("/storage/emulated/0", None),
                            ("/storage/self/primary", None),
                            ("/system", None),
                            ("/system_ext", None),
                            ("/vendor", None),
                        ],
                    }
                ]
                if IS_TERMUX
                else []
            ),
            {
                "title": "NOTES",
                "intro": (
                    (
                        "If host utilities like termux-api do not work, "
                        "ensure that PATH includes Termux bin directory as "
                        "well as special environment variables such as "
                        "ANDROID_ART_ROOT, ANDROID_DATA, ANDROID_I18N_ROOT, "
                        "ANDROID_ROOT, ANDROID_TZDATA_ROOT, BOOTCLASSPATH, "
                        "EXTERNAL_STORAGE. Valid values can be retrieved "
                        "through Termux shell."
                        "\n\n"
                        "Host storage bindings such as /sdcard may be "
                        "disabled if Termux app does not have necessary "
                        "permissions."
                        "\n\n"
                        if IS_TERMUX
                        else ""
                    )
                    + f"{CANONICAL_PROGRAM_NAME} comes without any guarantee "
                    "that any user-selected distribution image will work "
                    "properly. Any kind of observed bugs could happen "
                    "because of incompatibilities with the host kernel."
                ),
            },
        ],
    },
    "remove": {
        "usage": "remove [OPTIONS] CONTAINER",
        "aliases": ("rm",),
        "summary": ("Permanently delete the specified chroot container. No confirmation is requested, be careful."),
        "options": [
            ("-h, --help", "Show this help."),
            ("-v, --verbose", "Log each deleted file."),
            ("-q, --quiet", "Suppress non-error output. Mutually exclusive with --verbose."),
        ],
    },
    "unmount": {
        "usage": "unmount CONTAINER",
        "aliases": ("umount", "um"),
        "summary": ("Safely unmount a container, stopping all active sessions and resetting the session counter to 0."),
        "options": [
            ("-h, --help", "Show this help."),
        ],
        "examples": [
            f"{PROGRAM_NAME} unmount ubuntu",
        ],
    },
    "rename": {
        "usage": "rename OLDNAME NEWNAME",
        "summary": "Rename the installed chroot container.",
        "options": [
            ("-h, --help", "Show this help."),
            ("-q, --quiet", "Suppress non-error output."),
        ],
    },
    "reset": {
        "usage": "reset CONTAINER",
        "summary": (
            "Rebuild the specified container from scratch using the "
            "stored Docker image manifest. All current data inside "
            "the container will be lost."
            "\n\n"
            "Works only with containers created from Docker images."
        ),
        "options": [
            ("-h, --help", "Show this help."),
            ("-q, --quiet", "Suppress non-error output."),
        ],
    },
    "restore": {
        "usage": "restore [OPTIONS] [BACKUP_FILE]",
        "summary": (
            "Restore container from a backup archive. When backup file "
            "is not specified, archive data is read from stdin."
        ),
        "options": [
            ("-h, --help", "Show this help."),
            ("-v, --verbose", "Log each extracted file."),
            ("-q, --quiet", "Suppress non-error output. Mutually exclusive with --verbose."),
        ],
        "footer": [
            {
                "title": "NOTES",
                "intro": (
                    "Compression is detected automatically from the "
                    "file header. Supported: gzip, bzip2, xz, "
                    "uncompressed tar. Applies to both file and "
                    "stdin input."
                    "\n\n"
                    "Only one container is restored per archive. An "
                    "archive holding more than one container, or no "
                    "container rootfs at all, is rejected."
                ),
            },
        ],
    },
    "run": {
        "usage": "run [OPTIONS] CONTAINER [-- ARG ...]",
        "summary": (
            "Run the Entrypoint and/or Cmd defined in the "
            "container's Docker image manifest. Arguments given "
            "after '--' are appended to Entrypoint (replacing the "
            "image-defined Cmd). If neither Entrypoint nor Cmd is "
            "defined and no arguments are given, an error is "
            "reported."
            "\n\n"
            "Primarily intended to be used with server images."
        ),
        "options": [
            ("-h, --help", "Show this help."),
            (
                "-u, --user [USER]",
                "User identity to switch to instead of root. Accepted forms: "
                "'name' (username from /etc/passwd), "
                "'name:group' (username and group name from /etc/passwd and /etc/group), "
                "'uid' (numeric UID), "
                "'uid:gid' (numeric UID and GID).",
            ),
            _ISOLATED_OPT,
            _MINIMAL_OPT,
            (
                "--shared-home",
                "Bind host home directory into the container."
                + (" Takes priority over Isolated Mode. Already included in default mode." if IS_TERMUX else ""),
            ),
            (
                "--shared-tmp",
                "Bind host tmp directory to /tmp."
                + (
                    " Takes priority over Isolated Mode. Already included in default mode."
                    if IS_TERMUX
                    else " On Linux, included by default unless --isolated."
                ),
            ),
            (
                "--shared-display",
                "Share X11, Wayland, sound (PulseAudio/PipeWire), and D-Bus with the container."
                + (
                    " Takes priority over Isolated Mode. Already included in default mode. --shared-x11 accepted as alias."
                    if IS_TERMUX
                    else " On Linux, opt-in only. Forwards DISPLAY, XAUTHORITY, XDG_RUNTIME_DIR, WAYLAND_DISPLAY, PULSE_SERVER, and DBUS_SESSION_BUS_ADDRESS. --shared-x11 accepted as a backward-compatible alias."
                ),
            ),
            (
                "-b, --bind [SRC[:DEST[:OPTIONS]]]",
                "Custom filesystem binding. The optional third field OPTIONS "
                "is a comma-separated list of mount options applied via "
                "remount (e.g. 'ro', 'ro,nosuid'); SELinux relabel flags z/Z "
                "are accepted for docker-compat but ignored in a plain "
                "chroot. Can be specified multiple times."
                + (" Takes priority over Isolated Mode." if IS_TERMUX else " Honored in all modes."),
            ),
            ("-w, --work-dir [PATH]", "Set the initial working directory."),
            ("-e, --env VAR=VALUE", "Set an environment variable. Can be specified multiple times."),
            ("--get-chroot-cmd", "Print the fully assembled chroot command line and exit without running it."),
        ],
        "examples": [
            f"{PROGRAM_NAME} run nextcloud",
            f"{PROGRAM_NAME} run ubuntu --isolated -- /bin/echo hi",
        ],
    },
    "kill": {
        "usage": "kill CONTAINER",
        "aliases": ("k", "stop"),
        "summary": (
            "Forcibly stop a running container. All processes inside the "
            "container's chroot are sent SIGTERM and then SIGKILL after a "
            "short grace period, the filesystem bindings are unmounted, and "
            "the namespace holder (if any) is released. This is the abrupt "
            "counterpart to 'unmount'."
        ),
        "options": [
            ("-h, --help", "Show this help."),
        ],
        "examples": [
            f"{PROGRAM_NAME} kill ubuntu",
        ],
    },
    "ps": {
        "usage": "ps [OPTIONS]",
        "summary": (
            "List running containers: those with a live process inside their "
            "chroot or an active namespace holder. Shows rootfs size, image "
            "source, and status, like 'list'."
        ),
        "options": [
            ("-h, --help", "Show this help."),
            ("-a, --all", "Show all installed containers, not just running ones."),
            ("-q, --quiet", "Print only container names, one per line."),
        ],
        "examples": [
            f"{PROGRAM_NAME} ps",
            f"{PROGRAM_NAME} ps --all",
        ],
    },
    "diff": {
        "usage": "diff CONTAINER",
        "summary": (
            "Inspect changes to files and directories in a container's "
            "filesystem relative to the OCI/Docker image it was installed "
            "from. Output uses Docker-style markers:"
            "\n\n"
            "  A  a file or directory was added\n"
            "  C  a file or directory was changed\n"
            "  D  a file or directory was deleted"
            "\n\n"
            "Pseudo-filesystem mount points (/dev, /proc, /sys, /run, /tmp) "
            "are excluded. Available only for containers installed from an "
            "image whose layers are still present in the cache."
        ),
        "options": [
            ("-h, --help", "Show this help."),
        ],
        "examples": [
            f"{PROGRAM_NAME} diff ubuntu",
        ],
    },
    "search": {
        "usage": "search [OPTIONS] TERM",
        "aliases": ("find", "se"),
        "summary": (
            "Search Docker Hub for images matching TERM. Prints the image "
            "name, star count, whether it is an official image, and a short "
            "description. Requires network access; does not require root."
        ),
        "options": [
            ("-h, --help", "Show this help."),
            ("-l, --limit [N]", "Maximum number of results to show (default: 25, max: 100)."),
            ("-q, --quiet", "Reserved for future use."),
        ],
        "examples": [
            f"{PROGRAM_NAME} search nextcloud",
            f"{PROGRAM_NAME} search --limit 50 ubuntu",
        ],
    },
    "info": {
        "usage": "info",
        "aliases": ("version-info", "nf"),
        "summary": (
            "Print a structured diagnostics report about the host and installed "
            "containers. Useful to attach when filing a bug report so issues can "
            "be reproduced and triaged faster."
            "\n\n"
            "The report covers five sections:"
            "\n\n"
            "  Program  chroot-distro version, Python version, data location.\n"
            "  Host     On Termux: Termux version, Android release/SDK, device. "
            "On Linux: distribution name/version, kernel, libc. Host CPU "
            "architecture and 32-bit support are shown in both cases.\n"
            "  Capabilities Host checks that affect launching containers: "
            "privilege-escalation tool (sudo/doas/pkexec/su), Termux /data "
            "suid/exec flags, binfmt_misc + QEMU for foreign architectures, "
            "unshare/nsenter and user-namespace support, free disk space on "
            "the data dir, download cache size, and SELinux/AppArmor mode.\n"
            "  Images   Every installed container with rootfs size, detected "
            "architecture, image source, busy/idle status, plus source URL and "
            "image type from manifest labels when available.\n"
            "  Analysis Lightweight checks per image: architecture mismatch "
            "against the host, missing manifest, empty or unusual rootfs."
            "\n\n"
            "Read-only. Like 'list' it is rootless on Termux, but elevates on "
            "regular Linux to read the root-owned data directory where "
            "containers are installed."
        ),
        "options": [
            ("-h, --help", "Show this help."),
        ],
        "examples": [
            f"{PROGRAM_NAME} info",
        ],
    },
    "sync": {
        "usage": "sync [OPTIONS] [DIST:]SRC [DIST:]DEST",
        "summary": (
            "Efficiently synchronize directory between host and container "
            "by copying only modified files and deleting those which "
            "absent in the source. Files compared by size and modification "
            "timestamp, however it is possible to use more strict "
            "verification by checksum."
            "\n\n"
            "Both source and destination may be a local path or a "
            "'container:path' reference."
        ),
        "options": [
            ("-h, --help", "Show this help."),
            (
                "-c, --checksum",
                "Compare files by size and CRC32 checksum instead of "
                "size and modification time. Slower but with high precision.",
            ),
            (
                "-d, --delete",
                "After syncing, remove destination files and "
                "directories that have no counterpart in the source. "
                "Only effective when source is a directory.",
            ),
            ("-v, --verbose", "Log each synced or deleted entry."),
            ("-q, --quiet", "Suppress non-error output. Mutually exclusive with --verbose."),
        ],
        "examples": [
            f"{PROGRAM_NAME} sync ./dotfiles/ ubuntu:/root/",
            f"{PROGRAM_NAME} sync --delete ./app/ ubuntu:/opt/app/",
        ],
    },
}


TOP_COMMANDS = [
    ("help", "Show this help."),
    ("install", "Install distribution from OCI image or rootfs archive."),
    ("list", "List created containers."),
    ("login", "Start interactive shell inside a container."),
    ("run", "Run container entrypoint in server or distroless images."),
    ("remove", "Delete a container.", "Destroys data!"),
    ("unmount", "Safely unmount a container."),
    ("rename", "Rename a container."),
    ("reset", "Reinstall a container from scratch.", "Destroys data!"),
    ("backup", "Save container as a TAR archive."),
    ("restore", "Restore container from a TAR archive.", "Destroys data!"),
    ("clear-cache", "Delete cached downloads."),
    ("copy", "Copy files from/to container."),
    ("sync", "Sync files from/to container."),
    ("build", "Build an OCI image from a Dockerfile."),
    ("push", "Push a locally built image to a registry."),
    ("ps", "List running containers."),
    ("kill", "Forcibly stop a running container."),
    ("diff", "Inspect filesystem changes in a container."),
    ("search", "Search Docker Hub for images."),
    ("info", "Show host and container diagnostics for bug reports."),
]

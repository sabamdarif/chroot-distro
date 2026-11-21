# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
# Fish completion for chroot-distro
#
# Install:
#   cp chroot-distro.fish ~/.config/fish/completions/chroot-distro.fish

# Fish before 3.5 needs a procfs lookup for the effective UID.
function __chroot_distro_containers
	set -l base
	if __chroot_distro_is_termux
		set -l prefix
		if set -q TERMUX__PREFIX
			set prefix $TERMUX__PREFIX
		else
			set prefix /data/data/com.termux/files/usr
		end
		set base "$prefix/var/lib"
	else if test -n "$XDG_DATA_HOME"
		set base "$XDG_DATA_HOME"
	else
		set -l euid "$EUID"
		if not set -q EUID; and test -r /proc/self/status; and string match -rq '^Uid:\s+\d+\s+0\s' </proc/self/status
			set euid 0
		end
		if test "$euid" = 0; and set -q HOME
			set base "$HOME/.local/share"
		else
			set base ~root/.local/share
			string match -q -- '/*' "$base"; or return
		end
	end
	for d in "$base/chroot-distro/containers"/*/
		if test -d "$d/rootfs"
			string replace -rf -- '(?s)\A.*/([A-Za-z0-9][A-Za-z0-9_.-]*)/\z' '$1' "$d"
		end
	end
end

# ---------------------------------------------------------------------------
# Termux/Android detection, mirroring _detect_termux() in constants.py.
# Returns 0 (true) when at least two of three independent indicators match.
# ---------------------------------------------------------------------------
function __chroot_distro_is_termux
    set -l score 0
    if test -f /system/build.prop; or test -d /data/app
        set score (math $score + 1)
    end
    if set -q TERMUX_APP__APP_VERSION_NAME; or set -q TERMUX_VERSION
        set score (math $score + 1)
    end
    set -l prefix
    if set -q TERMUX__PREFIX
        set prefix $TERMUX__PREFIX
    else
        set prefix /data/data/com.termux/files/usr
    end
    if test -r "$prefix" -a -x "$prefix"
        set score (math $score + 1)
    end
    test $score -ge 2
end

# ---------------------------------------------------------------------------
# Helpers: true when no subcommand has been seen yet, or when a given
# canonical command (including all parser aliases) is active.
# ---------------------------------------------------------------------------
function __chroot_distro_seen_command
	set -l tokens (commandline -opc)
	contains -- "$tokens[2]" $argv
end

function __chroot_distro_no_subcommand
	not __chroot_distro_seen_command \
        install add i in ins \
        remove rm \
        rename reset \
        login sh \
        list li ls \
        backup bak bkp \
        restore \
        clear-cache clear cl \
        copy cp \
        sync run build push \
        unmount umount um \
        kill k stop \
        ps diff \
        search find se \
        info version-info nf \
        help h he hel
end

function __chroot_distro_seen_install
	__chroot_distro_seen_command install add i in ins
end

function __chroot_distro_seen_remove
	__chroot_distro_seen_command remove rm
end

function __chroot_distro_seen_login
	__chroot_distro_seen_command login sh
end

function __chroot_distro_seen_list
	__chroot_distro_seen_command list li ls
end

function __chroot_distro_seen_backup
	__chroot_distro_seen_command backup bak bkp
end

function __chroot_distro_seen_clear_cache
	__chroot_distro_seen_command clear-cache clear cl
end

function __chroot_distro_seen_copy
	__chroot_distro_seen_command copy cp
end

function __chroot_distro_seen_unmount
	__chroot_distro_seen_command unmount umount um
end

function __chroot_distro_seen_kill
	__chroot_distro_seen_command kill k stop
end

function __chroot_distro_seen_ps
	__chroot_distro_seen_command ps
end

function __chroot_distro_seen_diff
	__chroot_distro_seen_command diff
end

function __chroot_distro_seen_search
	__chroot_distro_seen_command search find se
end

function __chroot_distro_seen_info
	__chroot_distro_seen_command info version-info nf
end

function __chroot_distro_seen_help
	__chroot_distro_seen_command help h he hel
end

# ---------------------------------------------------------------------------
# Subcommands (canonical names)
# ---------------------------------------------------------------------------
complete -c chroot-distro -f -n __chroot_distro_no_subcommand -a install     -d 'Install a container from a Docker image or local archive'
complete -c chroot-distro -f -n __chroot_distro_no_subcommand -a remove      -d 'Remove an installed container'
complete -c chroot-distro -f -n __chroot_distro_no_subcommand -a rename      -d 'Rename a container'
complete -c chroot-distro -f -n __chroot_distro_no_subcommand -a reset       -d 'Reinstall a container from its original image'
complete -c chroot-distro -f -n __chroot_distro_no_subcommand -a login       -d 'Open a shell inside a container'
complete -c chroot-distro -f -n __chroot_distro_no_subcommand -a list        -d 'List installed containers'
complete -c chroot-distro -f -n __chroot_distro_no_subcommand -a backup      -d 'Backup a container to a tar archive'
complete -c chroot-distro -f -n __chroot_distro_no_subcommand -a restore     -d 'Restore a container from a tar archive'
complete -c chroot-distro -f -n __chroot_distro_no_subcommand -a clear-cache -d 'Clear the download cache'
complete -c chroot-distro -f -n __chroot_distro_no_subcommand -a copy        -d 'Copy files between host and container'
complete -c chroot-distro -f -n __chroot_distro_no_subcommand -a sync        -d 'Synchronize files between host and container'
complete -c chroot-distro -f -n __chroot_distro_no_subcommand -a run         -d 'Run the image entrypoint/cmd in a container'
complete -c chroot-distro -f -n __chroot_distro_no_subcommand -a build       -d 'Build an OCI image from a Dockerfile'
complete -c chroot-distro -f -n __chroot_distro_no_subcommand -a push        -d 'Push a locally built image to a registry'
complete -c chroot-distro -f -n __chroot_distro_no_subcommand -a unmount     -d 'Unmount a container filesystem'
complete -c chroot-distro -f -n __chroot_distro_no_subcommand -a kill        -d 'Forcibly stop a running container'
complete -c chroot-distro -f -n __chroot_distro_no_subcommand -a ps          -d 'List active container sessions'
complete -c chroot-distro -f -n __chroot_distro_no_subcommand -a diff        -d 'Inspect filesystem changes in a container'
complete -c chroot-distro -f -n __chroot_distro_no_subcommand -a search      -d 'Search Docker Hub for images'
complete -c chroot-distro -f -n __chroot_distro_no_subcommand -a info        -d 'Show host and container diagnostics'
complete -c chroot-distro -f -n __chroot_distro_no_subcommand -a help        -d 'Show help'

# Subcommand aliases (mirrors parser.py)
complete -c chroot-distro -f -n __chroot_distro_no_subcommand -a add   -d 'Alias for install'
complete -c chroot-distro -f -n __chroot_distro_no_subcommand -a i     -d 'Alias for install'
complete -c chroot-distro -f -n __chroot_distro_no_subcommand -a in    -d 'Alias for install'
complete -c chroot-distro -f -n __chroot_distro_no_subcommand -a ins   -d 'Alias for install'
complete -c chroot-distro -f -n __chroot_distro_no_subcommand -a rm    -d 'Alias for remove'
complete -c chroot-distro -f -n __chroot_distro_no_subcommand -a sh     -d 'Alias for login'
complete -c chroot-distro -f -n __chroot_distro_no_subcommand -a li    -d 'Alias for list'
complete -c chroot-distro -f -n __chroot_distro_no_subcommand -a ls    -d 'Alias for list'
complete -c chroot-distro -f -n __chroot_distro_no_subcommand -a bak   -d 'Alias for backup'
complete -c chroot-distro -f -n __chroot_distro_no_subcommand -a bkp   -d 'Alias for backup'
complete -c chroot-distro -f -n __chroot_distro_no_subcommand -a clear -d 'Alias for clear-cache'
complete -c chroot-distro -f -n __chroot_distro_no_subcommand -a cl    -d 'Alias for clear-cache'
complete -c chroot-distro -f -n __chroot_distro_no_subcommand -a cp     -d 'Alias for copy'
complete -c chroot-distro -f -n __chroot_distro_no_subcommand -a umount -d 'Alias for unmount'
complete -c chroot-distro -f -n __chroot_distro_no_subcommand -a um    -d 'Alias for unmount'
complete -c chroot-distro -f -n __chroot_distro_no_subcommand -a k     -d 'Alias for kill'
complete -c chroot-distro -f -n __chroot_distro_no_subcommand -a stop  -d 'Alias for kill'
complete -c chroot-distro -f -n __chroot_distro_no_subcommand -a find  -d 'Alias for search'
complete -c chroot-distro -f -n __chroot_distro_no_subcommand -a se    -d 'Alias for search'
complete -c chroot-distro -f -n __chroot_distro_no_subcommand -a version-info -d 'Alias for info'
complete -c chroot-distro -f -n __chroot_distro_no_subcommand -a nf    -d 'Alias for info'
complete -c chroot-distro -f -n __chroot_distro_no_subcommand -a h     -d 'Alias for help'
complete -c chroot-distro -f -n __chroot_distro_no_subcommand -a he    -d 'Alias for help'
complete -c chroot-distro -f -n __chroot_distro_no_subcommand -a hel   -d 'Alias for help'

# Global flags (before subcommand)
complete -c chroot-distro -f -n __chroot_distro_no_subcommand -s h -l help        -d 'Show help'
complete -c chroot-distro -f -n __chroot_distro_no_subcommand -s V -l version     -d 'Print the version'

# ---------------------------------------------------------------------------
# install (+ aliases add, i, in, ins)
# ---------------------------------------------------------------------------
complete -c chroot-distro -f -n __chroot_distro_seen_install \
    -s n -l name       -r -d 'Install under a custom container name'
complete -c chroot-distro -f -n __chroot_distro_seen_install \
    -l override-alias -r -d 'Install under a custom container name'
complete -c chroot-distro -f -n __chroot_distro_seen_install \
    -s a -l architecture -r -d 'Target CPU architecture' \
    -a 'aarch64\tAArch64 arm\tARM(32-bit) i686\tx86(32-bit) riscv64\tRISC-V x86_64\tx86_64'
complete -c chroot-distro -f -n __chroot_distro_seen_install \
	-l allow-insecure -d 'Allow insecure transport when downloading'
complete -c chroot-distro -f -n __chroot_distro_seen_install \
    -s q -l quiet      -d 'Suppress non-error output'
complete -c chroot-distro -f -n __chroot_distro_seen_install \
    -s h -l help       -d 'Show help'

# ---------------------------------------------------------------------------
# remove (+ alias rm)
# ---------------------------------------------------------------------------
complete -c chroot-distro -f -n __chroot_distro_seen_remove \
    -a '(__chroot_distro_containers)' -d 'Container'
complete -c chroot-distro -f -n __chroot_distro_seen_remove \
    -s v -l verbose    -d 'Print each removed file'
complete -c chroot-distro -f -n __chroot_distro_seen_remove \
    -s q -l quiet      -d 'Suppress non-error output'
complete -c chroot-distro -f -n __chroot_distro_seen_remove \
    -s h -l help       -d 'Show help'

# ---------------------------------------------------------------------------
# rename
# ---------------------------------------------------------------------------
complete -c chroot-distro -f -n '__chroot_distro_seen_command rename' \
    -a '(__chroot_distro_containers)' -d 'Container'
complete -c chroot-distro -f -n '__chroot_distro_seen_command rename' \
    -s q -l quiet      -d 'Suppress non-error output'
complete -c chroot-distro -f -n '__chroot_distro_seen_command rename' \
    -s h -l help       -d 'Show help'

# ---------------------------------------------------------------------------
# reset
# ---------------------------------------------------------------------------
complete -c chroot-distro -f -n '__chroot_distro_seen_command reset' \
    -a '(__chroot_distro_containers)' -d 'Container'
complete -c chroot-distro -f -n '__chroot_distro_seen_command reset' \
    -s q -l quiet      -d 'Suppress non-error output'
complete -c chroot-distro -f -n '__chroot_distro_seen_command reset' \
    -s h -l help       -d 'Show help'

# ---------------------------------------------------------------------------
# login (+ alias sh)
# ---------------------------------------------------------------------------
complete -c chroot-distro -f -n __chroot_distro_seen_login \
    -a '(__chroot_distro_containers)' -d 'Container'
complete -c chroot-distro -f -n __chroot_distro_seen_login \
    -s u -l user       -r -d 'Run as this user (default: root)'
complete -c chroot-distro -f -n __chroot_distro_seen_login \
	-l isolated -l isolate -d 'Fewer host binds + mount/PID/UTS/IPC namespaces'
complete -c chroot-distro -f -n __chroot_distro_seen_login \
    -l minimal            -d 'Bare /dev, /proc, /sys only'
complete -c chroot-distro -f -n __chroot_distro_seen_login \
    -l shared-home        -d 'Bind host home into guest home'
complete -c chroot-distro -f -n __chroot_distro_seen_login \
    -l shared-tmp         -d 'Share /tmp with the host'
complete -c chroot-distro -f -n __chroot_distro_seen_login \
    -l shared-display     -d 'Share X11, Wayland, sound and D-Bus with the container'
complete -c chroot-distro -f -n __chroot_distro_seen_login \
    -l shared-x11         -d 'Alias for --shared-display (backward compatibility)'
complete -c chroot-distro -f -n __chroot_distro_seen_login \
    -l no-new-privs       -d 'Set PR_SET_NO_NEW_PRIVS: setuid binaries cannot elevate'
complete -c chroot-distro -n __chroot_distro_seen_login \
    -s b -l bind       -r -d 'Bind-mount PATH[:DEST] into the container (repeatable)'
complete -c chroot-distro -n __chroot_distro_seen_login \
    -s w -l work-dir   -r -d 'Initial working directory inside the container'
complete -c chroot-distro -f -n __chroot_distro_seen_login \
    -s e -l env        -r -d 'Set environment variable VAR=VALUE (repeatable)'
complete -c chroot-distro -f -n __chroot_distro_seen_login \
    -l get-chroot-cmd      -d 'Print the chroot command line and exit'
complete -c chroot-distro -f -n __chroot_distro_seen_login \
    -s h -l help          -d 'Show help'

# ---------------------------------------------------------------------------
# list (+ aliases li, ls)
# ---------------------------------------------------------------------------
complete -c chroot-distro -f -n __chroot_distro_seen_list \
    -s v -l verbose    -d 'Show image config details'
complete -c chroot-distro -f -n __chroot_distro_seen_list \
    -l json            -d 'Print one JSON document on stdout'
complete -c chroot-distro -f -n __chroot_distro_seen_list \
    -s q -l quiet      -d 'Suppress non-error output'
complete -c chroot-distro -f -n __chroot_distro_seen_list \
    -s h -l help       -d 'Show help'

# ---------------------------------------------------------------------------
# backup (+ aliases bak, bkp)
# ---------------------------------------------------------------------------
complete -c chroot-distro -f -n __chroot_distro_seen_backup \
    -a '(__chroot_distro_containers)' -d 'Container'
complete -c chroot-distro -n __chroot_distro_seen_backup \
    -s o -l output     -r -d 'Write archive to FILE instead of stdout'
complete -c chroot-distro -f -n __chroot_distro_seen_backup \
    -s c -l compress   -r -d 'Compression algorithm' \
    -a 'gzip\tgzip bzip2\tbzip2 xz\txz none\tNo compression'
complete -c chroot-distro -f -n __chroot_distro_seen_backup \
    -s v -l verbose    -d 'Print each archived file'
complete -c chroot-distro -f -n __chroot_distro_seen_backup \
    -s q -l quiet      -d 'Suppress non-error output'
complete -c chroot-distro -f -n __chroot_distro_seen_backup \
    -s h -l help       -d 'Show help'

# ---------------------------------------------------------------------------
# restore
# ---------------------------------------------------------------------------
complete -c chroot-distro -n '__chroot_distro_seen_command restore' \
    -s v -l verbose    -d 'Print each extracted file'
complete -c chroot-distro -n '__chroot_distro_seen_command restore' \
    -s q -l quiet      -d 'Suppress non-error output'
complete -c chroot-distro -n '__chroot_distro_seen_command restore' \
    -s h -l help       -d 'Show help'

# ---------------------------------------------------------------------------
# clear-cache (+ aliases clear, cl)
# ---------------------------------------------------------------------------
complete -c chroot-distro -f -n __chroot_distro_seen_clear_cache \
    -l build-cache     -d 'Drop the build cache index and the layers only it pinned'
complete -c chroot-distro -f -n __chroot_distro_seen_clear_cache \
    -l keep            -r -d 'Prune least-recently-used entries past SIZE'
complete -c chroot-distro -f -n __chroot_distro_seen_clear_cache \
    -s v -l verbose    -d 'List removed files'
complete -c chroot-distro -f -n __chroot_distro_seen_clear_cache \
    -s q -l quiet      -d 'Suppress non-error output'
complete -c chroot-distro -f -n __chroot_distro_seen_clear_cache \
    -s h -l help       -d 'Show help'

# ---------------------------------------------------------------------------
# copy (+ alias cp)
# ---------------------------------------------------------------------------
complete -c chroot-distro -f -n __chroot_distro_seen_copy \
    -a '(__chroot_distro_containers)' -d 'Container (use container:path notation)'
complete -c chroot-distro -f -n __chroot_distro_seen_copy \
    -s v -l verbose    -d 'Print each copied file'
complete -c chroot-distro -f -n __chroot_distro_seen_copy \
    -s q -l quiet      -d 'Suppress non-error output'
complete -c chroot-distro -f -n __chroot_distro_seen_copy \
    -s m -l move       -d 'Move instead of copy'
complete -c chroot-distro -f -n __chroot_distro_seen_copy \
    -s r -l recursive  -d 'Copy directories recursively'
complete -c chroot-distro -f -n __chroot_distro_seen_copy \
    -l chown -r        -d 'Give every copied entry this owner (USER[:GROUP])'
complete -c chroot-distro -f -n __chroot_distro_seen_copy \
    -s h -l help       -d 'Show help'

# ---------------------------------------------------------------------------
# sync
# ---------------------------------------------------------------------------
complete -c chroot-distro -f -n '__chroot_distro_seen_command sync' \
    -a '(__chroot_distro_containers)' -d 'Container (use container:path notation)'
complete -c chroot-distro -f -n '__chroot_distro_seen_command sync' \
    -s v -l verbose    -d 'Print each synced file'
complete -c chroot-distro -f -n '__chroot_distro_seen_command sync' \
    -s q -l quiet      -d 'Suppress non-error output'
complete -c chroot-distro -f -n '__chroot_distro_seen_command sync' \
    -s c -l checksum      -d 'Use CRC32 checksum instead of size+mtime'
complete -c chroot-distro -f -n '__chroot_distro_seen_command sync' \
    -s d -l delete        -d 'Remove destination entries absent from source'
complete -c chroot-distro -f -n '__chroot_distro_seen_command sync' \
    -l chown -r           -d 'Give every synced entry this owner (USER[:GROUP])'
complete -c chroot-distro -f -n '__chroot_distro_seen_command sync' \
    -s h -l help          -d 'Show help'

# ---------------------------------------------------------------------------
# run
# ---------------------------------------------------------------------------
complete -c chroot-distro -f -n '__chroot_distro_seen_command run' \
    -a '(__chroot_distro_containers)' -d 'Container'
complete -c chroot-distro -f -n '__chroot_distro_seen_command run' \
    -s u -l user       -r -d 'Run as this user (default: root)'
complete -c chroot-distro -f -n '__chroot_distro_seen_command run' \
	-l isolated -l isolate -d 'Fewer host binds + mount/PID/UTS/IPC namespaces'
complete -c chroot-distro -f -n '__chroot_distro_seen_command run' \
    -l minimal            -d 'Bare /dev, /proc, /sys only'
complete -c chroot-distro -f -n '__chroot_distro_seen_command run' \
    -l shared-home        -d 'Bind host home into guest home'
complete -c chroot-distro -f -n '__chroot_distro_seen_command run' \
    -l shared-tmp         -d 'Share /tmp with the host'
complete -c chroot-distro -f -n '__chroot_distro_seen_command run' \
    -l shared-display     -d 'Share X11, Wayland, sound and D-Bus with the container'
complete -c chroot-distro -f -n '__chroot_distro_seen_command run' \
    -l shared-x11         -d 'Alias for --shared-display (backward compatibility)'
complete -c chroot-distro -f -n '__chroot_distro_seen_command run' \
    -l no-new-privs       -d 'Set PR_SET_NO_NEW_PRIVS: setuid binaries cannot elevate'
complete -c chroot-distro -n '__chroot_distro_seen_command run' \
    -s b -l bind       -r -d 'Bind-mount PATH[:DEST] into the container (repeatable)'
complete -c chroot-distro -n '__chroot_distro_seen_command run' \
    -s w -l work-dir   -r -d 'Initial working directory inside the container'
complete -c chroot-distro -f -n '__chroot_distro_seen_command run' \
    -s e -l env        -r -d 'Set environment variable VAR=VALUE (repeatable)'
complete -c chroot-distro -f -n '__chroot_distro_seen_command run' \
    -l entrypoint      -r -d 'Replace the image entrypoint for this run (Cmd cleared)'
complete -c chroot-distro -f -n '__chroot_distro_seen_command run' \
    -s d -l detach        -d 'Run the command in the background and return immediately'
complete -c chroot-distro -f -n '__chroot_distro_seen_command run' \
    -l get-chroot-cmd      -d 'Print the chroot command line and exit'
complete -c chroot-distro -f -n '__chroot_distro_seen_command run' \
    -s h -l help          -d 'Show help'

# ---------------------------------------------------------------------------
# build
# ---------------------------------------------------------------------------
complete -c chroot-distro -n '__chroot_distro_seen_command build' \
    -s f -l file       -r -d 'Path to Dockerfile (- reads from stdin)'
complete -c chroot-distro -f -n '__chroot_distro_seen_command build' \
    -s t -l tag        -r -d 'Image reference to assign (repeatable)'
complete -c chroot-distro -f -n '__chroot_distro_seen_command build' \
    -l build-arg       -r -d 'Set a build-time ARG (repeatable)'
complete -c chroot-distro -f -n '__chroot_distro_seen_command build' \
    -l build-context   -r -d 'Define a named build context (repeatable)'
complete -c chroot-distro -f -n '__chroot_distro_seen_command build' \
    -s a -l architecture -r -d 'Target CPU architecture' \
    -a 'aarch64\tAArch64 arm\tARM(32-bit) i686\tx86(32-bit) riscv64\tRISC-V x86_64\tx86_64'
complete -c chroot-distro -f -n '__chroot_distro_seen_command build' \
    -l platform       -r -d 'Build one image per platform (comma-separated, repeatable)' \
    -a 'linux/amd64 linux/arm64 linux/arm/v7 linux/386 linux/riscv64'
complete -c chroot-distro -f -n '__chroot_distro_seen_command build' \
    -l target          -r -d 'Stop after this named build stage'
complete -c chroot-distro -n '__chroot_distro_seen_command build' \
    -s o -l output     -r -d 'Write OCI tarball to FILE (repeatable)'
complete -c chroot-distro -f -n '__chroot_distro_seen_command build' \
    -l export          -r -d 'Export the rootfs as a directory or tarball (repeatable)' \
    -a 'type=local,dest= type=tar,dest='
complete -c chroot-distro -f -n '__chroot_distro_seen_command build' \
	-l install-as      -r -d 'Install image as a local container after build'
complete -c chroot-distro -f -n '__chroot_distro_seen_command build' \
    -l secret          -r -d 'Expose a secret to RUN --mount=type=secret (repeatable)'
complete -c chroot-distro -f -n '__chroot_distro_seen_command build' \
    -l ssh                -d 'Expose an SSH agent socket to RUN --mount=type=ssh (repeatable)'
complete -c chroot-distro -f -n '__chroot_distro_seen_command build' \
    -l cache-from      -r -d 'Import cached steps (repeatable)' \
    -a 'type=local,src= type=registry,ref='
complete -c chroot-distro -f -n '__chroot_distro_seen_command build' \
    -l cache-to        -r -d 'Export the cached steps of this build (repeatable)' \
    -a 'type=local,dest= type=registry,ref='
complete -c chroot-distro -f -n '__chroot_distro_seen_command build' \
	-l allow-insecure -d 'Allow insecure transport for registry build cache'
complete -c chroot-distro -f -n '__chroot_distro_seen_command build' \
    -l no-cache           -d 'Disable per-instruction build cache'
complete -c chroot-distro -f -n '__chroot_distro_seen_command build' \
    -l progress        -r -d 'Build output style' \
    -a 'auto plain tty rawjson'
complete -c chroot-distro -f -n '__chroot_distro_seen_command build' \
    -s v -l verbose       -d 'Echo each instruction and stream RUN output'
complete -c chroot-distro -f -n '__chroot_distro_seen_command build' \
    -s q -l quiet         -d 'Suppress non-error output'
complete -c chroot-distro -f -n '__chroot_distro_seen_command build' \
    -s h -l help          -d 'Show help'

# ---------------------------------------------------------------------------
# push
# ---------------------------------------------------------------------------
complete -c chroot-distro -f -n '__chroot_distro_seen_command push' \
    -s a -l architecture -r -d 'Target CPU architecture' \
    -a 'aarch64\tAArch64 arm\tARM(32-bit) i686\tx86(32-bit) riscv64\tRISC-V x86_64\tx86_64'
complete -c chroot-distro -f -n '__chroot_distro_seen_command push' \
	-l allow-insecure -d 'Allow insecure transport for the target registry'
complete -c chroot-distro -f -n '__chroot_distro_seen_command push' \
    -s q -l quiet      -d 'Suppress non-error output'
complete -c chroot-distro -f -n '__chroot_distro_seen_command push' \
    -s h -l help       -d 'Show help'

# ---------------------------------------------------------------------------
# unmount (+ aliases umount, um)
# ---------------------------------------------------------------------------
complete -c chroot-distro -f -n __chroot_distro_seen_unmount \
    -a '(__chroot_distro_containers)' -d 'Container'
complete -c chroot-distro -f -n __chroot_distro_seen_unmount \
    -s h -l help       -d 'Show help'

# ---------------------------------------------------------------------------
# kill (+ aliases k, stop)
# ---------------------------------------------------------------------------
complete -c chroot-distro -f -n __chroot_distro_seen_kill \
    -a '(__chroot_distro_containers)' -d 'Container'
complete -c chroot-distro -f -n __chroot_distro_seen_kill \
    -s h -l help       -d 'Show help'

# ---------------------------------------------------------------------------
# ps
# ---------------------------------------------------------------------------
complete -c chroot-distro -f -n __chroot_distro_seen_ps \
    -l json            -d 'Print one JSON document on stdout'
complete -c chroot-distro -f -n __chroot_distro_seen_ps \
    -s q -l quiet      -d 'Print only PIDs'
complete -c chroot-distro -f -n __chroot_distro_seen_ps \
    -s h -l help       -d 'Show help'

# ---------------------------------------------------------------------------
# diff
# ---------------------------------------------------------------------------
complete -c chroot-distro -f -n __chroot_distro_seen_diff \
    -a '(__chroot_distro_containers)' -d 'Container'
complete -c chroot-distro -f -n __chroot_distro_seen_diff \
    -l json            -d 'Print one JSON document on stdout'
complete -c chroot-distro -f -n __chroot_distro_seen_diff \
    -s h -l help       -d 'Show help'

# ---------------------------------------------------------------------------
# search (+ aliases find, se)
# ---------------------------------------------------------------------------
complete -c chroot-distro -f -n __chroot_distro_seen_search \
    -s l -l limit      -r -d 'Maximum number of results (default 25, max 100)'
complete -c chroot-distro -f -n __chroot_distro_seen_search \
    -s q -l quiet      -d 'Reserved for future use'
complete -c chroot-distro -f -n __chroot_distro_seen_search \
    -s h -l help       -d 'Show help'

# ---------------------------------------------------------------------------
# info (+ aliases version-info, nf)
# ---------------------------------------------------------------------------
complete -c chroot-distro -f -n __chroot_distro_seen_info \
    -l json            -d 'Print the report as one JSON document on stdout'
complete -c chroot-distro -f -n __chroot_distro_seen_info \
    -s h -l help       -d 'Show help'

# ---------------------------------------------------------------------------
# help (+ aliases h, he, hel)
# ---------------------------------------------------------------------------
complete -c chroot-distro -f -n __chroot_distro_seen_help \
	-a 'install add i in ins remove rm rename reset login sh list li ls backup bak bkp restore clear-cache clear cl copy cp sync run build push unmount umount um kill k stop ps diff search find se info version-info nf help h he hel' \
	-d 'Topic'
complete -c chroot-distro -f -n __chroot_distro_seen_help \
	-s h -l help -d 'Show help'

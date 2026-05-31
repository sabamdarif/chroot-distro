# Fish completion for chroot-distro
#
# Install:
#   cp chroot-distro.fish ~/.config/fish/completions/chroot-distro.fish

# ---------------------------------------------------------------------------
# Helper: resolve installed containers directory
# ---------------------------------------------------------------------------
function __chroot_distro_containers
    set -l dir
    if __chroot_distro_is_termux
        set -l prefix
        if set -q TERMUX__PREFIX
            set prefix $TERMUX__PREFIX
        else
            set prefix /data/data/com.termux/files/usr
        end
        set dir "$prefix/var/lib/chroot-distro/containers"
    else if set -q XDG_DATA_HOME
        set dir "$XDG_DATA_HOME/chroot-distro/containers"
    else
        set dir "$HOME/.local/share/chroot-distro/containers"
    end
    if test -d "$dir"
        for d in "$dir"/*/
            set -l name (basename "$d")
            if test -d "$dir/$name/rootfs"
                echo $name
            end
        end
    end
end

# ---------------------------------------------------------------------------
# Termux/Android detection — mirrors _detect_termux() in constants.py.
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
function __chroot_distro_no_subcommand
    not __fish_seen_subcommand_from \
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
        help h he hel
end

function __chroot_distro_seen_install
    __fish_seen_subcommand_from install add i in ins
end

function __chroot_distro_seen_remove
    __fish_seen_subcommand_from remove rm
end

function __chroot_distro_seen_login
    __fish_seen_subcommand_from login sh
end

function __chroot_distro_seen_list
    __fish_seen_subcommand_from list li ls
end

function __chroot_distro_seen_backup
    __fish_seen_subcommand_from backup bak bkp
end

function __chroot_distro_seen_clear_cache
    __fish_seen_subcommand_from clear-cache clear cl
end

function __chroot_distro_seen_copy
    __fish_seen_subcommand_from copy cp
end

function __chroot_distro_seen_unmount
    __fish_seen_subcommand_from unmount umount um
end

function __chroot_distro_seen_help
    __fish_seen_subcommand_from help h he hel
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
complete -c chroot-distro -f -n __chroot_distro_no_subcommand -a h     -d 'Alias for help'
complete -c chroot-distro -f -n __chroot_distro_no_subcommand -a he    -d 'Alias for help'
complete -c chroot-distro -f -n __chroot_distro_no_subcommand -a hel   -d 'Alias for help'

# Global flags (before subcommand)
complete -c chroot-distro -f -n __chroot_distro_no_subcommand -s h -l help        -d 'Show help'
complete -c chroot-distro -f -n __chroot_distro_no_subcommand -l no-elevate     -d 'Do not auto-elevate to root'
complete -c chroot-distro -f -n __chroot_distro_no_subcommand -l use-sudo       -d 'On Termux, prefer sudo over su'

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
complete -c chroot-distro -f -n '__fish_seen_subcommand_from rename' \
    -a '(__chroot_distro_containers)' -d 'Container'
complete -c chroot-distro -f -n '__fish_seen_subcommand_from rename' \
    -s q -l quiet      -d 'Suppress non-error output'
complete -c chroot-distro -f -n '__fish_seen_subcommand_from rename' \
    -s h -l help       -d 'Show help'

# ---------------------------------------------------------------------------
# reset
# ---------------------------------------------------------------------------
complete -c chroot-distro -f -n '__fish_seen_subcommand_from reset' \
    -a '(__chroot_distro_containers)' -d 'Container'
complete -c chroot-distro -f -n '__fish_seen_subcommand_from reset' \
    -s q -l quiet      -d 'Suppress non-error output'
complete -c chroot-distro -f -n '__fish_seen_subcommand_from reset' \
    -s h -l help       -d 'Show help'

# ---------------------------------------------------------------------------
# login (+ alias sh)
# ---------------------------------------------------------------------------
complete -c chroot-distro -f -n __chroot_distro_seen_login \
    -a '(__chroot_distro_containers)' -d 'Container'
complete -c chroot-distro -f -n __chroot_distro_seen_login \
    -s u -l user       -r -d 'Run as this user (default: root)'
complete -c chroot-distro -f -n __chroot_distro_seen_login \
    -l isolated           -d 'Fewer host binds + mount/PID/UTS/IPC namespaces'
complete -c chroot-distro -f -n __chroot_distro_seen_login \
    -l minimal            -d 'Bare /dev, /proc, /sys only'
complete -c chroot-distro -f -n __chroot_distro_seen_login \
    -l shared-home        -d 'Bind host home into guest home'
complete -c chroot-distro -f -n __chroot_distro_seen_login \
    -l shared-tmp         -d 'Share /tmp with the host'
complete -c chroot-distro -f -n __chroot_distro_seen_login \
    -l shared-x11         -d 'Share the X11 socket (/tmp/.X11-unix)'
complete -c chroot-distro -n __chroot_distro_seen_login \
    -s b -l bind       -r -d 'Bind-mount PATH[:DEST] into the container (repeatable)'
complete -c chroot-distro -f -n __chroot_distro_seen_login \
    -l hostname        -r -d 'Hostname visible inside the container'
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
complete -c chroot-distro -n '__fish_seen_subcommand_from restore' \
    -s v -l verbose    -d 'Print each extracted file'
complete -c chroot-distro -n '__fish_seen_subcommand_from restore' \
    -s q -l quiet      -d 'Suppress non-error output'
complete -c chroot-distro -n '__fish_seen_subcommand_from restore' \
    -s h -l help       -d 'Show help'

# ---------------------------------------------------------------------------
# clear-cache (+ aliases clear, cl)
# ---------------------------------------------------------------------------
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
    -s h -l help       -d 'Show help'

# ---------------------------------------------------------------------------
# sync
# ---------------------------------------------------------------------------
complete -c chroot-distro -f -n '__fish_seen_subcommand_from sync' \
    -a '(__chroot_distro_containers)' -d 'Container (use container:path notation)'
complete -c chroot-distro -f -n '__fish_seen_subcommand_from sync' \
    -s v -l verbose    -d 'Print each synced file'
complete -c chroot-distro -f -n '__fish_seen_subcommand_from sync' \
    -s q -l quiet      -d 'Suppress non-error output'
complete -c chroot-distro -f -n '__fish_seen_subcommand_from sync' \
    -s c -l checksum      -d 'Use CRC32 checksum instead of size+mtime'
complete -c chroot-distro -f -n '__fish_seen_subcommand_from sync' \
    -s d -l delete        -d 'Remove destination entries absent from source'
complete -c chroot-distro -f -n '__fish_seen_subcommand_from sync' \
    -s h -l help          -d 'Show help'

# ---------------------------------------------------------------------------
# run
# ---------------------------------------------------------------------------
complete -c chroot-distro -f -n '__fish_seen_subcommand_from run' \
    -a '(__chroot_distro_containers)' -d 'Container'
complete -c chroot-distro -f -n '__fish_seen_subcommand_from run' \
    -s u -l user       -r -d 'Run as this user (default: root)'
complete -c chroot-distro -f -n '__fish_seen_subcommand_from run' \
    -l isolated           -d 'Fewer host binds + mount/PID/UTS/IPC namespaces'
complete -c chroot-distro -f -n '__fish_seen_subcommand_from run' \
    -l minimal            -d 'Bare /dev, /proc, /sys only'
complete -c chroot-distro -f -n '__fish_seen_subcommand_from run' \
    -l shared-home        -d 'Bind host home into guest home'
complete -c chroot-distro -f -n '__fish_seen_subcommand_from run' \
    -l shared-tmp         -d 'Share /tmp with the host'
complete -c chroot-distro -f -n '__fish_seen_subcommand_from run' \
    -l shared-x11         -d 'Share the X11 socket (/tmp/.X11-unix)'
complete -c chroot-distro -n '__fish_seen_subcommand_from run' \
    -s b -l bind       -r -d 'Bind-mount PATH[:DEST] into the container (repeatable)'
complete -c chroot-distro -f -n '__fish_seen_subcommand_from run' \
    -l hostname        -r -d 'Hostname visible inside the container'
complete -c chroot-distro -n '__fish_seen_subcommand_from run' \
    -s w -l work-dir   -r -d 'Initial working directory inside the container'
complete -c chroot-distro -f -n '__fish_seen_subcommand_from run' \
    -s e -l env        -r -d 'Set environment variable VAR=VALUE (repeatable)'
complete -c chroot-distro -f -n '__fish_seen_subcommand_from run' \
    -l get-chroot-cmd      -d 'Print the chroot command line and exit'
complete -c chroot-distro -f -n '__fish_seen_subcommand_from run' \
    -s h -l help          -d 'Show help'

# ---------------------------------------------------------------------------
# build
# ---------------------------------------------------------------------------
complete -c chroot-distro -n '__fish_seen_subcommand_from build' \
    -s f -l file       -r -d 'Path to Dockerfile (- reads from stdin)'
complete -c chroot-distro -f -n '__fish_seen_subcommand_from build' \
    -s t -l tag        -r -d 'Image reference to assign (repeatable)'
complete -c chroot-distro -f -n '__fish_seen_subcommand_from build' \
    -l build-arg       -r -d 'Set a build-time ARG (repeatable)'
complete -c chroot-distro -f -n '__fish_seen_subcommand_from build' \
    -s a -l architecture -r -d 'Target CPU architecture' \
    -a 'aarch64\tAArch64 arm\tARM(32-bit) i686\tx86(32-bit) riscv64\tRISC-V x86_64\tx86_64'
complete -c chroot-distro -f -n '__fish_seen_subcommand_from build' \
    -l target          -r -d 'Stop after this named build stage'
complete -c chroot-distro -n '__fish_seen_subcommand_from build' \
    -s o -l output     -r -d 'Write OCI tarball to FILE (repeatable)'
complete -c chroot-distro -f -n '__fish_seen_subcommand_from build' \
    -l install-as      -r -d 'Install image as a local container after build' \
    -a '(__chroot_distro_containers)'
complete -c chroot-distro -f -n '__fish_seen_subcommand_from build' \
    -l no-cache           -d 'Disable per-instruction build cache'
complete -c chroot-distro -f -n '__fish_seen_subcommand_from build' \
    -s v -l verbose       -d 'Echo each instruction and stream RUN output'
complete -c chroot-distro -f -n '__fish_seen_subcommand_from build' \
    -s q -l quiet         -d 'Suppress non-error output'
complete -c chroot-distro -f -n '__fish_seen_subcommand_from build' \
    -s h -l help          -d 'Show help'

# ---------------------------------------------------------------------------
# push
# ---------------------------------------------------------------------------
complete -c chroot-distro -f -n '__fish_seen_subcommand_from push' \
    -s a -l architecture -r -d 'Target CPU architecture' \
    -a 'aarch64\tAArch64 arm\tARM(32-bit) i686\tx86(32-bit) riscv64\tRISC-V x86_64\tx86_64'
complete -c chroot-distro -f -n '__fish_seen_subcommand_from push' \
    -s q -l quiet      -d 'Suppress non-error output'
complete -c chroot-distro -f -n '__fish_seen_subcommand_from push' \
    -s h -l help       -d 'Show help'

# ---------------------------------------------------------------------------
# unmount (+ aliases umount, um)
# ---------------------------------------------------------------------------
complete -c chroot-distro -f -n __chroot_distro_seen_unmount \
    -a '(__chroot_distro_containers)' -d 'Container'
complete -c chroot-distro -f -n __chroot_distro_seen_unmount \
    -s h -l help       -d 'Show help'

# ---------------------------------------------------------------------------
# help (+ aliases h, he, hel)
# ---------------------------------------------------------------------------
complete -c chroot-distro -f -n __chroot_distro_seen_help \
    -a 'install remove rename reset login list backup restore clear-cache copy sync run build push unmount' \
    -d 'Topic'

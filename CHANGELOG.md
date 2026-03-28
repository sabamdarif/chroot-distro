# Changelog

### v1.5.5

- fix(chroot-distro/command_install): extract the rootfs with proper permission
- style(ci): format all workflow files
- fix(chroot-distro): embed status.sh into the main script bacause status.sh wasn't working on some device
- fix(chroot-distro): read current mount options and only remount if nosuid is actually set
- fix(chroot-distro/command_remove): verify all mounts are actually gone before doing rm -rf
- feat(download): add Termux fallback download methods (#37)
- feat(webui): make start,stop,uninstall button follow material ui color
- manjaro: bump to 20260309 (#33)
- debian: bump to 13.4 (#34)
- archlinux: bump to 2026.03.01 (#35)
- feat(webui): rename `Enable Serviced` to `Enable Serviced Autostart`
- feat(webui): update distro config icon to a linux icon
- fix(webui): hide the search button on distro config page and hide both buttons in main settings page
- feat(webui): put distro specfic settings in a seperate page
- feat(chroot-distro): now use seperate folder called mounts inside DATA_DIR where it will store all the mount points data
- feat(chroot-distro): do not depend on get_isolated_tracker_file for --isolated option
- docs: update README credits and add GPL-v3 license and author information in serviced
- feat(serviced): v0.1.7: now supports help, cat, kill also now it will scan the user folders for systemd services files
- feat(serviced): v0.1.6, now you can launch few systemd services
- feat(webui): add option in the distro's settings page to manage non-root users

### v1.5.4

- feat(serviced): version 0.1.5
- docs(readme): Remove kernel compatibility check instructions
- feat(webui): add option to change short order
- feat(webui): remove the save and cancel button from login settings dialog now it will autosave
- fix(chroot-distro): don't use safe_mount for temporary mount
- feat(webui): add option to configure login options (flags) from the webui
- feat(chroot-distro): complete the JOSINIFY=true option
- feat(webui): add option to skip user creation during installation
- feat(webui): add a dialog to input username and password info for new user
- fix(chroot-distro): disable needrestart's interactive prompts and warnings
- fix(chroot-distro/command_login): remount /data with suid to allow non-root sudo
- feat(chroot-distro): add option to create normal user during installation
- feat(webui): add option to disable phantom process killer
- feat(chroot-distro/command_login): prompt the user to install the distro if the distro he want to login isn't installed
- docs: update README.md
- manjaro: bump to 20260223 (#29)

### v1.5.3

- fix(ci/check_distro_versions): check latest version for void from /live/current/
- fix(ci/publish-distro): run `git pull --rebase origin main` before push
- feat(ci/build-distro): don't cancel old build on multiple commit
- trisquel: bump to 12.0 (#23)
- archlinux: bump to 2026.02.01 (#26)
- rockylinux: bump to 10.1 (#24)
- manjaro: bump to 20260216 (#25)
- feat(ci): improve distro auto update
- fix(ci/checkup-and-release): only run `Create Release` if the event_name == 'push'
- fix(chroot-distro): fix network problems in isolated envoronments and get that working (#21)
- feat(chroot-distro): adding bluetooth groops per default to user and add new --isolated to command_login (#19)
- feat(chroot-distro): instead /bin/su -P use setpriv or setsid + su and /bin/su -P as a fallback
- fix(chroot-distro): Adding other relevant android specific User and Group ID's (#14)
- refactor(chroot-distro): busybox everywhere
- fix(chroot-disttro): properly restore /data permission
- docs: update README.md add a docker and flatpak guide
- feat(ci): add new workflow to auto update the distro versions
- fix(chroot-distro): Fix when allowing suid rules (#13)

### v1.5.2

- feat(ci/checkup-and-release): don't create the chore: update files for release commit on relase instead it will do `git commit --amend --no-edit` and force push
- feat(ci/checkup-and-release): skip all commit from github-actions[bot] when generating changelog
- adddistro: archlinux (#12)
- adddistro: void (#11)
- feat(ci/build-distro): improve trigger rules
- fix(ci/publish-distro): don't remove existing data from distros.json
- fix(ci/build-distro): don't run release on pull_request
- adddistro: kali (#10)
- fix(ci/plan-build): don't build all distro when i just add one
- fix(ci/build-rootfs): install missing debootstrap
- refactor(ci/build-distro): divide into smaller chunks
- fix(ci/build-distro): fix error from function 'fromJson': Unexpected symbol: 'alpine'
- fix: disable archlinux, kali, void for now
- feat(ci/build-distro): run build using matrix
- ci(build-distro & checkup-and-release): update build trigger rules
- fix: fix debian build issue
- fix: fix serviced.py not found error
- fix: fix archlinux build issue
- feat: add option to build rootfs (based on proot-distro)
- feat: change project structure
- fix(ci/update-distro): fix serviced inject issue
- docs: add serviced and settings guide
- feat(serviced): improve dependency detection
- feat(chroot-distro): set setuid on bwrap if missing to enable Flatpak support
- feat(chroot-distro): remove `Kill stale Docker processes` section, it's handled by serviced
- feat(chroot-distroo & webui): add support for saveing the SERVICED and SERVICED VERBOSE MODE in settings.conf file
- feat(serviced): just use VERBOSE
- feat(chroot-distro): add new option to auto start enabled process on login
- fix(serviced): pass pyright and mising comments
- fix(ci/update-distro): fix distro build issue
- feat: add serviced a simple alternative to systemctl
- feat(chroot-distro): improve docker support
- feat(chroot-distro): make some improvement so we can run docker

### v1.5.1

- swap(chroot-distro): remove awk-jq and add a simple regex inside chroot-distro
- fix(Readme): fix acknowledgments links
- feat(webui): implement log persistence
- fix(chroot-distro): check for /etc folder to consider a distro is fully installed
- feat(webui): only make the middle section scroll
- feat(ci/checkup-and-release): add a option always bbuild a artifact also now use a build.sh to build the module
- style: cleanup
- docs: update readme

### v1.5.0

- feat(ci/checkup-and-release): generate log only from last numbered tag
- feat(webui): add search button
- feat(chroor-distro): improve chroot-distro list loading speed
- fix(webui): add the missing spin animation
- feat(chroot-distro/init_distros_data): compare hash before copy
- chore: update distros.json with latest versions [skip ci]
- feat(ci/update-distro.yml): run on each canges on update-distro.yml
- fix(chroot-distro): pass shellcheck, resolve SC3043 warning
- adddistro: alpine, manjaro, opensuse, rockylinux, trisquel
- feat(webui): add option to show version info in the webui
- feat(chroot-distro): check before and after copy that the file isn't a empty file
- feat: create minimal jq using awk and use that to capture json data
- chore: update distros.json with latest versions [skip ci]
- fix(ci): fix json process issue
- chore: update distros.json with latest versions [skip ci]
- feat: improve how it used to manage distro
- drop: remove ubuntu-lts

### v1.4.9

- feat(chroot-distro): add download_file to first try curl and if doesn't exist then try busybox wget
- feat(webui): implement a settings page and improve the ui
- feat(webui): remove the terminalSpinner
- feat(webui): play a animation when removing a distro
- feat(webui): add a download animation onn the install button
- feat(webui): add refresh button
- fix: remove the check using mount command in list_running as it will not work under webui
- feat: update workflow to build webui
- feat: add initial webui support
- feat: add new list-running option
- feat: add a option to print the data in a json format

### v1.4.8

- feat: add option to dynamically show distro related data in module description
- refactor: run normal user network fixes in command_login instead of command_install, move the unmount message to cleanup_all_mounts
- feat: improve safe_mount to specify fs_type and mount_opts

### v1.4.7

- feat: refactor the code replace all the termux related path with variables, and fix for --termux-home and --work-dir it wasn't restoring the permission of TERMUX_HOME after exit
- feat: better error handling when using --termux-home or --work-dir
- fix: create /run/resolvconf folder if doesn't exist
- style: don't hardcode REPO_NAME and PROGRAM_NAME and REPO_WONER
- fix: command_unmount always saying `Still some mount points found`
- fix: fix when using --work-dir without --termux-home we can't access anything from /data/data/com.termux/files/
- fix: sub directory access issue in --termux-home for non root users
- fix: normal user can't use --termux-home
- fix: fix apt internet connection issue
- feat: simplify the dns setup
- feat: add support for multiple session and auto unmount after all sessions are closed
- ci: don't zip .editorconfig in the module
- style: change default indent_style to tab
- fix: make sure all mounted points are get printed in mount tracker file
- refactor: replace all chroot "${INSTALLED_ROOTFS_DIR}/${distro_name}" COMMAND with run_chroot_cmd
- refactor: simplify resolv.conf setup
- fix(command_install): fix resolv.conf link issue

### v1.4.6

- feat: use separate mount.points for each distro
- fix: shellcheck SC2013
- feat: improve unmount logic, improve network setup, anf few more improvements
- feat: add /apex to mount, add some useful exports to /etc/profile, share termux home on --shared-tmp
- fix(ubuntu): messagebus group and user if missing, add missing root in group
- fix: fix _apt permissions and ownership issue

### v1.4.5

- fix: pass shellcheck
- feat: add a ci/cd to shellcheck and release new version
- feat: add option to run specfic configuration after install
- fix: remove auto unmount after login, it was causing issue

### v1.4.4

- better handle color variables
- adddistro: ubuntu-lts

### v1.4.3

- fix: mount /dev in the install part so fix any cannot create /dev/null error
- refactor: use more busybox

### v1.4.2

- fix: correct kali's download urls
- improve: improve the way it use to pass arguments in chroot

### v1.4.1

- remove unnecessary checks
- fix exec_command doesn't work sometime
- improve how it was download the rootfs
    - now it will always download the latest vesion

### v1.4

- docs: update readme
- add: kali linux
- fix: bash: cannot set terminal process group
    - use the `su -P` to fix the below error
      bash: cannot set terminal process group (4979): Inappropriate ioctl for device
      bash: no job control in this shell
      get it from here :- https://serverfault.com/a/1144764
- remove: unnecessary mounts
- remove: unnecessary group register
- add: /dev/pts mount instead of creating a new isolated devpts
- add: more checks
- merge: --force and normal unmount into one
- properly add /etc/group
- restore termux TMPDIR ownership after using it
- improve: change help menus designs
- improve: gid register process
- improve: /dev/shm mount logic
- fix: /dev/shm permission issue

### v1.3

- improve: mount /proc/self/fd folders only if they exist
- fix: remove the if block around suid mount
- improve: always create a new tmpfs then mount to /tmp
- fix: --termux-home permission denied issue
- update: debian to debian 13 (trixie)
- fix: if you use --termux-home make sure it resore the ownership of Termux Home to termux again
- improve: rely more on busybox, add an option to check that all required commands are available

### v1.1.2

- fix: fix wrong permission for /tmp

### v1.1.1

- fs: increase dev/shm size to 512M
    - 256Mb is too low so some app might now run properly that's why i increase it to 512Mb
- fix(archlinux): fix archlinux repo update error
- chor: update fedora to latest version
- docs: update readme
- refactor: use busybox for more task - chnage `curl` to `busybox wget` because some system just doesn't have
  curl on it - chnage `grep` to `busybox grep

### v1.1

- fix: add missing clear cache option, proper handle command_install
- feat: add function to set right permission before mount, fix some mount paths
- docs: update readme
- style: add some comments and rearrange few stuff
- fix: chnage fuser busybox fuser because there is no fuser in toybox
- feat: add a uninstall script to safely unmount the install distro and remove them

### v1.0.1

- fix: error bash: no job control in this shell when using --user flag
- feat: improve the mount and unmount points
- feat: better handle --shared-tmp
- docs: update readme

### v1.0

- fix: --work-dir not working, drop: --env option
- feat: add /data to mount point, so that it can access /data/data/com.termux/
- docs: improve the readme
- fix: the `--` parameter
    - Ex:- `chroot-distro login ubuntu --shared-tmp -- env DISPLAY=:0 apt update`
      `chroot-distro login ubuntu --shared-tmp -- /bin/sh -c 'apt update'`
      `chroot-distro login ubuntu --shared-tmp -- eval "env DISPLAY=:0 apt update"`
      will work now
- fix: mount /dev/pts to fix errors for some programs
- fix: set locale to avoid perl warnings about missing locales
- feat: make some android specific configurations so it can interact better with the android host
- fix: suid issue
- fix: safe_mount directory crate issue
- feat: update command_unmount_system_points to unmount all mount points

### v1.0-beta2

- add: a new option `unmount` to unmount the installed distro
    - Ex:- `chroot-distro unmount ubuntu`
- add: the missing install help menu
- add: the missing main help menu
- fix: busybox checks
- fix: cannot set terminal process group (-1) error when using --user flag

### v1.0-beta

- first test

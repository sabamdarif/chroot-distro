dist_version="20260223"

bootstrap_distribution() {
	sudo rm -f "${ROOTFS_DIR}"/manjaro-*.tar.xz

	if should_skip_arch "aarch64"; then
		echo "[*] Skipping architecture: aarch64"
		return
	fi

	curl --fail --location \
		--output "${WORKDIR}/manjaro-aarch64.tar.xz" \
		"https://github.com/manjaro-arm/rootfs/releases/download/${dist_version}/Manjaro-ARM-aarch64-latest.tar.gz"

	sudo rm -rf "${WORKDIR}/manjaro-aarch64"
	sudo mkdir -m 755 "${WORKDIR}/manjaro-aarch64"
	sudo tar -xp --acls --xattrs --xattrs-include='*' \
		-f "${WORKDIR}/manjaro-aarch64.tar.xz" \
		-C "${WORKDIR}/manjaro-aarch64"

	cat <<-EOF | sudo unshare -mpf bash -e -
		rm -f "${WORKDIR}/manjaro-aarch64/etc/resolv.conf"
		echo "nameserver 1.1.1.1" > "${WORKDIR}/manjaro-aarch64/etc/resolv.conf"
		mount --bind "${WORKDIR}/manjaro-aarch64/" "${WORKDIR}/manjaro-aarch64/"
		mount --bind /dev "${WORKDIR}/manjaro-aarch64/dev"
		mount --bind /proc "${WORKDIR}/manjaro-aarch64/proc"
		mount --bind /sys "${WORKDIR}/manjaro-aarch64/sys"
		chroot "${WORKDIR}/manjaro-aarch64" pacman-mirrors -a -P http -c poland
		chroot "${WORKDIR}/manjaro-aarch64" pacman-key --init
		chroot "${WORKDIR}/manjaro-aarch64" pacman-key --populate manjaro
		chroot "${WORKDIR}/manjaro-aarch64" pacman-key --populate archlinuxarm
		chroot "${WORKDIR}/manjaro-aarch64" pacman -Syu --noconfirm
		chroot "${WORKDIR}/manjaro-aarch64" pacman -S --noconfirm util-linux
	EOF

	sudo rm -f "${WORKDIR:?}"/manjaro-aarch64/var/cache/pacman/pkg/* || true

	archive_rootfs "${ROOTFS_DIR}/manjaro-aarch64-${dist_version}.tar.xz" \
		"manjaro-aarch64"
}

dist_version="20250202"

bootstrap_distribution() {
	sudo rm -f "${ROOTFS_DIR}"/void-*.tar.xz

	for arch in aarch64 armv7l i686 x86_64; do
		if should_skip_arch "$arch"; then
			echo "[*] Skipping architecture: $(translate_arch "$arch")"
			continue
		fi

		curl --fail --location \
			--output "${WORKDIR}/void-${arch}.tar.xz" \
			"https://repo-default.voidlinux.org/live/${dist_version}/void-${arch}-ROOTFS-${dist_version}.tar.xz"
		sudo rm -rf "${WORKDIR}/void-$(translate_arch "$arch")"
		sudo mkdir -m 755 "${WORKDIR}/void-$(translate_arch "$arch")"
		sudo tar -Jxp --acls --xattrs --xattrs-include='*' \
			-f "${WORKDIR}/void-${arch}.tar.xz" \
			-C "${WORKDIR}/void-$(translate_arch "$arch")"

		cat <<-EOF | sudo unshare -mpf bash -e -
			rm -f "${WORKDIR}/void-$(translate_arch "$arch")/etc/resolv.conf"
			echo "nameserver 1.1.1.1" > "${WORKDIR}/void-$(translate_arch "$arch")/etc/resolv.conf"
			rm -f "${WORKDIR}/void-$(translate_arch "$arch")/etc/mtab"
			mount --bind /dev "${WORKDIR}/void-$(translate_arch "$arch")/dev"
			mount --bind /proc "${WORKDIR}/void-$(translate_arch "$arch")/proc"
			mount --bind /sys "${WORKDIR}/void-$(translate_arch "$arch")/sys"
			chroot "${WORKDIR}/void-$(translate_arch "$arch")" xbps-reconfigure -fa
		EOF
		sudo rm -f "${WORKDIR}/void-$(translate_arch "$arch")"/var/cache/xbps/* || true

		archive_rootfs "${ROOTFS_DIR}/void-$(translate_arch "$arch")-${dist_version}.tar.xz" \
			"void-$(translate_arch "$arch")"
	done
	unset arch
}

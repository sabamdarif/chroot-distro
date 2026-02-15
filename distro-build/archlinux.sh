dist_version="2025.12.01"

bootstrap_distribution() {
	sudo rm -f "${ROOTFS_DIR}"/archlinux-*.tar.xz

	for arch in aarch64 armv7; do
		if should_skip_arch "$arch"; then
			echo "[*] Skipping architecture: $(translate_arch "$arch")"
			continue
		fi

		curl --fail --location \
			--output "${WORKDIR}/archlinux-${arch}.tar.gz" \
			"http://os.archlinuxarm.org/os/ArchLinuxARM-${arch}-latest.tar.gz"

		sudo rm -rf "${WORKDIR}/archlinux-$(translate_arch "$arch")"
		sudo mkdir -m 755 "${WORKDIR}/archlinux-$(translate_arch "$arch")"
		sudo tar -zxp --acls --xattrs --xattrs-include='*' \
			-f "${WORKDIR}/archlinux-${arch}.tar.gz" \
			-C "${WORKDIR}/archlinux-$(translate_arch "$arch")"

		# Disable pacman sandbox before any pacman operations (Landlock not supported in CI)
		sudo sed -i 's/#DisableSandbox/DisableSandbox/' "${WORKDIR}/archlinux-$(translate_arch "$arch")/etc/pacman.conf"

		cat <<-EOF | sudo unshare -mpf bash -e -
			rm -f "${WORKDIR}/archlinux-$(translate_arch "$arch")/etc/resolv.conf"
			echo "nameserver 1.1.1.1" > "${WORKDIR}/archlinux-$(translate_arch "$arch")/etc/resolv.conf"
			mount --bind "${WORKDIR}/archlinux-$(translate_arch "$arch")/" "${WORKDIR}/archlinux-$(translate_arch "$arch")/"
			mount --bind /dev "${WORKDIR}/archlinux-$(translate_arch "$arch")/dev"
			mount --bind /proc "${WORKDIR}/archlinux-$(translate_arch "$arch")/proc"
			mount --bind /sys "${WORKDIR}/archlinux-$(translate_arch "$arch")/sys"
			chroot "${WORKDIR}/archlinux-$(translate_arch "$arch")" pacman-key --init
			chroot "${WORKDIR}/archlinux-$(translate_arch "$arch")" pacman-key --populate archlinuxarm
			chroot "${WORKDIR}/archlinux-$(translate_arch "$arch")" pacman -Syu --noconfirm
		EOF

		sudo rm -rf "${WORKDIR:?}/archlinux-$(translate_arch "$arch")"/var/cache/pacman/pkg

		archive_rootfs "${ROOTFS_DIR}/archlinux-$(translate_arch "$arch")-${dist_version}.tar.xz" \
			"archlinux-$(translate_arch "$arch")"
	done
	unset arch

	# x86_64 and i686 build (requires pacstrap via bootstrap image)
	skip_x86=false
	if should_skip_arch "x86_64" && should_skip_arch "i686"; then
		skip_x86=true
	fi

	if [ "$skip_x86" = "false" ]; then
		curl --fail --location \
			--output "${WORKDIR}/archlinux-x86_64.tar.zst" \
			"https://mirror.rackspace.com/archlinux/iso/${dist_version}/archlinux-bootstrap-${dist_version}-x86_64.tar.zst"

		sudo mkdir -m 755 "${WORKDIR}/archlinux-bootstrap"
		sudo tar -xp --strip-components=1 --acls --xattrs --xattrs-include='*' \
			-f "${WORKDIR}/archlinux-x86_64.tar.zst" \
			-C "${WORKDIR}/archlinux-bootstrap"

		# Disable pacman sandbox in bootstrap environment (Landlock not supported in CI)
		sudo sed -i 's/#DisableSandbox/DisableSandbox/' "${WORKDIR}/archlinux-bootstrap/etc/pacman.conf"

		cat <<-EOF | sudo unshare -mpf bash -e -
			rm -f "${WORKDIR}/archlinux-bootstrap/etc/resolv.conf"
			echo "nameserver 1.1.1.1" > "${WORKDIR}/archlinux-bootstrap/etc/resolv.conf"
			mount --bind "${WORKDIR}/archlinux-bootstrap/" "${WORKDIR}/archlinux-bootstrap/"
			mount --bind /dev "${WORKDIR}/archlinux-bootstrap/dev"
			mount --bind /proc "${WORKDIR}/archlinux-bootstrap/proc"
			mount --bind /sys "${WORKDIR}/archlinux-bootstrap/sys"
			mkdir "${WORKDIR}/archlinux-bootstrap/archlinux-i686"
			mkdir "${WORKDIR}/archlinux-bootstrap/archlinux-x86_64"
			echo 'Server = http://mirror.rackspace.com/archlinux/\$repo/os/\$arch' > \
				"${WORKDIR}/archlinux-bootstrap/etc/pacman.d/mirrorlist"
			chroot "${WORKDIR}/archlinux-bootstrap" pacman-key --init
			chroot "${WORKDIR}/archlinux-bootstrap" pacman-key --populate
			chroot "${WORKDIR}/archlinux-bootstrap" pacstrap -K /archlinux-x86_64 base
			sed -i 's|Architecture = auto|Architecture = i686|' \
				"${WORKDIR}/archlinux-bootstrap/etc/pacman.conf"
			sed -i 's|Required DatabaseOptional|Never|' \
				"${WORKDIR}/archlinux-bootstrap/etc/pacman.conf"
			echo 'Server = https://de.mirror.archlinux32.org/\$arch/\$repo' > \
				"${WORKDIR}/archlinux-bootstrap/etc/pacman.d/mirrorlist"
			chroot "${WORKDIR}/archlinux-bootstrap" pacstrap -K /archlinux-i686 base
		EOF
		sudo mv archlinux-bootstrap/archlinux-x86_64 ./
		sudo mv archlinux-bootstrap/archlinux-i686 ./

		for arch in i686 x86_64; do
			if should_skip_arch "$arch"; then
				echo "[*] Skipping architecture: $arch"
				continue
			fi

			sudo rm -rf "${WORKDIR:?}/archlinux-${arch}"/var/cache/pacman/pkg
			sudo sed -i 's/#DisableSandbox/DisableSandbox/' "archlinux-${arch}/etc/pacman.conf"
			archive_rootfs "${ROOTFS_DIR}/archlinux-${arch}-${dist_version}.tar.xz" \
				"archlinux-${arch}"
		done
		unset arch
	fi
}

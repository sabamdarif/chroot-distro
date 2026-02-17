dist_version="2026.02.01"

bootstrap_distribution() {
	sudo rm -f "${ROOTFS_DIR}"/archlinux-*.tar.xz

	local bootstrap_ready=false

	# Build x86_64 before i686 to ensure bootstrap config is not tainted for x86_64
	for arch in aarch64 armv7 x86_64 i686; do
		if should_skip_arch "$arch"; then
			echo "[*] Skipping architecture: $(translate_arch "$arch")"
			continue
		fi

		case "$arch" in
		aarch64 | armv7)
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

				# Remove kernel and firmware to save space (not needed in chroot)
				if [ "$arch" = "aarch64" ]; then
					chroot "${WORKDIR}/archlinux-$(translate_arch "$arch")" pacman -Rnsc --noconfirm linux-aarch64 linux-firmware || true
				else
					chroot "${WORKDIR}/archlinux-$(translate_arch "$arch")" pacman -Rnsc --noconfirm linux-armv7 linux-firmware || true
				fi

				# Retry upgrade in case of transient mirror 404s
				for attempt in 1 2 3; do
					if chroot "${WORKDIR}/archlinux-$(translate_arch "$arch")" pacman -Syyu --noconfirm; then
						break
					fi
					if [ "\$attempt" -eq 3 ]; then
						echo "Error: pacman upgrade failed after 3 attempts"
						exit 1
					fi
					echo "[*] Retry \$attempt: pacman upgrade failed, retrying in 30s..."
					sleep 30
				done
			EOF
			;;
		x86_64 | i686)
			if [ "$bootstrap_ready" = "false" ]; then
				curl --fail --location \
					--output "${WORKDIR}/archlinux-x86_64.tar.zst" \
					"https://mirror.rackspace.com/archlinux/iso/${dist_version}/archlinux-bootstrap-${dist_version}-x86_64.tar.zst"

				sudo mkdir -m 755 "${WORKDIR}/archlinux-bootstrap"
				sudo tar -xp --strip-components=1 --acls --xattrs --xattrs-include='*' \
					-f "${WORKDIR}/archlinux-x86_64.tar.zst" \
					-C "${WORKDIR}/archlinux-bootstrap"

				# Disable pacman sandbox in bootstrap environment
				sudo sed -i 's/#DisableSandbox/DisableSandbox/' "${WORKDIR}/archlinux-bootstrap/etc/pacman.conf"

				# Configure bootstrap environment once
				cat <<-EOF | sudo unshare -mpf bash -e -
					rm -f "${WORKDIR}/archlinux-bootstrap/etc/resolv.conf"
					echo "nameserver 1.1.1.1" > "${WORKDIR}/archlinux-bootstrap/etc/resolv.conf"
					mount --bind "${WORKDIR}/archlinux-bootstrap/" "${WORKDIR}/archlinux-bootstrap/"
					mount --bind /dev "${WORKDIR}/archlinux-bootstrap/dev"
					mount --bind /proc "${WORKDIR}/archlinux-bootstrap/proc"
					mount --bind /sys "${WORKDIR}/archlinux-bootstrap/sys"
					echo 'Server = http://mirror.rackspace.com/archlinux/\$repo/os/\$arch' > \
						"${WORKDIR}/archlinux-bootstrap/etc/pacman.d/mirrorlist"
					chroot "${WORKDIR}/archlinux-bootstrap" pacman-key --init
					chroot "${WORKDIR}/archlinux-bootstrap" pacman-key --populate
				EOF
				bootstrap_ready=true
			fi

			sudo mkdir -p "${WORKDIR}/archlinux-bootstrap/archlinux-${arch}"

			if [ "$arch" = "i686" ]; then
				# Configure bootstrap for i686 only when needed
				cat <<-EOF | sudo unshare -mpf bash -e -
					sed -i 's|Architecture = auto|Architecture = i686|' \
						"${WORKDIR}/archlinux-bootstrap/etc/pacman.conf"
					sed -i 's|Required DatabaseOptional|Never|' \
						"${WORKDIR}/archlinux-bootstrap/etc/pacman.conf"
					echo 'Server = https://de.mirror.archlinux32.org/\$arch/\$repo' > \
						"${WORKDIR}/archlinux-bootstrap/etc/pacman.d/mirrorlist"
				EOF
			fi

			# Build specific architecture
			cat <<-EOF | sudo unshare -mpf bash -e -
				mount --bind "${WORKDIR}/archlinux-bootstrap/" "${WORKDIR}/archlinux-bootstrap/"
				mount --bind /dev "${WORKDIR}/archlinux-bootstrap/dev"
				mount --bind /proc "${WORKDIR}/archlinux-bootstrap/proc"
				mount --bind /sys "${WORKDIR}/archlinux-bootstrap/sys"
				chroot "${WORKDIR}/archlinux-bootstrap" pacstrap -K /archlinux-${arch} base
			EOF

			sudo mv "${WORKDIR}/archlinux-bootstrap/archlinux-${arch}" "${WORKDIR}/archlinux-$(translate_arch "$arch")"

			# Post-configuration
			sudo sed -i 's/#DisableSandbox/DisableSandbox/' "${WORKDIR}/archlinux-$(translate_arch "$arch")/etc/pacman.conf"
			;;
		esac

		# Common Cleanup
		sudo rm -rf "${WORKDIR:?}/archlinux-$(translate_arch "$arch")"/var/cache/pacman/pkg

		archive_rootfs "${ROOTFS_DIR}/archlinux-$(translate_arch "$arch")-${dist_version}.tar.xz" \
			"archlinux-$(translate_arch "$arch")"
	done

	# Cleanup bootstrap directory if it was created
	if [ "$bootstrap_ready" = "true" ]; then
		sudo rm -rf "${WORKDIR}/archlinux-bootstrap"
	fi
}

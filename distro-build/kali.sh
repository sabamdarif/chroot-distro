dist_version="2025.4"

bootstrap_distribution() {
	sudo rm -f "${ROOTFS_DIR}"/kali-*.tar.xz

	# Kali officially supports amd64 and arm64
	for arch in aarch64 x86_64; do
		if should_skip_arch "$arch"; then
			echo "[*] Skipping architecture: $(translate_arch "$arch")"
			continue
		fi

		local kali_arch
		case "$arch" in
		aarch64) kali_arch="arm64" ;;
		x86_64) kali_arch="amd64" ;;
		*) continue ;;
		esac

		echo "[*] Bootstrapping Kali Linux ${dist_version} for ${kali_arch}"

		# Create temporary directory for this architecture
		sudo rm -rf "${WORKDIR}/kali-$(translate_arch "$arch")"
		sudo mkdir -m 755 "${WORKDIR}/kali-$(translate_arch "$arch")"

		# Use debootstrap to create minimal Kali rootfs
		sudo debootstrap \
			--arch="${kali_arch}" \
			--variant=minbase \
			--components=main,contrib,non-free,non-free-firmware \
			--include=kali-archive-keyring,apt-transport-https,ca-certificates \
			kali-rolling \
			"${WORKDIR}/kali-$(translate_arch "$arch")" \
			http://http.kali.org/kali

		# Configure the rootfs
		cat <<-EOF | sudo unshare -mpf bash -e -
			rm -f "${WORKDIR}/kali-$(translate_arch "$arch")/etc/resolv.conf"
			echo "nameserver 1.1.1.1" > "${WORKDIR}/kali-$(translate_arch "$arch")/etc/resolv.conf"
			mount --bind /dev "${WORKDIR}/kali-$(translate_arch "$arch")/dev"
			mount --bind /proc "${WORKDIR}/kali-$(translate_arch "$arch")/proc"
			mount --bind /sys "${WORKDIR}/kali-$(translate_arch "$arch")/sys"

			# Update and configure
			chroot "${WORKDIR}/kali-$(translate_arch "$arch")" apt-get update
			chroot "${WORKDIR}/kali-$(translate_arch "$arch")" apt-get upgrade -y

			# Clean up
			chroot "${WORKDIR}/kali-$(translate_arch "$arch")" apt-get clean
			rm -rf "${WORKDIR}/kali-$(translate_arch "$arch")"/var/lib/apt/lists/*
			rm -rf "${WORKDIR}/kali-$(translate_arch "$arch")"/var/cache/apt/archives/*
		EOF

		# Clean up any remaining cache
		sudo rm -rf "${WORKDIR:?}/kali-$(translate_arch "$arch")"/var/cache/apt/archives/* || true
		sudo rm -rf "${WORKDIR:?}/kali-$(translate_arch "$arch")"/tmp/* || true
		sudo rm -rf "${WORKDIR:?}/kali-$(translate_arch "$arch")"/var/tmp/* || true

		# Archive the rootfs
		archive_rootfs "${ROOTFS_DIR}/kali-$(translate_arch "$arch")-${dist_version}.tar.xz" \
			"kali-$(translate_arch "$arch")"
	done
}

# After changing, update the DISTRO_NAME below.
dist_version="25.10"
dist_codename="questing"

bootstrap_distribution() {
	sudo rm -f "${ROOTFS_DIR}"/ubuntu-*-"${dist_version}".tar.xz

	for arch in arm64 armhf amd64; do
		if should_skip_arch "$arch"; then
			echo "[*] Skipping architecture: $(translate_arch "$arch")"
			continue
		fi

		sudo rm -rf "${WORKDIR}/ubuntu-${dist_codename}-$(translate_arch "$arch")"
		sudo mmdebstrap \
			--architectures=${arch} \
			--variant=apt \
			--components="main,universe,multiverse" \
			--include="locales,passwd,software-properties-common,sudo" \
			--format=directory \
			"${dist_codename}" \
			"${WORKDIR}/ubuntu-${dist_codename}-$(translate_arch "$arch")"

		cat <<-EOF | sudo unshare -mpf bash -e -
			mount --bind /dev "${WORKDIR}/ubuntu-${dist_codename}-$(translate_arch "$arch")/dev"
			mount --bind /proc "${WORKDIR}/ubuntu-${dist_codename}-$(translate_arch "$arch")/proc"
			mount --bind /sys "${WORKDIR}/ubuntu-${dist_codename}-$(translate_arch "$arch")/sys"
			chroot "${WORKDIR}/ubuntu-${dist_codename}-$(translate_arch "$arch")" apt update
			chroot "${WORKDIR}/ubuntu-${dist_codename}-$(translate_arch "$arch")" apt purge -yq --allow-remove-essential coreutils-from-uutils
			chroot "${WORKDIR}/ubuntu-${dist_codename}-$(translate_arch "$arch")" apt purge -yq --allow-remove-essential rust-coreutils
			chroot "${WORKDIR}/ubuntu-${dist_codename}-$(translate_arch "$arch")" apt install -yq coreutils-from-gnu
			chroot "${WORKDIR}/ubuntu-${dist_codename}-$(translate_arch "$arch")" apt install -yq gnu-coreutils
			chroot "${WORKDIR}/ubuntu-${dist_codename}-$(translate_arch "$arch")" apt clean
			rm -rf "${WORKDIR}/ubuntu-${dist_codename}-$(translate_arch "$arch")"/var/lib/apt/lists/*
		EOF

		archive_rootfs "${ROOTFS_DIR}/ubuntu-$(translate_arch "$arch")-${dist_version}.tar.xz" \
			"ubuntu-${dist_codename}-$(translate_arch "$arch")"
	done
	unset arch
}

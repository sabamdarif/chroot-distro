# Put only current stable version here!
dist_version="13.4"
dist_codename="trixie"

bootstrap_distribution() {
	sudo rm -f "${ROOTFS_DIR}"/debian-*-"${dist_version}".tar.xz

	for arch in arm64 armhf i386 amd64; do
		if should_skip_arch "$arch"; then
			echo "[*] Skipping architecture: $(translate_arch "$arch")"
			continue
		fi

		sudo rm -rf "${WORKDIR}/debian-${dist_codename}-$(translate_arch "$arch")"
		sudo mmdebstrap \
			--architectures=${arch} \
			--variant=minbase \
			--components="main,contrib" \
			--include="ca-certificates,locales" \
			--format=directory \
			"${dist_codename}" \
			"${WORKDIR}/debian-${dist_codename}-$(translate_arch "$arch")"
		archive_rootfs "${ROOTFS_DIR}/debian-$(translate_arch "$arch")-${dist_version}.tar.xz" \
			"debian-${dist_codename}-$(translate_arch "$arch")"
	done
	unset arch
}

# Put only current stable version here!
dist_version="12.0"
dist_codename="ecne"

bootstrap_distribution() {
	sudo rm -f "${ROOTFS_DIR}"/trisquel-*-"${dist_version}".tar.xz

	for arch in i386 arm64 armhf amd64; do
		if should_skip_arch "$arch"; then
			echo "[*] Skipping architecture: $(translate_arch "$arch")"
			continue
		fi

		sudo rm -rf "${WORKDIR}/trisquel-$(translate_arch "$arch")"
		sudo mmdebstrap \
			--architectures=${arch} \
			--variant=apt \
			--components="main" \
			--include="ca-certificates,locales,trisquel-keyring,software-properties-common,passwd" \
			--format=directory \
			"${dist_codename}" \
			"${WORKDIR}/trisquel-$(translate_arch "$arch")" \
			"deb http://archive.trisquel.org/trisquel ${dist_codename} main" \
			"deb http://archive.trisquel.org/trisquel ${dist_codename}-updates main" \
			"deb http://archive.trisquel.org/trisquel ${dist_codename}-security main" \
			"deb http://archive.trisquel.org/trisquel ${dist_codename}-backports main"
		archive_rootfs "${ROOTFS_DIR}/trisquel-$(translate_arch "$arch")-${dist_version}.tar.xz" \
			"trisquel-$(translate_arch "$arch")"
	done
	unset arch
}

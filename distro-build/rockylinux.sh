dist_version="10.1"

bootstrap_distribution() {
	sudo rm -f "${ROOTFS_DIR}"/rocky-*.tar.xz

	for arch in aarch64 x86_64; do
		if should_skip_arch "$arch"; then
			echo "[*] Skipping architecture: $(translate_arch "$arch")"
			continue
		fi

		curl --fail --location --output "${WORKDIR}/Rocky-Container-Minimal.${arch}-${dist_version}.tar.xz" "https://download.rockylinux.org/pub/rocky/${dist_version%%.*}/images/${arch}/Rocky-${dist_version%%.*}-Container-Minimal.latest.${arch}.tar.xz"
		sudo rm -rf "${WORKDIR}/rocky-tmp" "${WORKDIR}/rocky-$(translate_arch "$arch")"
		mkdir "${WORKDIR}/rocky-tmp"
		tar -C "${WORKDIR}/rocky-tmp" -Jxf "${WORKDIR}/Rocky-Container-Minimal.${arch}-${dist_version}.tar.xz"
		oci_manifest=$(jq -r '.manifests[0].digest' "${WORKDIR}/rocky-tmp"/index.json | cut -d ':' -f 2)
		oci_layers=$(jq -r '.layers[].digest' "${WORKDIR}/rocky-tmp/blobs/sha256/${oci_manifest}" | cut -d ':' -f 2)

		sudo mkdir -m 755 "${WORKDIR}/rocky-$(translate_arch "$arch")"
		for layer in ${oci_layers}; do
			sudo tar -zxp --acls --xattrs --xattrs-include='*' \
				-f "${WORKDIR}/rocky-tmp/blobs/sha256/${layer}" \
				-C "${WORKDIR}/rocky-$(translate_arch "$arch")"
		done
		sudo rm -rf "${WORKDIR}/rocky-tmp"

		cat <<-EOF | sudo unshare -mpf bash -e -
			rm -f "${WORKDIR}/rocky-$(translate_arch "$arch")/etc/resolv.conf"
			echo "nameserver 1.1.1.1" > "${WORKDIR}/rocky-$(translate_arch "$arch")/etc/resolv.conf"
			mount --bind /dev "${WORKDIR}/rocky-$(translate_arch "$arch")/dev"
			mount --bind /proc "${WORKDIR}/rocky-$(translate_arch "$arch")/proc"
			mount --bind /sys "${WORKDIR}/rocky-$(translate_arch "$arch")/sys"
			chroot "${WORKDIR}/rocky-$(translate_arch "$arch")" microdnf upgrade -y
			chroot "${WORKDIR}/rocky-$(translate_arch "$arch")" microdnf install dnf -y
			chroot "${WORKDIR}/rocky-$(translate_arch "$arch")" microdnf clean all -y
		EOF

		archive_rootfs "${ROOTFS_DIR}/rocky-$(translate_arch "$arch")-${dist_version}.tar.xz" "rocky-$(translate_arch "$arch")"
	done
	unset arch
}

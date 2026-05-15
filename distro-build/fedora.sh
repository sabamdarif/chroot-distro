dist_version="43-1.6"

bootstrap_distribution() {
	sudo rm -f "${ROOTFS_DIR}"/fedora-*.tar.xz

	for arch in aarch64 x86_64; do
		if should_skip_arch "$arch"; then
			echo "[*] Skipping architecture: $(translate_arch "$arch")"
			continue
		fi

		curl --fail --location \
			--output "${WORKDIR}/Fedora-Container-Base-Generic.${arch}-${dist_version}.oci.tar.xz" \
			"https://mirror.de.leaseweb.net/fedora/releases/${dist_version%%-*}/Container/${arch}/images/Fedora-Container-Base-Generic-${dist_version}.${arch}.oci.tar.xz"
		sudo rm -rf "${WORKDIR}/fedora-tmp" "${WORKDIR}/fedora-$(translate_arch "$arch")"
		mkdir "${WORKDIR}/fedora-tmp"
		tar -C "${WORKDIR}/fedora-tmp" -Jxf "${WORKDIR}/Fedora-Container-Base-Generic.${arch}-${dist_version}.oci.tar.xz"
		oci_manifest=$(jq -r '.manifests[0].digest' "${WORKDIR}/fedora-tmp"/index.json | cut -d ':' -f 2)
		oci_layers=$(jq -r '.layers[].digest' "${WORKDIR}/fedora-tmp/blobs/sha256/${oci_manifest}" | cut -d ':' -f 2)

		sudo mkdir -m 755 "${WORKDIR}/fedora-$(translate_arch "$arch")"
		for layer in ${oci_layers}; do
			sudo tar -zxp --acls --xattrs --xattrs-include='*' \
				-f "${WORKDIR}/fedora-tmp/blobs/sha256/${layer}" \
				-C "${WORKDIR}/fedora-$(translate_arch "$arch")"
		done
		sudo rm -rf "${WORKDIR}/fedora-tmp"

		cat <<-EOF | sudo unshare -mpf bash -e -
			rm -f "${WORKDIR}/fedora-$(translate_arch "$arch")/etc/resolv.conf"
			echo "nameserver 1.1.1.1" > "${WORKDIR}/fedora-$(translate_arch "$arch")/etc/resolv.conf"
			sed -i '/tsflags=nodocs/d' "${WORKDIR}/fedora-$(translate_arch "$arch")/etc/dnf/dnf.conf"
			echo "excludepkgs=*selinux* filesystem" >> "${WORKDIR}/fedora-$(translate_arch "$arch")/etc/dnf/dnf.conf"
			mount --bind /dev "${WORKDIR}/fedora-$(translate_arch "$arch")/dev"
			mount --bind /proc "${WORKDIR}/fedora-$(translate_arch "$arch")/proc"
			mount --bind /sys "${WORKDIR}/fedora-$(translate_arch "$arch")/sys"
			chroot "${WORKDIR}/fedora-$(translate_arch "$arch")" dnf upgrade -y
			chroot "${WORKDIR}/fedora-$(translate_arch "$arch")" dnf reinstall -y '*'
			chroot "${WORKDIR}/fedora-$(translate_arch "$arch")" dnf install -y passwd util-linux sudo
			chroot "${WORKDIR}/fedora-$(translate_arch "$arch")" dnf clean all
			chmod 4755 "${WORKDIR}/fedora-$(translate_arch "$arch")"/usr/bin/sudo
		EOF

		archive_rootfs "${ROOTFS_DIR}/fedora-$(translate_arch "$arch")-${dist_version%%-*}.tar.xz" \
			"fedora-$(translate_arch "$arch")"
	done
	unset arch
}

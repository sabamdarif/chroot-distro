dist_version="16.0"

bootstrap_distribution() {
	sudo rm -f "${ROOTFS_DIR}"/opensuse-*.tar.xz

	opensuse_manifest=$(docker manifest inspect opensuse/leap:"${dist_version}")
	for arch in arm64 amd64; do
		if should_skip_arch "$arch"; then
			echo "[*] Skipping architecture: $(translate_arch "$arch")"
			continue
		fi

		digest=$(
			echo "$opensuse_manifest" |
				jq -r ".manifests[]" |
				jq -r "select(.platform.architecture == \"${arch}\")" |
				jq -r ".digest"
		)

		docker pull "opensuse/leap@${digest}"
		docker export --output "${WORKDIR}/opensuse-dump-${arch}.tar" \
			$(docker create "opensuse/leap@${digest}")

		sudo rm -rf "${WORKDIR}/opensuse-$(translate_arch "$arch")"
		sudo mkdir -m 755 "${WORKDIR}/opensuse-$(translate_arch "$arch")"
		sudo tar -xpf "${WORKDIR}/opensuse-dump-${arch}.tar" \
			-C "${WORKDIR}/opensuse-$(translate_arch "$arch")"

		cat <<-EOF | sudo unshare -mpf bash -e -
			rm -f "${WORKDIR}/opensuse-$(translate_arch "$arch")/etc/resolv.conf"
			echo "nameserver 1.1.1.1" > "${WORKDIR}/opensuse-$(translate_arch "$arch")/etc/resolv.conf"
			sed -i -E 's/^(rpm\.install\.excludedocs)/# \1/g' "${WORKDIR}/opensuse-$(translate_arch "$arch")/etc/zypp/zypp.conf"
			mount --bind /dev "${WORKDIR}/opensuse-$(translate_arch "$arch")/dev"
			mount --bind /proc "${WORKDIR}/opensuse-$(translate_arch "$arch")/proc"
			mount --bind /sys "${WORKDIR}/opensuse-$(translate_arch "$arch")/sys"
			chroot "${WORKDIR}/opensuse-$(translate_arch "$arch")" zypper refresh
			chroot "${WORKDIR}/opensuse-$(translate_arch "$arch")" zypper dup --no-confirm
			chroot "${WORKDIR}/opensuse-$(translate_arch "$arch")" rpm -qa --qf '%{NAME} ' | xargs -n 1 | grep -Pv '(filesystem|gpg-pubkey)' > /tmp/opensuse-pkgs.txt
			cat /tmp/opensuse-pkgs.txt | xargs chroot "${WORKDIR}/opensuse-$(translate_arch "$arch")" zypper install --no-confirm --force
			chroot "${WORKDIR}/opensuse-$(translate_arch "$arch")" zypper install --no-confirm util-linux sudo
			chroot "${WORKDIR}/opensuse-$(translate_arch "$arch")" zypper clean -a
		EOF
		sudo rm -f /tmp/opensuse-pkgs.txt

		archive_rootfs "${ROOTFS_DIR}/opensuse-$(translate_arch "$arch")-${dist_version}.tar.xz" \
			"opensuse-$(translate_arch "$arch")"
	done
	unset opensuse_manifest
}

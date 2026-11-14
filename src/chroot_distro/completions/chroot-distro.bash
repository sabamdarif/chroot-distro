# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
# Bash completion for chroot-distro
#
# Install system-wide:
#   cp chroot-distro.bash /usr/share/bash-completion/completions/chroot-distro
# Install for current user:
#   mkdir -p ~/.local/share/bash-completion/completions
#   cp chroot-distro.bash ~/.local/share/bash-completion/completions/chroot-distro

_chroot_distro_complete_containers() {
	local base d name LC_ALL=C
	COMPREPLY=()
	if _chroot_distro_is_termux; then
		base="${TERMUX__PREFIX:-/data/data/com.termux/files/usr}/var/lib"
	elif [[ -n "${XDG_DATA_HOME:-}" ]]; then
		base="${XDG_DATA_HOME}"
	elif ((EUID == 0)) && [[ -v HOME ]]; then
		base="${HOME}/.local/share"
	else
		base=~root/.local/share
		[[ "${base}" == /* ]] || return
	fi
	for d in "${base}/chroot-distro/containers"/*/; do
		[[ -d "${d}rootfs" ]] || continue
		name=${d%/}
		name=${name##*/}
		if [[ "${name}" == [A-Za-z0-9]* && "${name}" != *[!A-Za-z0-9_.-]* && "${name}" == "$1"* ]]; then
			COMPREPLY+=("${name}")
		fi
	done
}

# Returns 0 (true) when running on Termux/Android: at least two of three
# independent indicators must match, mirroring _detect_termux() in constants.py.
_chroot_distro_is_termux() {
	local score=0
	[[ -f /system/build.prop || -d /data/app ]] && ((score++))
	[[ -n "${TERMUX_APP__APP_VERSION_NAME}" || -n "${TERMUX_VERSION}" ]] && ((score++))
	local prefix="${TERMUX__PREFIX:-/data/data/com.termux/files/usr}"
	[[ -r "${prefix}" && -x "${prefix}" ]] && ((score++))
	[[ ${score} -ge 2 ]]
}

# Bash expands this word list as shell input, so pass only static words.
_chroot_distro_compgen_words() {
	mapfile -t COMPREPLY < <(compgen -W "$1" -- "$2")
}

_chroot_distro() {
	local cur prev words cword
	_init_completion || return

	local -r _all_commands="install add i in ins remove rm rename reset login sh list li ls
        backup bak bkp restore clear-cache clear cl copy cp sync run build push
        kill k stop ps diff search find se info version-info nf
        unmount umount um help h he hel"

	# Complete the subcommand itself
	if [[ ${cword} -eq 1 ]]; then
		if [[ "${cur}" == -* ]]; then
			_chroot_distro_compgen_words "-h --help -V --version" "${cur}"
		else
			_chroot_distro_compgen_words "${_all_commands}" "${cur}"
		fi
		return
	fi

	local command="${words[1]}"

	# Map aliases to canonical command names (mirrors parser.py ALIAS_TO_CANONICAL)
	case "${command}" in
	add | i | in | ins) command=install ;;
	rm) command=remove ;;
	sh) command=login ;;
	li | ls) command=list ;;
	bak | bkp) command=backup ;;
	clear | cl) command=clear-cache ;;
	cp) command=copy ;;
	k | stop) command="kill" ;;
	find | se) command=search ;;
	version-info | nf) command=info ;;
	umount | um) command=unmount ;;
	h | he | hel) command=help ;;
	esac

	case "${command}" in

	# -----------------------------------------------------------------------
	install)
		case "${prev}" in
		-n | --name | --override-alias)
			return
			;;
		-a | --architecture)
			_chroot_distro_compgen_words "aarch64 arm i686 riscv64 x86_64" "${cur}"
			return
			;;
		esac
		if [[ "${cur}" == -* ]]; then
			_chroot_distro_compgen_words "-n --name --override-alias -a --architecture --allow-insecure -q --quiet -h --help" "${cur}"
		elif [[ "${cur}" == /* || "${cur}" == ./* || "${cur}" == ../* ]]; then
			_filedir
		fi
		;;

	# -----------------------------------------------------------------------
	remove)
		if [[ "${cur}" == -* ]]; then
			_chroot_distro_compgen_words "-v --verbose -q --quiet -h --help" "${cur}"
		else
			_chroot_distro_complete_containers "${cur}"
		fi
		;;

	# -----------------------------------------------------------------------
	rename)
		if [[ "${cur}" == -* ]]; then
			_chroot_distro_compgen_words "-q --quiet -h --help" "${cur}"
		else
			_chroot_distro_complete_containers "${cur}"
		fi
		;;

	# -----------------------------------------------------------------------
	reset)
		if [[ "${cur}" == -* ]]; then
			_chroot_distro_compgen_words "-q --quiet -h --help" "${cur}"
		else
			_chroot_distro_complete_containers "${cur}"
		fi
		;;

	# -----------------------------------------------------------------------
	login)
		# After --, complete host-side commands
		local i
		for ((i = 2; i < cword; i++)); do
			if [[ "${words[i]}" == "--" ]]; then
				_command_offset $((i + 1))
				return
			fi
		done
		case "${prev}" in
		-u | --user) return ;;
		-b | --bind)
			_filedir
			return
			;;
		-w | --work-dir)
			_filedir -d
			return
			;;
		-e | --env) return ;;
		esac
		if [[ "${cur}" == -* ]]; then
			local opts="-u --user --isolated --isolate --minimal --no-new-privs --shared-home --shared-tmp --shared-display --shared-x11
                    -b --bind -w --work-dir -e --env --get-chroot-cmd -h --help"
			_chroot_distro_compgen_words "${opts}" "${cur}"
		else
			_chroot_distro_complete_containers "${cur}"
		fi
		;;

	# -----------------------------------------------------------------------
	list)
		_chroot_distro_compgen_words "-v --verbose -q --quiet -h --help --json" "${cur}"
		;;

	# -----------------------------------------------------------------------
	backup)
		case "${prev}" in
		-o | --output)
			_filedir
			return
			;;
		-c | --compress)
			_chroot_distro_compgen_words "gzip bzip2 xz none" "${cur}"
			return
			;;
		esac
		if [[ "${cur}" == -* ]]; then
			_chroot_distro_compgen_words "-o --output -c --compress -v --verbose -q --quiet -h --help" "${cur}"
		else
			_chroot_distro_complete_containers "${cur}"
		fi
		;;

	# -----------------------------------------------------------------------
	restore)
		if [[ "${cur}" == -* ]]; then
			_chroot_distro_compgen_words "-v --verbose -q --quiet -h --help" "${cur}"
		else
			_filedir '@(tar|tar.gz|tgz|tar.bz2|tbz2|tar.xz|txz)'
		fi
		;;

	# -----------------------------------------------------------------------
	clear-cache)
		_chroot_distro_compgen_words "--build-cache --keep -v --verbose -q --quiet -h --help" "${cur}"
		;;

	# -----------------------------------------------------------------------
	copy)
		if [[ "${cur}" == -* ]]; then
			_chroot_distro_compgen_words "-v --verbose -q --quiet -m --move -r --recursive --chown -h --help" "${cur}"
		else
			# Support container:path notation: complete container names
			# (no colon yet) or paths (colon already present → filesystem)
			if [[ "${cur}" == *:* ]]; then
				_filedir
			else
				_chroot_distro_complete_containers "${cur}"
				_filedir
			fi
		fi
		;;

	# -----------------------------------------------------------------------
	sync)
		if [[ "${cur}" == -* ]]; then
			_chroot_distro_compgen_words "-v --verbose -q --quiet -c --checksum -d --delete --chown -h --help" "${cur}"
		else
			if [[ "${cur}" == *:* ]]; then
				_filedir
			else
				_chroot_distro_complete_containers "${cur}"
				_filedir
			fi
		fi
		;;

	# -----------------------------------------------------------------------
	run)
		# After --, complete host-side commands
		local i
		for ((i = 2; i < cword; i++)); do
			if [[ "${words[i]}" == "--" ]]; then
				_command_offset $((i + 1))
				return
			fi
		done
		case "${prev}" in
		-u | --user) return ;;
		-b | --bind)
			_filedir
			return
			;;
		-w | --work-dir)
			_filedir -d
			return
			;;
		-e | --env) return ;;
		--entrypoint) return ;;
		esac
		if [[ "${cur}" == -* ]]; then
			local opts="-u --user --isolated --isolate --minimal --no-new-privs --shared-home --shared-tmp --shared-display --shared-x11
                    -b --bind -w --work-dir -e --env --entrypoint -d --detach --get-chroot-cmd -h --help"
			_chroot_distro_compgen_words "${opts}" "${cur}"
		else
			_chroot_distro_complete_containers "${cur}"
		fi
		;;

	# -----------------------------------------------------------------------
	unmount)
		if [[ "${cur}" == -* ]]; then
			_chroot_distro_compgen_words "-h --help" "${cur}"
		else
			_chroot_distro_complete_containers "${cur}"
		fi
		;;

	# -----------------------------------------------------------------------
	build)
		if [[ "${cur}" == --install-as=* || ( "${prev}" == = && "${words[cword - 2]}" == --install-as ) ]]; then
			return
		fi
		case "${prev}" in
		-f | --file)
			_filedir
			return
			;;
		-t | --tag)
			return
			;;
		--build-arg)
			return
			;;
		-a | --architecture)
			_chroot_distro_compgen_words "aarch64 arm i686 riscv64 x86_64" "${cur}"
			return
			;;
		--platform)
			_chroot_distro_compgen_words "linux/amd64 linux/arm64 linux/arm/v7 linux/386 linux/riscv64" "${cur}"
			return
			;;
		--target | --install-as)
			return
			;;
		-o | --output)
			_filedir
			return
			;;
		--progress)
			_chroot_distro_compgen_words "auto plain tty rawjson" "${cur}"
			return
			;;
		--export)
			_chroot_distro_compgen_words "type=local,dest= type=tar,dest=" "${cur}"
			return
			;;
		--cache-from)
			_chroot_distro_compgen_words "type=local,src= type=registry,ref=" "${cur}"
			return
			;;
		--cache-to)
			_chroot_distro_compgen_words "type=local,dest= type=registry,ref=" "${cur}"
			return
			;;
		--build-context)
			return
			;;
		esac
		if [[ "${cur}" == -* ]]; then
			_chroot_distro_compgen_words "-f --file -t --tag --build-arg --build-context -a --architecture
                    --platform --target -o --output --export --install-as --secret --ssh
					--cache-from --cache-to --allow-insecure --no-cache --progress -v --verbose
                    -q --quiet -h --help" "${cur}"
		else
			_filedir -d
		fi
		;;

	# -----------------------------------------------------------------------
	push)
		case "${prev}" in
		-a | --architecture)
			_chroot_distro_compgen_words "aarch64 arm i686 riscv64 x86_64" "${cur}"
			return
			;;
		esac
		if [[ "${cur}" == -* ]]; then
			_chroot_distro_compgen_words "-a --architecture --allow-insecure -q --quiet -h --help" "${cur}"
		fi
		;;

	# -----------------------------------------------------------------------
	kill)
		if [[ "${cur}" == -* ]]; then
			_chroot_distro_compgen_words "-h --help" "${cur}"
		else
			_chroot_distro_complete_containers "${cur}"
		fi
		;;

	# -----------------------------------------------------------------------
	ps)
		_chroot_distro_compgen_words "-q --quiet -h --help --json" "${cur}"
		;;

	# -----------------------------------------------------------------------
	diff)
		if [[ "${cur}" == -* ]]; then
			_chroot_distro_compgen_words "-h --help --json" "${cur}"
		else
			_chroot_distro_complete_containers "${cur}"
		fi
		;;

	# -----------------------------------------------------------------------
	search)
		case "${prev}" in
		-l | --limit)
			return
			;;
		esac
		if [[ "${cur}" == -* ]]; then
			_chroot_distro_compgen_words "-l --limit -q --quiet -h --help" "${cur}"
		fi
		;;

	# -----------------------------------------------------------------------
	info)
		_chroot_distro_compgen_words "-h --help --json" "${cur}"
		;;

	# -----------------------------------------------------------------------
	help)
		_chroot_distro_compgen_words "${_all_commands} -h --help" "${cur}"
		;;

	esac
}

complete -F _chroot_distro chroot-distro

import os
import shutil
import subprocess
from pathlib import Path

import pytest


pytestmark = pytest.mark.skipif(os.name != "posix" or shutil.which("bash") is None, reason="POSIX Bash is unavailable")


def _bash_completions(env, *words):
    completion = Path(__file__).resolve().parents[2] / "src/chroot_distro/completions/chroot-distro.bash"
    result = subprocess.run(
        [
            "bash",
            "--noprofile",
            "--norc",
            "-c",
            r"""
source "$1"
shift
input=("$@")
_chroot_distro_is_termux() { return 1; }
_init_completion() {
    words=(chroot-distro "${input[@]}")
    cword=$((${#words[@]} - 1))
    cur=${words[cword]}
    prev=${words[cword - 1]}
}
_filedir() { COMPREPLY+=(taken); }
_chroot_distro
for candidate in "${COMPREPLY[@]}"; do
    printf '%s\n' "$candidate"
done
""",
            "bash",
            str(completion),
            *words,
        ],
        env=env,
        capture_output=True,
        text=True,
        check=True,
    )

    assert result.stderr == ""
    return result.stdout.splitlines()


def test_bash_container_completion_uses_literal_names(tmp_path):
    containers = tmp_path / "chroot-distro" / "containers"
    for name in ("valid-name_0.1", "$(printf injected)", "invalid space", "line\n", "évil"):
        (containers / name / "rootfs").mkdir(parents=True)
    (containers / "missing-rootfs").mkdir()

    assert _bash_completions({**os.environ, "XDG_DATA_HOME": str(tmp_path)}, "login", "") == ["valid-name_0.1"]


@pytest.mark.parametrize("xdg_data_home", [None, ""])
def test_bash_default_completion_uses_the_root_store(tmp_path, xdg_data_home):
    name = f"{tmp_path.name}-home-container"
    (tmp_path / ".local/share/chroot-distro/containers" / name / "rootfs").mkdir(parents=True)
    env = {**os.environ, "HOME": str(tmp_path)}
    if xdg_data_home is None:
        env.pop("XDG_DATA_HOME", None)
    else:
        env["XDG_DATA_HOME"] = xdg_data_home

    assert (name in _bash_completions(env, "login", "")) == (os.geteuid() == 0)


def test_bash_install_as_value_does_not_complete_container_or_host_names(tmp_path):
    (tmp_path / "chroot-distro/containers/taken/rootfs").mkdir(parents=True)
    env = {**os.environ, "XDG_DATA_HOME": str(tmp_path)}

    assert _bash_completions(env, "build", "--inst") == ["--install-as"]
    assert _bash_completions(env, "build", "--install-as", "ta") == []
    assert _bash_completions(env, "build", "--install-as", "=", "ta") == []
    assert _bash_completions(env, "build", "--install-as", "fresh", "ta") == ["taken"]

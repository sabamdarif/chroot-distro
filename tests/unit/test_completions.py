import os
import shutil
import subprocess
from pathlib import Path

import pytest


@pytest.mark.skipif(os.name != "posix" or shutil.which("bash") is None, reason="POSIX Bash is unavailable")
def test_bash_container_completion_uses_literal_names(tmp_path):
    containers = tmp_path / "chroot-distro" / "containers"
    for name in ("valid-name_0.1", "$(printf injected)", "invalid space", "line\n", "évil"):
        (containers / name / "rootfs").mkdir(parents=True)
    (containers / "missing-rootfs").mkdir()

    completion = Path(__file__).resolve().parents[2] / "src/chroot_distro/completions/chroot-distro.bash"
    result = subprocess.run(
        [
            "bash",
            "--noprofile",
            "--norc",
            "-c",
            r"""
source "$1"
_chroot_distro_is_termux() { return 1; }
_init_completion() { cur=''; prev=login; words=(chroot-distro login ''); cword=2; }
_chroot_distro
printf '%s\n' "${COMPREPLY[@]}"
""",
            "bash",
            str(completion),
        ],
        env={**os.environ, "XDG_DATA_HOME": str(tmp_path)},
        capture_output=True,
        text=True,
        check=True,
    )

    assert result.stderr == ""
    assert result.stdout.splitlines() == ["valid-name_0.1"]

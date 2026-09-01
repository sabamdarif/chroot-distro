# `build --install-as <name>` refuses a name that is already taken, and the
# question "is it taken?" is the one thing standing between the build and an
# install that writes over a container. os.path.isdir() on the composed path
# answers it through whatever is in the way: a guest that left
# `containers/<name> -> <host dir>` behind (on Termux the runtime tree is under
# the $PREFIX bound read-write into every non-isolated container) was told the
# name was free whenever that directory held no rootfs, and the install then
# unpacked through the link.

from types import SimpleNamespace

import pytest

from chroot_distro import paths
from chroot_distro.arch import Platform
from chroot_distro.commands.build import command_build
from chroot_distro.exceptions import ChrootDistroError


@pytest.fixture
def build_dir(tmp_path):
    d = tmp_path / "ctx"
    d.mkdir()
    (d / "Dockerfile").write_text("FROM alpine\n")
    return d


def _args(build_dir, install_as):
    return SimpleNamespace(path=str(build_dir), install_as=install_as, quiet=True)


@pytest.fixture
def containers(monkeypatch, tmp_path):
    root = tmp_path / "containers"
    root.mkdir()
    monkeypatch.setattr(paths, "CONTAINERS_DIR", str(root))
    return root


def test_a_planted_container_entry_stops_the_build(build_dir, containers, tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (containers / "victim").symlink_to(outside)

    with pytest.raises(ChrootDistroError) as exc:
        command_build(_args(build_dir, "victim"))

    assert "not usable" in str(exc.value)
    assert list(outside.iterdir()) == []


def test_an_installed_name_is_still_refused(build_dir, containers, capsys):
    (containers / "taken" / "rootfs").mkdir(parents=True)

    with pytest.raises(SystemExit):
        command_build(_args(build_dir, "taken"))

    assert "already" in capsys.readouterr().err


def test_a_free_name_gets_past_the_guard(build_dir, containers, monkeypatch):
    # The guard is not a refusal machine: a name nothing stands under has to
    # reach the build itself, which here is only asked to fail recognisably.
    def boom(*_a, **_k):
        raise ChrootDistroError("reached the build")

    monkeypatch.setattr("chroot_distro.commands.build.BuildLock", boom)

    with pytest.raises(ChrootDistroError, match="reached the build"):
        command_build(_args(build_dir, "free"))


def test_foreign_build_with_run_refuses_without_an_emulator(build_dir, monkeypatch, capsys):
    (build_dir / "Dockerfile").write_text("FROM alpine\nRUN echo hello\n")
    monkeypatch.setattr("chroot_distro.commands.build.get_device_platform", lambda: Platform("linux", "amd64"))
    monkeypatch.setattr("chroot_distro.commands.build.needs_emulation", lambda _arch: True)
    monkeypatch.setattr(
        "chroot_distro.commands.build.ensure_handler",
        lambda _arch: (None, "no QEMU user-mode emulator is installed"),
    )

    with pytest.raises(SystemExit) as exc:
        command_build(SimpleNamespace(path=str(build_dir), override_arch="aarch64", quiet=True))

    assert exc.value.code == 1
    assert "RUN steps cannot execute" in capsys.readouterr().err


def test_foreign_build_without_run_says_nothing_about_an_emulator(build_dir, monkeypatch, capsys):
    # `FROM alpine` alone execs nothing, so the preflight has nothing to refuse
    # and nothing to advise: the cross-compile shape must not be told to install
    # QEMU it will never call. run_step asks again if a step does reach an exec.
    monkeypatch.setattr("chroot_distro.commands.build.get_device_platform", lambda: Platform("linux", "amd64"))
    monkeypatch.setattr("chroot_distro.commands.build.needs_emulation", lambda _arch: True)
    monkeypatch.setattr(
        "chroot_distro.commands.build.ensure_handler",
        lambda _arch: (None, "no QEMU user-mode emulator is installed"),
    )

    def boom(*_args, **_kwargs):
        raise ChrootDistroError("reached the build")

    monkeypatch.setattr("chroot_distro.commands.build.BuildLock", boom)
    with pytest.raises(ChrootDistroError, match="reached the build"):
        command_build(SimpleNamespace(path=str(build_dir), override_arch="aarch64", quiet=True))

    assert "no emulator was registered" not in capsys.readouterr().err


def test_a_run_on_the_build_platform_needs_no_emulator(build_dir, monkeypatch, capsys):
    # The cross-compile shape: the stage that runs is the host's own, and the
    # foreign stage only assembles files, so the RUN does not ask for an emulator.
    (build_dir / "Dockerfile").write_text(
        "FROM --platform=$BUILDPLATFORM alpine AS builder\n"
        "RUN make\n"
        "FROM alpine\n"
        "COPY --from=builder /app /app\n"
    )
    monkeypatch.setattr("chroot_distro.commands.build.get_device_platform", lambda: Platform("linux", "amd64"))
    monkeypatch.setattr("chroot_distro.commands.build.needs_emulation", lambda arch: arch != "x86_64")
    monkeypatch.setattr(
        "chroot_distro.commands.build.ensure_handler",
        lambda _arch: (None, "no QEMU user-mode emulator is installed"),
    )

    def boom(*_args, **_kwargs):
        raise ChrootDistroError("reached the build")

    monkeypatch.setattr("chroot_distro.commands.build.BuildLock", boom)
    with pytest.raises(ChrootDistroError, match="reached the build"):
        command_build(SimpleNamespace(path=str(build_dir), override_arch="aarch64", quiet=True))

    assert "RUN steps cannot execute" not in capsys.readouterr().err

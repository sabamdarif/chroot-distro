from contextlib import nullcontext
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from chroot_distro.commands import install


@pytest.mark.parametrize(
    ("ref", "expected"),
    [
        ("/abs/path.tar", True),
        ("./rel.tar", True),
        ("../up.tar", True),
        ("~/home.tar", True),
        ("ubuntu:22.04", False),
        ("http://x/y.tar", False),
    ],
)
def test_is_local_path(ref, expected):
    assert install._is_local_path(ref) is expected


@pytest.mark.parametrize(
    ("ref", "expected"),
    [
        ("http://x/y", True),
        ("https://x/y", True),
        ("ftp://x/y", False),
        ("/local", False),
    ],
)
def test_is_url(ref, expected):
    assert install._is_url(ref) is expected


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("/tmp/Ubuntu-22.04.tar.gz", "ubuntu-22.04"),
        ("archlinux.tar.xz", "archlinux"),
        ("my_image.oci.tar", "my_image"),
        ("Sample.OCI.TAR.GZ", "sample"),
        ("sample.oci.tar.xz", "sample"),
        ("sample.oci.tar.bz2", "sample"),
        ("sample.oci.tar.zst", "sample"),
        ("sample.oci.tar.zstd", "sample"),
        ("sample.tar.zst", "sample"),
        ("sample.tar.zstd", "sample"),
        ("sample.tzst", "sample"),
        ("Weird Name!.tgz", "weird-name"),
        ("--leading.tar", "leading"),
        ("a___b.tar", "a___b"),
    ],
)
def test_derive_local_name(path, expected):
    assert install._derive_local_name(path) == expected


@pytest.mark.parametrize(
    ("url", "name", "expected"),
    [
        ("https://example.com:8443/images/Sample.OCI.TAR.GZ?token=x#fragment", None, "sample"),
        ("https://[::1]:8080/images/root.tar.zst", None, "root"),
        ("https://example.com/archive%20name.tar", None, "archive-20name"),
        ("https://example.com?token=x#fragment", "custom", "custom"),
        ("https://example.com/download/", "custom", "custom"),
    ],
)
def test_install_derives_url_name_and_passes_original_url(monkeypatch, url, name, expected):
    run_install = Mock()
    monkeypatch.setattr(install, "_run_install", run_install)
    monkeypatch.setattr(install, "ContainerLock", lambda *args, **kwargs: nullcontext())
    args = SimpleNamespace(image_ref=[url], custom_container_name=name, override_arch="x86_64")

    install.command_install(args)

    run_install.assert_called_once_with(expected, url, None, url, "x86_64", insecure=False)


@pytest.mark.parametrize(
    ("url", "name", "message"),
    [
        ("https://example.com?token=secret", None, "--name NAME"),
        ("https://user:secret@example.com/download/#secret", None, "--name NAME"),
        ("https://user:secret@[::1/image.tar", "custom", "invalid archive URL"),
        ("https://user:secret@example.com:65536/image.tar", "custom", "invalid archive URL"),
        ("https://example.com:secret/image.tar", "custom", "invalid archive URL"),
        ("https:///image.tar?token=secret", "custom", "invalid archive URL"),
        ("https://exa mple.com/image.tar?token=secret", "custom", "invalid archive URL"),
    ],
)
def test_install_rejects_url_before_lock_without_echoing_input(monkeypatch, capsys, url, name, message):
    lock = Mock()
    monkeypatch.setattr(install, "ContainerLock", lock)
    args = SimpleNamespace(image_ref=[url], custom_container_name=name)

    with pytest.raises(SystemExit) as exc:
        install.command_install(args)

    assert exc.value.code == 1
    lock.assert_not_called()
    error = capsys.readouterr().err
    assert message in error
    assert "secret" not in error


@pytest.mark.parametrize(
    ("ref", "arch", "message"),
    [
        ("./\x1bmissing.tar", None, r"./\emissing.tar"),
        ("alpine", "\x1bunknown", r"\eunknown"),
    ],
)
def test_install_escapes_archive_path_and_architecture(capsys, ref, arch, message):
    with pytest.raises(SystemExit):
        install.command_install(SimpleNamespace(image_ref=[ref], override_arch=arch))

    assert message in capsys.readouterr().err

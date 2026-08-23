# Containment test for where `build --output` packs the archive it publishes.
#
# The tarball used to be opened by the temporary's *name*: the staging helper
# created the file off the descriptor its walk had validated, closed it, and
# handed back the path for the caller to open a second time. The name is this
# program's, but the directory it stands in is the user's -- `--output
# /tmp/img.tar` stages beside the destination, in a directory anyone sharing the
# machine can read -- so between the create and the reopen the temporary can be
# found in readdir(), unlinked, and replaced with a symlink, and the archive's
# bytes then land on whatever that named.

import contextlib
import json
import os
import tarfile

import pytest

from chroot_distro import atomic
from chroot_distro.helpers import oci_writer

IMAGE_CONFIG = {"architecture": "amd64", "os": "linux", "config": {"Cmd": ["/bin/sh"]}}


def _write(out_path):
    manifest = {
        "schemaVersion": 2,
        "config": {"digest": "sha256:" + "0" * 64, "size": 0},
        "layers": [],
    }
    oci_writer.write_oci_archive(out_path, manifest, IMAGE_CONFIG, "test:latest")


@pytest.fixture
def decoy(tmp_path):
    path = tmp_path / "decoy"
    path.write_text("host content\n")
    return path


def test_the_published_archive_holds_the_whole_image(tmp_path):
    out = tmp_path / "img.tar"
    _write(str(out))

    with tarfile.open(out) as tf:
        names = tf.getnames()
        config_name = json.loads(tf.extractfile("manifest.json").read())[0]["Config"]
        config = json.loads(tf.extractfile(config_name).read())

    assert names[0] == "oci-layout"
    assert "index.json" in names
    assert config == IMAGE_CONFIG


def test_a_temporary_swapped_for_a_symlink_is_not_written_through(tmp_path, monkeypatch, decoy):
    staged = atomic._staged

    @contextlib.contextmanager
    def swapping(path, suffix, mode):
        with staged(path, suffix, mode) as (fd, tmp):
            os.unlink(tmp)
            os.symlink(decoy, tmp)
            yield fd, tmp

    monkeypatch.setattr(atomic, "_staged", swapping)

    out = tmp_path / "img.tar"
    _write(str(out))

    assert decoy.read_text() == "host content\n"
    assert os.path.islink(out)

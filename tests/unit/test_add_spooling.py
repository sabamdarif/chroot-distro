# ADD reads content nobody local chose the size of: an HTTP response, and every
# regular member of an archive it auto-extracts. A file_map covers a whole
# COPY/ADD instruction and is consumed only once the instruction ends, so an
# entry holding bytes holds them that long and every member of an extracted
# archive holds them at the same time. Content that is not already a file is
# spooled to one.
#
# The sniff that sends a source to the extractor is a signature, and a
# signature is all it can be: gzip, bzip2 and xz magic say "compressed", not
# "compressed tar".

import http.client
import io
import os
import sys

if sys.version_info >= (3, 14):
    import tarfile
else:
    from backports.zstd import tarfile

import gzip

import pytest

from chroot_distro import dirfd
from chroot_distro.helpers.build_engine import copy_step
from chroot_distro.helpers.build_engine.errors import BuildError


@pytest.fixture
def spool(tmp_path):
    d = tmp_path / "spool"
    d.mkdir()
    sp = copy_step._Spool(str(d), dirfd.opendir(str(d)))
    yield sp
    sp.close()


def _make_tar(path, entries):
    """Write a tar at *path* from (name, kind, payload, mtime) tuples."""
    with tarfile.open(path, "w") as tf:
        for name, kind, payload, mtime in entries:
            info = tarfile.TarInfo(name)
            info.mtime = mtime
            if kind == "dir":
                info.type = tarfile.DIRTYPE
                info.mode = 0o755
                tf.addfile(info)
            elif kind == "symlink":
                info.type = tarfile.SYMTYPE
                info.linkname = payload
                tf.addfile(info)
            else:
                info.size = len(payload)
                info.mode = 0o644
                tf.addfile(info, io.BytesIO(payload))


def _extract(path, dest, file_map, spool):
    """Auto-extract *path* the way ADD does: by descriptor, off its own tree."""
    tree = copy_step._SourceTree(os.path.dirname(path))
    return copy_step._extract_archive(tree, [os.path.basename(path)], dest, file_map, 0, 0, spool)


def _assert_no_bytes_held(file_map):
    for arcname, entry in file_map.items():
        assert "data" not in entry, f"{arcname} holds its content in memory"
        assert entry["kind"] != "content", arcname
        if entry["kind"] == "file":
            assert os.path.isfile(entry["src"]), arcname


def test_auto_extracted_members_are_spooled(tmp_path, spool):
    arc = tmp_path / "payload.tar"
    _make_tar(
        str(arc),
        [
            ("a", "file", b"A" * 4096, 0),
            ("b", "file", b"B" * 4096, 0),
            ("d", "dir", None, 0),
            ("d/link", "symlink", "../a", 0),
        ],
    )
    file_map = {}
    assert _extract(str(arc), "extracted", file_map, spool) == 4

    _assert_no_bytes_held(file_map)
    with open(file_map["extracted/a"]["src"], "rb") as fh:
        assert fh.read() == b"A" * 4096
    # Each member gets its own spool file rather than sharing one.
    assert file_map["extracted/a"]["src"] != file_map["extracted/b"]["src"]
    # Non-content members still describe themselves inline.
    assert file_map["extracted/d"]["kind"] == "dir"
    assert file_map["extracted/d/link"]["kind"] == "symlink"


def test_member_mtime_survives_the_spool(tmp_path, spool):
    # layer_diff's "file" kind reads mtime off the file, not off the entry, so
    # the archive's timestamp has to land on the spool file itself.
    arc = tmp_path / "payload.tar"
    _make_tar(str(arc), [("a", "file", b"A", 1234567890)])
    file_map = {}
    _extract(str(arc), "extracted", file_map, spool)

    assert int(os.stat(file_map["extracted/a"]["src"]).st_mtime) == 1234567890


def test_an_absurd_member_mtime_does_not_raise(tmp_path, spool):
    # os.utime() raises OverflowError, not OSError, on a value the platform
    # cannot store — and the value comes out of a guest-written header.
    arc = tmp_path / "payload.tar"
    _make_tar(str(arc), [("a", "file", b"A", 2**63)])
    file_map = {}
    _extract(str(arc), "extracted", file_map, spool)

    assert os.path.isfile(file_map["extracted/a"]["src"])


def test_url_response_is_spooled(spool, monkeypatch):
    body = b"N" * (1 << 20)

    class _Resp(io.BytesIO):
        headers = {"Content-Length": str(len(body))}

        def __enter__(self):
            return self

        def __exit__(self, *_a):
            self.close()
            return False

    class _Opener:
        def open(self, _url):
            return _Resp(body)

    monkeypatch.setattr(copy_step.urllib.request, "build_opener", lambda *_a: _Opener())

    file_map = {}
    copy_step._copy_url("https://example.invalid/blob.bin", "/opt/blob.bin", file_map, 0, 0, None, spool)

    _assert_no_bytes_held(file_map)
    with open(file_map["opt/blob.bin"]["src"], "rb") as fh:
        assert fh.read() == body


# ── a signature is not an archive ─────────────────────────────────────────────
def test_a_gzip_that_is_not_a_tar_records_nothing(tmp_path, spool):
    src = tmp_path / "data.gz"
    src.write_bytes(gzip.compress(b"just some bytes, no tar headers here"))
    file_map = {}

    assert _extract(str(src), "dest", file_map, spool) == 0
    assert file_map == {}


def test_add_copies_a_non_archive_gzip_verbatim(tmp_path, spool):
    # Docker copies a file its own archive probe rejects, and the gzip magic
    # that got this here says "compressed", not "compressed tar".
    src = tmp_path / "data.gz"
    src.write_bytes(gzip.compress(b"payload"))
    file_map = {}

    copy_step._add_to_file_map(
        copy_step._SourceTree(str(tmp_path)),
        ["data.gz"],
        os.lstat(src),
        "/opt/",
        is_dir_dest=True,
        file_map=file_map,
        uid=0,
        gid=0,
        mode_override=None,
        auto_extract=True,
        src_rel="data.gz",
        ignore_patterns=[],
        spool=spool,
    )

    assert file_map["opt/data.gz"]["kind"] == "file"
    assert file_map["opt/data.gz"]["src"] == str(src)


def test_a_truncated_archive_names_the_source(tmp_path, spool):
    arc = tmp_path / "payload.tar"
    _make_tar(str(arc), [("a", "file", b"A" * 4096, 0), ("b", "file", b"B" * 4096, 0)])
    whole = arc.read_bytes()
    arc.write_bytes(whole[: 512 + 4096 + 512 + 1024])
    file_map = {}

    with pytest.raises(BuildError, match="cannot extract"):
        _extract(str(arc), "extracted", file_map, spool)


# ── a response that ends early ────────────────────────────────────────────────
# ADD has no digest to check its download against, so a truncated body is
# caught nowhere downstream: the short bytes land in the rootfs and in the layer
# `push` uploads, under the name of the whole file.
def _add_url(spool, monkeypatch, resp_factory):
    """Run one ADD <url> against a response *resp_factory* makes."""

    class _Opener:
        def open(self, _url):
            return resp_factory()

    monkeypatch.setattr(copy_step.urllib.request, "build_opener", lambda *_a: _Opener())
    file_map = {}
    copy_step._copy_url("https://example.invalid/blob.bin", "/opt/blob.bin", file_map, 0, 0, None, spool)
    return file_map


class _Resp(io.BytesIO):
    """A response body with headers, entered and exited like urllib's."""

    headers: dict = {}

    def __enter__(self):
        return self

    def __exit__(self, *_a):
        self.close()
        return False


def test_a_body_short_of_its_declared_length_is_refused(spool, monkeypatch):
    class _Short(_Resp):
        headers = {"Content-Length": "1048576"}

    with pytest.raises(BuildError, match="4096 of 1048576"):
        _add_url(spool, monkeypatch, lambda: _Short(b"N" * 4096))


def test_a_body_cut_mid_chunk_is_a_build_error(spool, monkeypatch):
    # A chunked body has no declared length to check, and the read raises
    # http.client.IncompleteRead — not an OSError, so it used to walk out of
    # here and out of `build` as a traceback.
    class _Cut(_Resp):
        def read(self, *_a):
            raise http.client.IncompleteRead(b"partial", 900)

    with pytest.raises(BuildError, match="IncompleteRead"):
        _add_url(spool, monkeypatch, lambda: _Cut(b""))


def test_a_length_the_remote_wrote_by_hand_is_treated_as_absent(spool, monkeypatch):
    # int() on a header the remote chose is a ValueError nothing here catches,
    # and http.client's own answer to one it cannot parse is to read on.
    class _Nonsense(_Resp):
        headers = {"Content-Length": "not a number"}

    file_map = _add_url(spool, monkeypatch, lambda: _Nonsense(b"payload"))

    with open(file_map["opt/blob.bin"]["src"], "rb") as fh:
        assert fh.read() == b"payload"


def test_a_body_past_its_declared_length_is_kept_whole(spool, monkeypatch):
    # The check is short-of-declared only: more bytes than announced is the
    # remote disagreeing with itself, not a download this program cut off.
    class _Long(_Resp):
        headers = {"Content-Length": "4"}

    file_map = _add_url(spool, monkeypatch, lambda: _Long(b"payload"))

    with open(file_map["opt/blob.bin"]["src"], "rb") as fh:
        assert fh.read() == b"payload"

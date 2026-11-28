# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
"""Read tar archives through their compression trailers, including from pipes."""

import bz2
import contextlib
import gzip
import io
import lzma
import sys
import typing
import zlib
from collections.abc import Iterator

if sys.version_info >= (3, 14):
    import tarfile as tar

    from compression import zstd
else:
    from backports import zstd
    from backports.zstd import tarfile as tar

from chroot_distro.progress import ByteCounter

_MAGIC_COMPRESS = (
    (b"\x1f\x8b\x08", "gz"),
    (b"\xfd7zXZ\x00", "xz"),
    (b"\x5d\x00", "xz"),
    (b"\x28\xb5\x2f\xfd", "zst"),
)


def detect_compression(header: bytes) -> str:
    """Return the tarfile mode suffix inferred from the header."""
    if header.startswith(b"BZh") and b"1" <= header[3:4] <= b"9" and header[4:10] in (b"1AY&SY", b"\x17rE8P\x90"):
        return "bz2"
    for magic, mode in _MAGIC_COMPRESS:
        if header.startswith(magic):
            return mode
    return ""


class _TarInput(io.RawIOBase):
    """Replay the compression header before continuing from a pipe."""

    def __init__(self, source: ByteCounter) -> None:
        self._source = source
        self.header = source.read(10)
        while len(self.header) < 10:
            chunk = source.read(10 - len(self.header))
            if not chunk:
                break
            self.header += chunk

    def readable(self) -> bool:
        return True

    def readinto(self, buffer, /) -> int:
        if not self.header:
            return typing.cast(int, self._source.readinto(buffer))
        view = memoryview(buffer)
        size = min(len(view), len(self.header))
        view[:size] = self.header[:size]
        self.header = self.header[size:]
        return size


class _StrictTarInfo(tar.TarInfo):
    """Distinguish a complete tar archive from a bad or missing header."""

    @classmethod
    def fromtarfile(cls, tarfile: tar.TarFile) -> "_StrictTarInfo":
        try:
            return super().fromtarfile(tarfile)
        except tar.EOFHeaderError:  # type: ignore[attr-defined]
            stream = tarfile.fileobj
            if stream.read(tar.BLOCKSIZE) != bytes(tar.BLOCKSIZE):
                raise tar.ReadError("tar archive must end with two zero blocks") from None
            while padding := stream.read(1 << 17):
                if padding.count(0) != len(padding):
                    raise tar.ReadError("unexpected data after the tar terminator") from None
            raise
        except tar.HeaderError as exc:
            raise tar.ReadError(f"invalid tar header or terminator: {exc}") from exc


@contextlib.contextmanager
def open_tar(source: ByteCounter, *, seekable: bool = False) -> Iterator[tar.TarFile]:
    """Open a tar at the input's current offset. Exhaust its iterator to check EOF."""
    with contextlib.ExitStack() as resources:
        stream: typing.Any = source
        if seekable:
            offset = source.tell()
            header = source.read(10)
            source.seek(offset)
        else:
            replay = _TarInput(source)
            header = replay.header
            stream = resources.enter_context(io.BufferedReader(replay))

        try:
            compression = detect_compression(header)
            decoded = stream
            if compression == "gz":
                decoded = resources.enter_context(gzip.GzipFile(fileobj=stream, mode="rb"))
            elif compression == "bz2":
                decoded = resources.enter_context(bz2.BZ2File(stream))
            elif compression == "xz":
                decoded = resources.enter_context(lzma.LZMAFile(stream))
            elif compression == "zst":
                decoded = resources.enter_context(zstd.ZstdFile(stream))
            mode = "r:" if seekable else "r|"
            yield resources.enter_context(
                tar.open(fileobj=decoded, mode=mode, tarinfo=_StrictTarInfo, stream=True)  # type: ignore[call-overload]
            )
        except (EOFError, gzip.BadGzipFile, lzma.LZMAError, zlib.error, zstd.ZstdError) as exc:
            raise tar.ReadError(f"incomplete or invalid compressed tar: {exc}") from exc

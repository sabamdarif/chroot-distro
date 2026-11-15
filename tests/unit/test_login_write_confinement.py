"""Login profile and hostname edits stay beneath the opened guest root."""

import contextlib
import errno
import os
import stat

import pytest

from chroot_distro import dirfd
from chroot_distro.commands.login import env
from chroot_distro.helpers import rootfs


@pytest.fixture
def guest(tmp_path, monkeypatch):
    root = tmp_path / "guest"
    (root / "etc/profile.d").mkdir(parents=True)
    (root / "etc/hosts").write_text("127.0.0.1 localhost\n")
    monkeypatch.setattr(os, "fchown", lambda fd, uid, gid: None)
    return root


def leaf(root, kind):
    return root / ("etc/hosts" if kind == "hosts" else "etc/profile.d/chroot-profile.sh")


def update(root, kind):
    if kind == "hosts":
        rootfs.ensure_hosts_entry(str(root), "box")
    else:
        env.inject_env_profile(str(root), {"FOO": "value"}, owner_uid=123, owner_gid=456)


def snapshot(path):
    st = path.stat()
    return path.read_bytes(), stat.S_IMODE(st.st_mode), st.st_uid, st.st_gid, st.st_ino


@pytest.mark.parametrize("kind", ["profile", "hosts"])
@pytest.mark.parametrize("link", ["symlink", "hardlink"])
def test_final_links_leave_host_unchanged(guest, tmp_path, kind, link):
    outside = tmp_path / "host-file"
    outside.write_text("KEEP\n")
    outside.chmod(0o640)
    dest = leaf(guest, kind)
    dest.unlink(missing_ok=True)
    if link == "symlink":
        dest.symlink_to(outside)
    else:
        dest.hardlink_to(outside)
    before = snapshot(outside)

    update(guest, kind)

    assert snapshot(outside) == before
    if kind == "profile":
        assert not dest.is_symlink()
        assert dest.read_text() == "export FOO='value'\n"
        assert stat.S_IMODE(dest.stat().st_mode) == 0o600
    else:
        assert os.path.samestat(dest.lstat(), outside.stat()) if link == "hardlink" else dest.is_symlink()


@pytest.mark.parametrize("kind", ["profile", "hosts"])
@pytest.mark.parametrize("absolute", [False, True])
def test_guest_parent_aliases(guest, kind, absolute):
    (guest / "state").mkdir()
    (guest / "etc").rename(guest / "state/etc")
    (guest / "etc").symlink_to(("/" if absolute else "") + "state/etc")

    update(guest, kind)

    assert "box" in leaf(guest / "state", kind).read_text() if kind == "hosts" else (
        leaf(guest / "state", kind).read_text() == "export FOO='value'\n"
    )


@pytest.mark.parametrize("kind", ["profile", "hosts"])
def test_external_parent_is_not_followed(guest, tmp_path, kind):
    outside = tmp_path / "outside"
    (outside / "profile.d").mkdir(parents=True)
    sentinel = outside / ("hosts" if kind == "hosts" else "profile.d/chroot-profile.sh")
    sentinel.write_text("KEEP\n")
    before = snapshot(sentinel)
    (guest / "etc").rename(guest / "saved-etc")
    (guest / "etc").symlink_to(outside)

    update(guest, kind)

    assert snapshot(sentinel) == before
    assert sorted(p.relative_to(outside).as_posix() for p in outside.rglob("*")) == (
        ["hosts", "profile.d"] if kind == "hosts" else ["profile.d", "profile.d/chroot-profile.sh"]
    )


@pytest.mark.parametrize("kind", ["profile", "hosts"])
def test_parent_replaced_before_guarded_walk_is_refused(guest, tmp_path, monkeypatch, kind):
    module = rootfs if kind == "hosts" else env
    resolve = module.safe_resolve_parts_at
    outside = tmp_path / "outside"
    (outside / "profile.d").mkdir(parents=True)
    sentinel = outside / ("hosts" if kind == "hosts" else "profile.d/chroot-profile.sh")
    sentinel.write_text("KEEP\n")

    def swap(fd, parts):
        result = resolve(fd, parts)
        (guest / "etc").rename(guest / "saved-etc")
        (guest / "etc").symlink_to(outside)
        return result

    monkeypatch.setattr(module, "safe_resolve_parts_at", swap)
    update(guest, kind)

    assert sentinel.read_text() == "KEEP\n"
    assert "box" not in (guest / "saved-etc/hosts").read_text()
    assert not (guest / "saved-etc/profile.d/chroot-profile.sh").exists()


@pytest.mark.parametrize("kind", ["profile", "hosts"])
def test_root_replacement_after_open_uses_pin(guest, tmp_path, monkeypatch, kind):
    module = rootfs if kind == "hosts" else env
    resolve = module.safe_resolve_parts_at
    saved = tmp_path / "saved"
    outside = tmp_path / "outside"
    outside.mkdir()

    def swap(fd, parts):
        guest.rename(saved)
        guest.symlink_to(outside)
        return resolve(fd, parts)

    monkeypatch.setattr(module, "safe_resolve_parts_at", swap)
    update(guest, kind)

    assert list(outside.iterdir()) == []
    assert "box" in leaf(saved, kind).read_text() if kind == "hosts" else leaf(saved, kind).is_file()


@pytest.mark.parametrize("kind", ["profile", "hosts", "stale-profile"])
def test_parent_replaced_after_pin_keeps_writes_and_cleanup_in_original(guest, tmp_path, monkeypatch, kind):
    profile = guest / "etc/profile.d"
    for name in ("chroot-profile.sh", "termux-profile.sh", "termux-prefix.sh"):
        (profile / name).write_text("OLD\n")
    parent = guest / ("etc" if kind == "hosts" else "etc/profile.d")
    parent_stat = parent.stat()
    saved = tmp_path / "saved"
    outside = tmp_path / "outside"
    outside.mkdir()
    for name in ("hosts", "chroot-profile.sh", "termux-profile.sh", "termux-prefix.sh"):
        (outside / name).write_text("KEEP\n")
    before = {p.name: snapshot(p) for p in outside.iterdir()}
    descend = dirfd.descend_at

    def swap(fd, parts, **kwargs):
        result = descend(fd, parts, **kwargs)
        if os.path.samestat(os.fstat(result), parent_stat):
            parent.rename(saved)
            parent.symlink_to(outside)
        return result

    monkeypatch.setattr(dirfd, "descend_at", swap)
    if kind == "stale-profile":
        env.inject_env_profile(str(guest), {})
    else:
        update(guest, kind)

    assert {p.name: snapshot(p) for p in outside.iterdir()} == before
    if kind == "hosts":
        assert "box" in (saved / "hosts").read_text()
    else:
        assert not (saved / "termux-profile.sh").exists()
        assert not (saved / "termux-prefix.sh").exists()
        if kind == "stale-profile":
            assert list(saved.iterdir()) == []
        else:
            assert (saved / "chroot-profile.sh").read_text() == "export FOO='value'\n"


@pytest.mark.parametrize("kind", ["profile", "hosts"])
@pytest.mark.parametrize("failure", [OSError(errno.EIO, "injected write failure"), KeyboardInterrupt()])
def test_failure_before_publication_preserves_original(guest, monkeypatch, kind, failure):
    module = rootfs if kind == "hosts" else env
    dest = leaf(guest, kind)
    dest.write_text("OLD\n")
    before = snapshot(dest)
    write = module.atomic_write

    @contextlib.contextmanager
    def fail(*args, **kwargs):
        with write(*args, **kwargs) as fh:
            yield fh
            raise failure

    monkeypatch.setattr(module, "atomic_write", fail)
    if isinstance(failure, KeyboardInterrupt):
        with pytest.raises(KeyboardInterrupt):
            update(guest, kind)
    else:
        update(guest, kind)

    assert snapshot(dest) == before
    assert list(dest.parent.glob(dest.name + ".*")) == []


@pytest.mark.parametrize("kind", ["profile", "hosts"])
@pytest.mark.parametrize("entry", ["fifo", "directory", "loop", "missing"])
def test_unsafe_or_missing_entries_do_not_block(guest, kind, entry):
    dest = leaf(guest, kind)
    dest.unlink(missing_ok=True)
    if entry == "fifo":
        os.mkfifo(dest)
    elif entry == "directory":
        dest.mkdir()
    elif entry == "loop":
        dest.symlink_to(dest.name)
    before = dest.lstat() if entry != "missing" else None

    update(guest, kind)

    if kind == "profile" and entry != "directory":
        assert dest.read_text() == "export FOO='value'\n"
    elif before is not None:
        assert os.path.samestat(before, dest.lstat())
    else:
        assert not dest.exists()


@pytest.mark.parametrize("kind", ["profile", "hosts"])
@pytest.mark.parametrize("entry", ["missing", "loop"])
def test_missing_or_looping_parent_is_skipped(guest, kind, entry):
    parent = guest / "etc"
    parent.rename(guest / "saved-etc")
    if entry == "loop":
        parent.symlink_to("etc")

    update(guest, kind)

    assert parent.is_symlink() if entry == "loop" else not parent.exists()
    assert not (guest / "saved-etc/profile.d/chroot-profile.sh").exists()
    assert "box" not in (guest / "saved-etc/hosts").read_text()


def test_profile_owner_is_applied_to_private_staged_descriptor(guest, monkeypatch):
    dest = leaf(guest, "profile")
    dest.write_text("OLD\n")
    before = snapshot(dest)
    calls = []

    def chown(fd, uid, gid):
        st = os.fstat(fd)
        assert stat.S_IMODE(st.st_mode) == 0o600
        assert st.st_ino != before[-1]
        assert snapshot(dest) == before
        calls.append((st.st_ino, uid, gid))

    monkeypatch.setattr(os, "fchown", chown)
    update(guest, "profile")

    assert calls == [(dest.stat().st_ino, 123, 456)]
    assert stat.S_IMODE(dest.stat().st_mode) == 0o600


@pytest.mark.parametrize("absolute", [False, True])
def test_hosts_leaf_alias_and_idempotence_preserve_content_and_mode(guest, monkeypatch, absolute):
    hosts = leaf(guest, "hosts")
    target = guest / "etc/real-hosts"
    hosts.rename(target)
    hosts.symlink_to("/etc/real-hosts" if absolute else "real-hosts")
    target.write_text("# keep\n127.0.0.1 localhost alias")
    target.chmod(0o640)
    original = target.stat()
    owners = []
    monkeypatch.setattr(os, "fchown", lambda fd, uid, gid: owners.append((uid, gid)))

    rootfs.ensure_hosts_entry(str(guest), "localhost", "box", "box", "", "alias")
    after = snapshot(target)
    rootfs.ensure_hosts_entry(str(guest), "box", "localhost")

    assert target.read_text() == "# keep\n127.0.0.1 localhost alias\n127.0.0.1   box\n"
    assert snapshot(target) == after
    assert hosts.is_symlink()
    assert after[1] == 0o640
    assert owners == [(original.st_uid, original.st_gid)]


def test_hosts_invalid_text_is_skipped(guest):
    hosts = leaf(guest, "hosts")
    hosts.write_bytes(b"\xff\n")
    before = snapshot(hosts)

    update(guest, "hosts")

    assert snapshot(hosts) == before


def test_termux_profile_directory_alias_and_quoting(guest):
    prefix = "/data/data/com.termux/files/usr"
    (guest / prefix.lstrip("/") / "etc").mkdir(parents=True)
    (guest / prefix.lstrip("/") / "etc/profile.d").symlink_to("/etc/profile.d")

    env.inject_env_profile(
        str(guest), {"FOO": "a'b"}, guest_prefix=prefix, append_termux_bin=True
    )

    content = leaf(guest, "profile").read_text()
    assert "export FOO='a'\\''b'" in content
    assert f'export PATH="${{PATH}}:{env.TERMUX_PREFIX}/bin"' in content


def test_profile_directory_alias_to_guest_root(guest):
    profile = guest / "etc/profile.d"
    profile.rmdir()
    profile.symlink_to("/")

    update(guest, "profile")

    assert (guest / "chroot-profile.sh").read_text() == "export FOO='value'\n"

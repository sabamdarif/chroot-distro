"""Android install fixups retain guest descriptors and refuse shared files."""

import contextlib
import errno
import os
import stat
from types import SimpleNamespace

import pytest

from chroot_distro import dirfd
from chroot_distro.helpers import android, rootfs


@pytest.fixture
def guest(tmp_path, monkeypatch):
    root = tmp_path / "guest"
    etc = root / "etc"
    etc.mkdir(parents=True)
    (etc / "passwd").write_text("root:x:0:0::/root:/bin/sh\n_apt:x:42:65534::/:/bin/false\n")
    (etc / "group").write_text("root:x:0:\n")
    (etc / "shadow").write_text("root:*:::::::\n")
    (etc / "gshadow").write_text("root:*::\n")
    (etc / "adduser.conf").write_text("CONFIG=1\n")
    monkeypatch.setattr(android, "IS_TERMUX", True)
    monkeypatch.setattr(rootfs, "IS_TERMUX", True)
    monkeypatch.setattr(rootfs.pwd, "getpwuid", lambda uid: SimpleNamespace(pw_name="app"))
    monkeypatch.setattr(rootfs, "termux_home_owner_ids", lambda: (10123, 10123))
    monkeypatch.setattr(rootfs.os, "getgroups", lambda: [10123, 9999])
    monkeypatch.setattr(rootfs.grp, "getgrgid", lambda gid: SimpleNamespace(gr_name=f"g{gid}"))
    changed_owners = []

    def fchown(fd, uid, gid):
        changed_owners.append((os.fstat(fd).st_ino, uid, gid))

    monkeypatch.setattr(os, "fchown", fchown)
    return root, changed_owners


def prepare(root, **kwargs):
    rootfs.register_android_ids(str(root), **kwargs)
    android.configure_android_rootfs(str(root), **kwargs)


def snapshot(path):
    st = path.stat()
    return path.read_bytes(), stat.S_IMODE(st.st_mode), st.st_uid, st.st_gid, st.st_ino


@pytest.mark.parametrize("name", ["passwd", "group", "shadow", "gshadow", "adduser.conf"])
@pytest.mark.parametrize("kind", ["symlink", "hardlink"])
def test_account_and_config_links_leave_host_unchanged(guest, tmp_path, name, kind):
    root, owners = guest
    outside = tmp_path / "host-file"
    outside.write_text("KEEP\n")
    outside.chmod(0o600)
    leaf = root / "etc" / name
    leaf.unlink()
    if kind == "symlink":
        leaf.symlink_to(outside)
    else:
        leaf.hardlink_to(outside)
    before = snapshot(outside)

    prepare(root)

    assert snapshot(outside) == before
    assert before[-1] not in [inode for inode, _, _ in owners]


@pytest.mark.parametrize("name", ["passwd", "group", "shadow", "gshadow", "adduser.conf"])
@pytest.mark.parametrize("kind", ["loop", "fifo"])
def test_unsafe_account_entries_are_refused(guest, name, kind):
    root, _ = guest
    leaf = root / "etc" / name
    leaf.unlink()
    if kind == "loop":
        leaf.symlink_to(name)
    else:
        os.mkfifo(leaf)
    before = leaf.lstat()

    prepare(root)

    assert os.path.samestat(before, leaf.lstat())


@pytest.mark.parametrize("alias", ["etc", "accounts"])
def test_absolute_guest_aliases_and_secret_modes(guest, alias):
    root, _ = guest
    target = root / "system" / "etc"
    target.parent.mkdir()
    if alias == "etc":
        (root / "etc").rename(target)
        (root / "etc").symlink_to("/system/etc")
    else:
        target.mkdir()
        for name in ("passwd", "group", "shadow", "gshadow", "adduser.conf"):
            (root / "etc" / name).rename(target / name)
            (root / "etc" / name).symlink_to(f"/system/etc/{name}")
    (target / "adduser.conf").chmod(0o640)

    prepare(root)
    first = {p.name: snapshot(p) for p in target.iterdir()}
    prepare(root)

    assert {p.name: snapshot(p) for p in target.iterdir()} == first
    assert "_apt:x:42:3003:" in (target / "passwd").read_text()
    assert "aid_inet:x:3003:root,_apt" in (target / "group").read_text()
    assert "EXTRA_GROUPS=" in (target / "adduser.conf").read_text()
    for name, mode in (
        ("passwd", 0o644),
        ("group", 0o644),
        ("shadow", 0o600),
        ("gshadow", 0o600),
        ("adduser.conf", 0o640),
    ):
        assert stat.S_IMODE((target / name).stat().st_mode) == mode


def test_replaced_root_name_uses_caller_descriptor(guest, tmp_path):
    root, _ = guest
    fd = dirfd.opendir(str(root))
    saved = tmp_path / "saved"
    root.rename(saved)
    outside = tmp_path / "outside"
    (outside / "etc").mkdir(parents=True)
    sentinel = outside / "etc" / "passwd"
    sentinel.write_text("KEEP\n")
    root.symlink_to(outside)
    try:
        prepare(root, root_fd=fd)
        assert os.fstat(fd).st_ino == saved.stat().st_ino
    finally:
        os.close(fd)
    assert sentinel.read_text() == "KEEP\n"
    assert list((outside / "etc").iterdir()) == [sentinel]
    assert "aid_app:" in (saved / "etc" / "passwd").read_text()


def test_parent_replaced_after_read_does_not_redirect_publication(guest, tmp_path, monkeypatch):
    root, _ = guest
    outside = tmp_path / "outside"
    outside.mkdir()
    sentinel = outside / "passwd"
    sentinel.write_text("KEEP\n")
    saved = root / "saved-etc"
    real_atomic = rootfs.atomic_write

    @contextlib.contextmanager
    def replace_parent(name, **kwargs):
        if name == "passwd" and not saved.exists():
            (root / "etc").rename(saved)
            (root / "etc").symlink_to(outside)
        with real_atomic(name, **kwargs) as fh:
            yield fh

    monkeypatch.setattr(rootfs, "atomic_write", replace_parent)
    prepare(root)
    assert sentinel.read_text() == "KEEP\n"
    assert list(outside.iterdir()) == [sentinel]
    assert "aid_app:" in (saved / "passwd").read_text()


def test_parent_replaced_before_guarded_walk_is_refused(guest, tmp_path, monkeypatch):
    root, _ = guest
    outside = tmp_path / "outside"
    outside.mkdir()
    sentinel = outside / "passwd"
    sentinel.write_text("KEEP\n")
    real_resolve = rootfs.safe_resolve_parts_at
    swapped = False

    def resolve(fd, parts):
        nonlocal swapped
        answer = real_resolve(fd, parts)
        if not swapped:
            swapped = True
            (root / "etc").rename(root / "saved-etc")
            (root / "etc").symlink_to(outside)
        return answer

    monkeypatch.setattr(rootfs, "safe_resolve_parts_at", resolve)
    prepare(root)
    assert sentinel.read_text() == "KEEP\n"
    assert list(outside.iterdir()) == [sentinel]


@pytest.mark.parametrize("failure", ["write", "staging_link"])
def test_atomic_failure_preserves_original_account(guest, tmp_path, monkeypatch, failure):
    root, owners = guest
    passwd = root / "etc" / "passwd"
    before = snapshot(passwd)
    outside = tmp_path / "host-file"
    outside.write_text("KEEP\n")
    host_before = snapshot(outside)
    real_atomic = rootfs.atomic_write

    @contextlib.contextmanager
    def fail(name, **kwargs):
        with real_atomic(name, **kwargs) as fh:
            yield fh
            if failure == "write":
                raise OSError(errno.EIO, "injected write failure")
            parent = kwargs["dir_fd"]
            temporary = next(entry for entry in os.listdir(parent) if entry.startswith("passwd."))
            os.unlink(temporary, dir_fd=parent)
            os.symlink(outside, temporary, dir_fd=parent)

    monkeypatch.setattr(rootfs, "atomic_write", fail)
    rootfs.register_android_ids(str(root))
    assert snapshot(passwd) == before
    assert snapshot(outside) == host_before
    assert host_before[-1] not in [inode for inode, _, _ in owners]


def test_apt_walk_skips_external_links_and_special_files(guest, tmp_path):
    root, owners = guest
    apt = root / "var" / "lib" / "apt"
    (apt / "lists").mkdir(parents=True)
    regular = apt / "lists" / "index"
    regular.write_text("index")
    outside = tmp_path / "outside"
    outside.mkdir()
    sentinel = outside / "sentinel"
    sentinel.write_text("KEEP")
    (apt / "link").symlink_to(sentinel)
    (apt / "directory-link").symlink_to(outside)
    (apt / "hardlink").hardlink_to(sentinel)
    os.mkfifo(apt / "pipe")
    before = snapshot(sentinel)

    android.configure_android_rootfs(str(root))

    assert snapshot(sentinel) == before
    assert before[-1] not in [inode for inode, _, _ in owners]
    for path in (apt, apt / "lists", regular):
        assert (path.stat().st_ino, 42, 3003) in owners


def test_apt_parent_replacement_keeps_pinned_tree(guest, tmp_path, monkeypatch):
    root, owners = guest
    apt = root / "var/lib/apt"
    apt.mkdir(parents=True)
    (apt / "index").touch()
    outside = tmp_path / "outside"
    outside.mkdir()
    sentinel = outside / "index"
    sentinel.write_text("KEEP")
    before = snapshot(sentinel)
    real_walk = android._chown_apt_tree

    def replace(fd, uid):
        apt.rename(apt.with_name("saved"))
        apt.symlink_to(outside)
        real_walk(fd, uid)

    monkeypatch.setattr(android, "_chown_apt_tree", replace)
    android.configure_android_rootfs(str(root))
    assert snapshot(sentinel) == before
    assert before[-1] not in [inode for inode, _, _ in owners]
    assert ((apt.with_name("saved") / "index").stat().st_ino, 42, 3003) in owners


@pytest.mark.parametrize("uid", ["-1", "4294967295", "4294967296", "bad", "", "9" * 5000])
def test_invalid_apt_uid_does_not_change_identity_or_chown(guest, uid, caplog):
    root, owners = guest
    passwd = root / "etc/passwd"
    passwd.write_text(f"_apt:x:{uid}:65534::/:/bin/false\n")
    before = snapshot(passwd)
    (root / "var/lib/apt").mkdir(parents=True)

    android.configure_android_rootfs(str(root))

    assert snapshot(passwd) == before
    assert owners == [] or all(gid != 3003 for _, _, gid in owners)
    assert "_apt" in caplog.text


def test_linux_fixups_are_inert(guest, monkeypatch):
    root, owners = guest
    before = {p.name: snapshot(p) for p in (root / "etc").iterdir()}
    monkeypatch.setattr(android, "IS_TERMUX", False)
    monkeypatch.setattr(rootfs, "IS_TERMUX", False)
    prepare(root)
    assert {p.name: snapshot(p) for p in (root / "etc").iterdir()} == before
    assert owners == []


@pytest.mark.parametrize("name", ["passwd", "group", "shadow", "gshadow", "adduser.conf"])
def test_invalid_text_is_refused_without_replacement(guest, name):
    root, _ = guest
    leaf = root / "etc" / name
    leaf.write_bytes(b"\xff\xfe\n")
    before = snapshot(leaf)
    prepare(root)
    assert snapshot(leaf) == before


def test_registration_requires_existing_passwd(guest):
    root, _ = guest
    (root / "etc/passwd").unlink()
    before = {p.name: snapshot(p) for p in (root / "etc").iterdir()}
    rootfs.register_android_ids(str(root))
    assert {p.name: snapshot(p) for p in (root / "etc").iterdir()} == before


def test_shadow_mode_is_repaired_without_new_entries(guest):
    root, _ = guest
    rootfs.register_android_ids(str(root))
    for name in ("shadow", "gshadow"):
        (root / "etc" / name).chmod(0o644)
    rootfs.register_android_ids(str(root))
    for name in ("shadow", "gshadow"):
        assert stat.S_IMODE((root / "etc" / name).stat().st_mode) == 0o600
    assert (root / "etc/shadow").read_text().count("aid_app:") == 1


def test_deep_apt_walk_bounds_descriptors(guest, monkeypatch):
    root, owners = guest
    apt = root / "var/lib/apt"
    apt.mkdir(parents=True)
    root_fd = dirfd.opendir(str(root))
    fd = dirfd.opendir(str(apt))
    deepest = None
    try:
        for _ in range(1100):
            os.mkdir("d", dir_fd=fd)
            child = dirfd.opendir_at(fd, "d")
            os.close(fd)
            fd = child
        leaf, _ = dirfd.open_new_at(fd, "index")
        deepest = os.fstat(leaf).st_ino
        os.close(leaf)
        os.close(fd)
        fd = None
        monkeypatch.setattr(dirfd, "MAX_OPEN_LEVELS", 4)
        android.configure_android_rootfs(str(root))
        assert (deepest, 42, 3003) in owners
    finally:
        if fd is not None:
            os.close(fd)
        dirfd.rmtree_at(root_fd, "var", force=True)
        os.close(root_fd)

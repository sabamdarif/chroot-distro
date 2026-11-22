"""Login setup writes stay beneath the opened guest root."""

import contextlib
import errno
import fcntl
import logging
import os
import stat

import pytest

from chroot_distro import dirfd, paths
from chroot_distro.commands import login
from chroot_distro.commands.login import env
from chroot_distro.helpers import rootfs


@pytest.fixture(params=[False, True], ids=["linux", "termux"])
def container_store(tmp_path, monkeypatch, request):
    prefix = tmp_path / "prefix"
    containers = (prefix / "var/lib" if request.param else tmp_path) / "chroot-distro/containers"
    root = containers / "box/rootfs"
    root.mkdir(parents=True)
    monkeypatch.setattr(paths, "CONTAINERS_DIR", str(containers))
    monkeypatch.setattr(paths, "RUNTIME_DIR", str(containers.parent))
    monkeypatch.setattr(paths, "IS_TERMUX", request.param)
    monkeypatch.setattr(paths, "TERMUX_PREFIX", str(prefix))
    monkeypatch.setattr(dirfd, "_mount_id", lambda fd: 1)
    return root


@pytest.fixture
def account_files(container_store, monkeypatch):
    monkeypatch.setattr(login, "IS_TERMUX", False)
    parent = container_store / "etc"
    parent.mkdir()
    passwd = parent / "passwd"
    passwd.write_text("demo:x:1500:1500::/home/demo:/bin/sh\n")
    return passwd


@pytest.mark.parametrize("boundary", ["rootfs", "etc", "passwd", "unavailable"])
def test_shared_home_passwd_refuses_unverified_mounts(container_store, account_files, monkeypatch, capsys, boundary):
    target = {"rootfs": container_store, "etc": account_files.parent, "passwd": account_files}.get(boundary)
    before = snapshot(account_files)

    def mount_id(fd):
        if target is None:
            raise OSError(errno.ENOTSUP, "mount IDs unavailable")
        return 2 if os.path.samestat(os.fstat(fd), target.stat()) else 1

    monkeypatch.setattr(dirfd, "_mount_id", mount_id)
    user = login._resolve_login_user(str(container_store), "box", "demo")
    assert login._align_login_account("box", "demo", user, owner_ids=(1550, 1550), shared_home=True) is user
    assert "cannot align guest account" in capsys.readouterr().err
    assert snapshot(account_files) == before


def test_passwd_alignment_refuses_hardlinks_and_rootfs_replacement(
    container_store, account_files, tmp_path, capsys
):
    user = login._resolve_login_user(str(container_store), "box", "demo")
    host = tmp_path / "host"
    (host / "etc").mkdir(parents=True)
    sentinel = host / "etc/passwd"
    sentinel.hardlink_to(account_files)
    before = snapshot(sentinel)

    assert login._align_login_account("box", "demo", user, owner_ids=(1550, 1550), shared_home=True) is user
    assert snapshot(sentinel) == before
    container_store.rename(container_store.with_name("old"))
    container_store.symlink_to(host)

    assert login._align_login_account("box", "demo", user, owner_ids=(1550, 1550), shared_home=True) is user
    assert snapshot(sentinel) == before
    assert capsys.readouterr().err.count("cannot align guest account") == 2


def test_passwd_alignment_refuses_parent_swap(container_store, account_files, tmp_path, monkeypatch):
    user = login._resolve_login_user(str(container_store), "box", "demo")
    host = tmp_path / "host"
    host.mkdir()
    sentinel = host / "passwd"
    sentinel.write_bytes(account_files.read_bytes())
    before = snapshot(sentinel)
    resolve = rootfs.safe_resolve_parts_at

    def swap(fd, parts):
        result = resolve(fd, parts)
        account_files.parent.rename(container_store / "saved")
        account_files.parent.symlink_to(host)
        return result

    monkeypatch.setattr(rootfs, "safe_resolve_parts_at", swap)
    assert login._align_login_account("box", "demo", user, owner_ids=(1550, 1550)) is user
    assert snapshot(sentinel) == before
    assert (container_store / "saved/passwd").read_bytes() == before[0]


def test_passwd_conflicts_commit_with_selected_account(container_store, account_files, monkeypatch):
    account_files.write_text(
        "# keep\nroot:x:1550:1550::/root:/bin/sh\n"
        "other:x:1550:1550::/home/other:/bin/sh\n"
        "busy:x:1001:1001::/home/busy:/bin/sh\n"
        "demo:x:1500:1500::/home/demo:/bin/sh"
    )
    alias = account_files.with_name("accounts")
    account_files.rename(alias)
    account_files.symlink_to("/etc/accounts")
    alias.chmod(0o640)
    user = login._resolve_login_user(str(container_store), "box", "demo")
    before = snapshot(alias)
    write = rootfs.atomic_write

    @contextlib.contextmanager
    def fail(*args, **kwargs):
        with write(*args, **kwargs) as fh:
            yield fh
            raise OSError(errno.EIO, "injected before publication")

    with monkeypatch.context() as failed:
        failed.setattr(rootfs, "atomic_write", fail)
        assert login._align_login_account("box", "demo", user, owner_ids=(1550, 1551)) is user
        assert snapshot(alias) == before

    updated = login._align_login_account("box", "demo", user, owner_ids=(1550, 1551))
    assert (updated["uid"], updated["gid"]) == ("1550", "1551")
    assert alias.read_text() == (
        "# keep\nroot:x:0:0::/root:/bin/sh\n"
        "other:x:1002:1002::/home/other:/bin/sh\n"
        "busy:x:1001:1001::/home/busy:/bin/sh\n"
        "demo:x:1550:1551::/home/demo:/bin/sh"
    )
    assert account_files.is_symlink()
    assert stat.S_IMODE(alias.stat().st_mode) == 0o640
    alias.chmod(0o4640)
    after = snapshot(alias)
    assert login._align_login_account("box", "demo", user, owner_ids=(1550, 1551)) == updated
    assert snapshot(alias) == after


@pytest.mark.parametrize("user_spec", ["1550:1551", "missing"])
def test_passwd_alignment_requires_a_named_record(account_files, user_spec):
    from chroot_distro.exceptions import ChrootDistroError

    account_files.write_text("demo:x:1550:1550::/home/demo:/bin/sh\nmissing:x:1500\n")
    name = user_spec.split(":")[0]
    user = {"name": name, "uid": "1550", "gid": "1551", "home": "/"}
    before = snapshot(account_files)

    if name.isdigit():
        assert login._align_login_account("box", user_spec, user, owner_ids=(1550, 1550), shared_home=True) is user
    else:
        with pytest.raises(ChrootDistroError, match="no usable /etc/passwd entry"):
            login._align_login_account("box", user_spec, user, owner_ids=(1550, 1550), shared_home=True)
    assert snapshot(account_files) == before


def test_root_account_repair_and_identity_refresh_hold_session_lock(container_store, account_files, monkeypatch):
    account_files.write_text("root:x:10328:10328::/root:/bin/sh\n")
    user = login._resolve_login_user(str(container_store), "box", "root")
    update = login.set_passwd_uid_gid
    resolve = login._resolve_login_user

    def check_lock(operation):
        def checked(*args, **kwargs):
            with open(os.path.join(paths.container_data_dir("box"), "sessions.lock"), "rb") as contender:
                with pytest.raises(BlockingIOError):
                    fcntl.flock(contender.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            return operation(*args, **kwargs)

        return checked

    monkeypatch.setattr(login, "set_passwd_uid_gid", check_lock(update))
    monkeypatch.setattr(login, "_resolve_login_user", check_lock(resolve))
    repaired = login._align_login_account("box", "root", user, owner_ids=(1550, 1550), shared_home=True)
    assert (repaired["uid"], repaired["gid"]) == ("0", "0")
    assert account_files.read_text() == "root:x:0:0::/root:/bin/sh\n"


def test_automatic_alignment_does_not_map_named_user_to_uid_zero(container_store, account_files):
    from chroot_distro.exceptions import ChrootDistroError

    user = login._resolve_login_user(str(container_store), "box", "demo")
    before = snapshot(account_files)
    assert login._align_login_account("box", "demo", user, owner_ids=(0, 0)) is user
    with pytest.raises(ChrootDistroError, match="refusing to map guest account .* to UID 0"):
        login._align_login_account("box", "demo", user, owner_ids=(0, 0), shared_home=True)
    assert snapshot(account_files) == before


def test_image_volumes_create_missing_leaves_and_keep_existing_entries(container_store, monkeypatch):
    root = container_store
    (root / "state/keep").mkdir(parents=True)
    (root / "alias").symlink_to("/state")
    (root / "state/link").symlink_to("keep")
    chowns = []
    monkeypatch.setattr(os, "fchown", lambda fd, uid, gid: chowns.append((os.fstat(fd), uid, gid)))
    declarations = ["/", "/bad/../other", "bad\0name", "/\ud800", "/state/keep", "/state/link", "alias//./new"]

    login._prepare_image_volumes("box", declarations, 123, 456)
    login._prepare_image_volumes("box", declarations, 123, 456)

    assert {p.name for p in root.iterdir()} == {"alias", "state"}
    assert {p.name for p in (root / "state").iterdir()} == {"keep", "link", "new"}
    assert (root / "state/link").is_symlink()
    [(opened, uid, gid)] = chowns
    assert os.path.samestat(opened, (root / "state/new").stat())
    assert (uid, gid) == (123, 456)


@pytest.mark.parametrize("boundary", ["root", "parent", "leaf", "unknown"])
def test_image_volumes_require_the_rootfs_mount_for_each_write(container_store, monkeypatch, boundary):
    root = container_store
    (root / "state").mkdir()
    target = {"root": root, "parent": root / "state", "leaf": root / "state/volume"}.get(boundary)

    def mount_id(fd):
        if target is None:
            raise OSError(errno.ENOTSUP, "mount IDs unavailable")
        return 2 if target.exists() and os.path.samestat(os.fstat(fd), target.stat()) else 1

    def chown(fd, uid, gid):
        pytest.fail("ownership changed without a verified mount")

    monkeypatch.setattr(dirfd, "_mount_id", mount_id)
    monkeypatch.setattr(os, "fchown", chown)

    login._prepare_image_volumes("box", ["/state/volume"], 123, 456)

    assert (root / "state/volume").exists() == (boundary == "leaf")


def test_image_volumes_refuse_replaced_parent(container_store, tmp_path, monkeypatch):
    root = container_store
    outside = tmp_path / "outside"
    outside.mkdir()
    (root / "state").mkdir()
    resolve = login.safe_resolve_parts_at

    def swap(fd, parts):
        resolved = resolve(fd, parts)
        (root / "state").rename(root / "saved")
        (root / "state").symlink_to(outside)
        return resolved

    monkeypatch.setattr(login, "safe_resolve_parts_at", swap)

    login._prepare_image_volumes("box", ["/state/volume"], 123, 456)

    assert list(outside.iterdir()) == []
    assert list((root / "saved").iterdir()) == []


def test_image_volumes_refuse_replaced_leaf(container_store, tmp_path, monkeypatch):
    root = container_store
    outside = tmp_path / "outside"
    outside.mkdir()
    opendir = dirfd.opendir_at

    def swap(fd, name):
        if name == "volume":
            (root / "volume").rename(root / "saved")
            (root / "volume").symlink_to(outside)
        return opendir(fd, name)

    def chown(fd, uid, gid):
        pytest.fail("ownership changed through a substituted link")

    monkeypatch.setattr(dirfd, "opendir_at", swap)
    monkeypatch.setattr(os, "fchown", chown)

    login._prepare_image_volumes("box", ["/volume"], 123, 456)

    assert (root / "saved").is_dir()
    assert (root / "volume").is_symlink()


def test_image_volumes_refuse_symlinked_rootfs(container_store, tmp_path):
    root = container_store
    outside = tmp_path / "outside"
    outside.mkdir()
    root.rmdir()
    root.symlink_to(outside)

    login._prepare_image_volumes("box", ["/vol"], 123, 456)

    assert list(outside.iterdir()) == []


@pytest.fixture
def termux_cache(container_store, monkeypatch):
    monkeypatch.setattr(login, "TERMUX_APP_PACKAGE", "com.example.termux")
    return container_store / "data/data/com.example.termux/cache"


def test_termux_cache_resolves_guest_aliases_and_preserves_existing_directory(container_store, termux_cache):
    termux_cache.parent.mkdir(parents=True)
    target = container_store / "var/cache/termux"
    termux_cache.symlink_to("/var/cache/termux")

    login._prepare_termux_cache("box")

    assert target.is_dir()
    assert termux_cache.is_symlink()
    target.chmod(0o700)
    before = target.stat()

    login._prepare_termux_cache("box")

    assert os.path.samestat(target.stat(), before)
    assert stat.S_IMODE(target.stat().st_mode) == 0o700


@pytest.mark.parametrize("boundary", ["root", "parent", "leaf", "unknown"])
def test_termux_cache_requires_a_verified_mount(container_store, termux_cache, monkeypatch, caplog, boundary):
    termux_cache.parent.mkdir(parents=True)
    if boundary == "leaf":
        termux_cache.mkdir()
    target = {"root": container_store, "parent": termux_cache.parent, "leaf": termux_cache}.get(boundary)

    def mount_id(fd):
        if target is None:
            raise OSError(errno.ENOTSUP, "mount IDs unavailable")
        return 2 if os.path.samestat(os.fstat(fd), target.stat()) else 1

    monkeypatch.setattr(dirfd, "_mount_id", mount_id)
    with caplog.at_level(logging.DEBUG, logger=login.__name__):
        login._prepare_termux_cache("box")

    assert "Could not prepare guest Termux cache" in caplog.text
    assert termux_cache.exists() == (boundary == "leaf")


def test_termux_cache_refuses_replaced_parent(termux_cache, tmp_path, monkeypatch):
    parent = termux_cache.parent
    parent.mkdir(parents=True)
    saved = parent.with_name("saved")
    outside = tmp_path / "outside"
    outside.mkdir()
    resolve = login.safe_resolve_parts_at

    def swap(fd, parts):
        resolved = resolve(fd, parts)
        parent.rename(saved)
        parent.symlink_to(outside)
        return resolved

    monkeypatch.setattr(login, "safe_resolve_parts_at", swap)
    login._prepare_termux_cache("box")

    assert list(saved.iterdir()) == []
    assert list(outside.iterdir()) == []


def test_termux_cache_refuses_symlinked_rootfs(container_store, tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    container_store.rmdir()
    container_store.symlink_to(outside)

    login._prepare_termux_cache("box")

    assert list(outside.iterdir()) == []


@pytest.mark.parametrize("package", ["", ".", "..", "nested/name", "bad\0name"])
def test_termux_cache_refuses_invalid_package_component(container_store, monkeypatch, package):
    monkeypatch.setattr(login, "TERMUX_APP_PACKAGE", package)

    login._prepare_termux_cache("box")

    assert list(container_store.iterdir()) == []


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

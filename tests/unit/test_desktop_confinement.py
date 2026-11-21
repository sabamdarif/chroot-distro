"""Desktop setup writes through pinned guest parents and validates cookie sources."""

import contextlib
import errno
import os
import stat
import threading
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import pytest

from chroot_distro import atomic
from chroot_distro.helpers import nvidia, x11, xauthority


def entries(cookie=b"fixture-cookie"):
    return [
        xauthority.XauthEntry(xauthority.FAMILY_LOCAL, b"", b"1", b"MIT-MAGIC-COOKIE-1", cookie),
        xauthority.XauthEntry(xauthority.FAMILY_LOCAL, b"", b"2", b"MIT-MAGIC-COOKIE-1", b"other-display"),
    ]


@pytest.fixture
def desktop(tmp_path, monkeypatch):
    root = tmp_path / "guest"
    (root / "var/tmp").mkdir(parents=True)
    (root / "etc").mkdir()
    home = tmp_path / "home"
    home.mkdir()
    source = home / "auth"
    xauthority.write_xauthority(str(source), entries())
    monkeypatch.setattr(x11, "_invoking_home", lambda uid: str(home))
    owners = []
    monkeypatch.setattr(os, "fchown", lambda fd, uid, gid: owners.append((os.fstat(fd).st_ino, uid, gid)))
    return SimpleNamespace(root=root, home=home, source=source, owners=owners)


def provision(desktop, *, root=None, source=None):
    return x11.provision_guest_xauthority(
        str(root if root is not None else desktop.root),
        host_xauthority=str(source if source is not None else desktop.source),
        display=":1",
        guest_uid=1001,
        guest_gid=1002,
    )


def setup(kind, desktop):
    if kind == "x11":
        return provision(desktop)
    return nvidia.setup_ldconfig_for_wsl(str(desktop.root))


def leaf(kind, root):
    return root / (x11.GUEST_XAUTHORITY_PATH.lstrip("/") if kind == "x11" else "etc/ld.so.conf.d/wsl-nvidia.conf")


@pytest.mark.parametrize("kind", ["x11", "wsl"])
@pytest.mark.parametrize("absolute", [False, True])
def test_guest_parent_aliases_resolve_inside_root(desktop, kind, absolute):
    parent = desktop.root / ("var" if kind == "x11" else "etc")
    (desktop.root / "state").mkdir()
    parent.rename(desktop.root / "state" / parent.name)
    parent.symlink_to(("/" if absolute else "") + "state/" + parent.name)

    setup(kind, desktop)

    dest = leaf(kind, desktop.root / "state")
    assert dest.is_file()
    if kind == "x11":
        assert xauthority.read_xauthority(str(dest)) == entries()[:1]
        assert stat.S_IMODE(dest.stat().st_mode) == 0o600
        assert desktop.owners == [(dest.stat().st_ino, 1001, 1002)]
    else:
        assert dest.read_text() == "/usr/lib/wsl/lib\n"
        assert stat.S_IMODE(dest.stat().st_mode) == 0o644


@pytest.mark.parametrize("kind", ["x11", "wsl"])
def test_external_parent_symlink_cannot_redirect_write(desktop, tmp_path, kind):
    outside = tmp_path / "host"
    outside.mkdir()
    sentinel = outside / "keep"
    sentinel.write_text("KEEP")
    parent = desktop.root / ("var/tmp" if kind == "x11" else "etc")
    parent.rmdir()
    parent.symlink_to(outside)

    setup(kind, desktop)

    assert list(outside.iterdir()) == [sentinel]
    assert sentinel.read_text() == "KEEP"
    rerooted = desktop.root / str(outside).lstrip("/")
    dest = rerooted / (".chroot-distro-xauthority" if kind == "x11" else "ld.so.conf.d/wsl-nvidia.conf")
    assert dest.is_file()


@pytest.mark.parametrize("kind", ["x11", "wsl"])
def test_parent_replaced_between_resolution_and_walk_is_refused(desktop, tmp_path, monkeypatch, kind):
    module = x11 if kind == "x11" else nvidia
    real_resolve = module.safe_resolve_parts_at
    parent = desktop.root / ("var" if kind == "x11" else "etc")
    saved = tmp_path / "saved"
    outside = tmp_path / "host"
    outside.mkdir()

    def resolve(fd, parts):
        result = real_resolve(fd, parts)
        parent.rename(saved)
        parent.symlink_to(outside)
        return result

    monkeypatch.setattr(module, "safe_resolve_parts_at", resolve)
    setup(kind, desktop)

    assert list(outside.iterdir()) == []
    assert not (saved / ("tmp/.chroot-distro-xauthority" if kind == "x11" else "ld.so.conf.d/wsl-nvidia.conf")).exists()


@pytest.mark.parametrize("kind", ["x11", "wsl"])
def test_root_replacement_does_not_reopen_root_name(desktop, tmp_path, monkeypatch, kind):
    module = x11 if kind == "x11" else nvidia
    real_resolve = module.safe_resolve_parts_at
    outside = tmp_path / "host"
    outside.mkdir()
    saved = tmp_path / "saved"

    def resolve(fd, parts):
        desktop.root.rename(saved)
        desktop.root.symlink_to(outside)
        return real_resolve(fd, parts)

    monkeypatch.setattr(module, "safe_resolve_parts_at", resolve)
    setup(kind, desktop)

    assert list(outside.iterdir()) == []
    assert leaf(kind, saved).is_file()


@pytest.mark.parametrize("kind", ["x11", "wsl"])
def test_parent_replacement_after_pin_keeps_write_in_original(desktop, tmp_path, monkeypatch, kind):
    outside = tmp_path / "host"
    outside.mkdir()
    saved = tmp_path / "saved"
    parent = leaf(kind, desktop.root).parent

    def swap():
        parent.rename(saved)
        parent.symlink_to(outside)

    if kind == "x11":
        real_write = x11.write_xauthority

        def write(*args, **kwargs):
            swap()
            return real_write(*args, **kwargs)

        monkeypatch.setattr(x11, "write_xauthority", write)
    else:
        real_atomic = nvidia.atomic_write

        @contextlib.contextmanager
        def write(*args, **kwargs):
            swap()
            with real_atomic(*args, **kwargs) as out:
                yield out

        monkeypatch.setattr(nvidia, "atomic_write", write)

    setup(kind, desktop)

    assert list(outside.iterdir()) == []
    assert (saved / leaf(kind, desktop.root).name).is_file()


@pytest.mark.parametrize("kind", ["x11", "wsl"])
@pytest.mark.parametrize("entry", ["symlink", "hardlink", "fifo", "directory"])
def test_planted_final_entries_do_not_modify_host(desktop, tmp_path, kind, entry):
    victim = tmp_path / "host-file"
    victim.write_text("KEEP")
    victim.chmod(0o640)
    dest = leaf(kind, desktop.root)
    dest.parent.mkdir(parents=True, exist_ok=True)
    if entry == "symlink":
        dest.symlink_to(victim)
    elif entry == "hardlink":
        dest.hardlink_to(victim)
    elif entry == "fifo":
        os.mkfifo(dest)
    else:
        dest.mkdir()
    before = dest.lstat()

    setup(kind, desktop)

    assert victim.read_text() == "KEEP"
    assert stat.S_IMODE(victim.stat().st_mode) == 0o640
    assert victim.stat().st_ino not in [inode for inode, _, _ in desktop.owners]
    if kind == "wsl" or entry == "directory":
        assert os.path.samestat(before, dest.lstat())
    else:
        assert stat.S_ISREG(dest.lstat().st_mode)
        assert xauthority.read_xauthority(str(dest)) == entries()[:1]


def test_unsafe_source_is_not_copied(desktop, tmp_path):
    unsafe = tmp_path / "private-auth"
    unsafe.write_bytes(desktop.source.read_bytes())

    assert provision(desktop, source=unsafe) is None
    assert not leaf("x11", desktop.root).exists()


@pytest.mark.parametrize("kind", ["fifo", "directory", "loop"])
def test_nonregular_sources_are_refused(desktop, kind):
    desktop.source.unlink()
    if kind == "fifo":
        os.mkfifo(desktop.source)
    elif kind == "directory":
        desktop.source.mkdir()
    else:
        desktop.source.symlink_to(desktop.source.name)

    assert provision(desktop) is None
    assert not leaf("x11", desktop.root).exists()


def test_authorized_source_symlink_is_canonicalized_once(desktop, monkeypatch):
    alias = desktop.home / "alias"
    alias.symlink_to(desktop.source)
    real_check = x11._is_safe_auth_path
    checked = []

    def check(path, uid, home):
        checked.append(path)
        return real_check(path, uid, home)

    monkeypatch.setattr(x11, "_is_safe_auth_path", check)
    assert provision(desktop, source=alias) == x11.GUEST_XAUTHORITY_PATH
    assert checked == [str(desktop.source)]
    assert xauthority.read_xauthority(str(leaf("x11", desktop.root))) == entries()[:1]


@pytest.mark.parametrize("part", ["leaf", "parent"])
def test_authorized_source_replaced_with_symlink_is_refused(desktop, tmp_path, monkeypatch, part):
    outside = tmp_path / "private"
    outside.mkdir()
    secret = outside / desktop.source.name
    secret.write_bytes(desktop.source.read_bytes())
    real_check = x11._is_safe_auth_path

    def check(path, uid, home):
        allowed = real_check(path, uid, home)
        if part == "leaf":
            desktop.source.unlink()
            desktop.source.symlink_to(secret)
        else:
            desktop.home.rename(tmp_path / "saved-home")
            desktop.home.symlink_to(outside)
        return allowed

    monkeypatch.setattr(x11, "_is_safe_auth_path", check)
    assert provision(desktop) is None
    assert not leaf("x11", desktop.root).exists()


def test_opened_source_is_parsed_and_closed_without_reopening(desktop, monkeypatch):
    real_read = x11.read_xauthority
    source_fds = []

    def read(fd):
        assert isinstance(fd, int)
        source_fds.append(fd)
        desktop.source.unlink()
        xauthority.write_xauthority(str(desktop.source), entries(b"replacement"))
        return real_read(fd)

    monkeypatch.setattr(x11, "read_xauthority", read)
    assert provision(desktop) == x11.GUEST_XAUTHORITY_PATH
    assert xauthority.read_xauthority(str(leaf("x11", desktop.root))) == entries()[:1]
    with pytest.raises(OSError) as exc:
        os.fstat(source_fds[0])
    assert exc.value.errno == errno.EBADF


@pytest.mark.parametrize("failure", ["owner", "mode", "write", "rename", "interrupt"])
def test_cookie_failure_preserves_previous_complete_file(desktop, monkeypatch, caplog, failure):
    dest = leaf("x11", desktop.root)
    xauthority.write_xauthority(str(dest), entries(b"previous-cookie"))
    before = dest.read_bytes()

    def fail(*args, **kwargs):
        if failure == "interrupt":
            raise KeyboardInterrupt
        raise OSError(errno.EIO, "fixture failure")

    if failure == "owner":
        monkeypatch.setattr(os, "fchown", fail)
    elif failure == "mode":
        monkeypatch.setattr(os, "fchmod", fail)
    elif failure == "rename":
        monkeypatch.setattr(os, "replace", fail)
    else:
        def write(fp, entry):
            fp.write(b"partial-cookie")
            fail()

        monkeypatch.setattr(xauthority, "_write_entry", write)

    if failure == "interrupt":
        with pytest.raises(KeyboardInterrupt):
            provision(desktop)
    else:
        assert provision(desktop) is None
    assert dest.read_bytes() == before
    assert list(dest.parent.iterdir()) == [dest]
    assert "fixture-cookie" not in caplog.text
    assert "previous-cookie" not in caplog.text


@pytest.mark.parametrize("kind", ["x11", "wsl"])
def test_post_publication_fsync_failure_leaves_complete_file(desktop, monkeypatch, kind):
    real_fsync = os.fsync

    def fsync(fd):
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            raise OSError(errno.EIO, "directory fsync failed")
        real_fsync(fd)

    monkeypatch.setattr(os, "fsync", fsync)
    assert setup(kind, desktop) is None
    dest = leaf(kind, desktop.root)
    if kind == "x11":
        assert xauthority.read_xauthority(str(dest)) == entries()[:1]
    else:
        assert dest.read_text() == "/usr/lib/wsl/lib\n"
    assert list(dest.parent.iterdir()) == [dest]


def test_simultaneous_guests_keep_separate_cookies(desktop, monkeypatch):
    roots = [desktop.root / "one", desktop.root / "two"]
    sources = [desktop.home / "one.auth", desktop.home / "two.auth"]
    for index, (root, source) in enumerate(zip(roots, sources)):
        (root / "var").mkdir(parents=True)
        (root / "var/tmp").symlink_to("/cookies")
        xauthority.write_xauthority(str(source), entries(str(index).encode()))
    real_write = x11.write_xauthority
    barrier = threading.Barrier(2)

    def write(*args, **kwargs):
        barrier.wait(timeout=5)
        return real_write(*args, **kwargs)

    monkeypatch.setattr(x11, "write_xauthority", write)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda index: provision(desktop, root=roots[index], source=sources[index]), range(2)))

    assert results == [x11.GUEST_XAUTHORITY_PATH] * 2
    for index, root in enumerate(roots):
        dest = root / "cookies/.chroot-distro-xauthority"
        assert xauthority.read_xauthority(str(dest)) == entries(str(index).encode())[:1]


@pytest.mark.parametrize("kind", ["symlink", "hardlink"])
@pytest.mark.parametrize("temporary", ["legacy", "exclusive"])
def test_cookie_temporary_collision_does_not_touch_target(tmp_path, monkeypatch, kind, temporary):
    victim = tmp_path / "victim"
    victim.write_text("KEEP")
    victim.chmod(0o644)
    dest = tmp_path / "cookie"
    if temporary == "legacy":
        planted = tmp_path / "cookie.tmp"
    else:
        random = iter([b"a" * 8, b"b" * 8])
        monkeypatch.setattr(os, "urandom", lambda count: next(random))
        planted = tmp_path / f"cookie.{os.getpid()}.{(b'a' * 8).hex()}.tmp"
    if kind == "symlink":
        planted.symlink_to(victim)
    else:
        planted.hardlink_to(victim)
    previous_umask = os.umask(0o777)
    try:
        xauthority.write_xauthority(str(dest), entries())
    finally:
        os.umask(previous_umask)

    assert victim.read_text() == "KEEP"
    assert stat.S_IMODE(victim.stat().st_mode) == 0o644
    assert planted.exists()
    assert stat.S_IMODE(dest.stat().st_mode) == 0o600
    assert xauthority.read_xauthority(str(dest)) == entries()


def test_wsl_config_race_preserves_new_entry(desktop, monkeypatch):
    real_link = os.link
    dest = leaf("wsl", desktop.root)

    def link(src, dst, **kwargs):
        dest.write_text("existing configuration\n")
        real_link(src, dst, **kwargs)

    monkeypatch.setattr(os, "link", link)
    nvidia.setup_ldconfig_for_wsl(str(desktop.root))

    assert dest.read_text() == "existing configuration\n"
    assert list(dest.parent.iterdir()) == [dest]


@pytest.mark.parametrize("failure", ["write", "link", "interrupt"])
def test_failed_wsl_creation_cleans_up_and_can_retry(desktop, monkeypatch, failure):
    real_atomic = nvidia.atomic_write

    def fail(*args, **kwargs):
        if failure == "interrupt":
            raise KeyboardInterrupt
        raise OSError(errno.EIO, "fixture failure")

    with monkeypatch.context() as patch:
        if failure == "link":
            patch.setattr(os, "link", fail)
        else:
            @contextlib.contextmanager
            def write(*args, **kwargs):
                with real_atomic(*args, **kwargs) as out:
                    out.write("partial")
                    fail()
                    yield out

            patch.setattr(nvidia, "atomic_write", write)
        if failure == "interrupt":
            with pytest.raises(KeyboardInterrupt):
                setup("wsl", desktop)
        else:
            setup("wsl", desktop)

    dest = leaf("wsl", desktop.root)
    assert list(dest.parent.iterdir()) == []
    setup("wsl", desktop)
    assert dest.read_text() == "/usr/lib/wsl/lib\n"


def test_wsl_integration_keeps_driver_bindings(desktop, tmp_path, monkeypatch):
    host = tmp_path / "wsl"
    host.mkdir()
    (desktop.root / "usr/lib").mkdir(parents=True)
    (desktop.root / "lib").symlink_to("usr/lib")
    monkeypatch.setattr(nvidia, "is_wsl", lambda: True)
    monkeypatch.setattr(nvidia, "find_wsl_libraries", lambda root: [(str(host), "/usr/lib/wsl")])
    monkeypatch.setattr(nvidia, "find_nvidia_device_nodes", lambda: [])
    monkeypatch.setattr(nvidia, "find_nvidia_configs", lambda: [])
    monkeypatch.setattr(nvidia, "find_nvidia_binaries", lambda: [])

    binds, env = nvidia.get_nvidia_integration(str(desktop.root))

    assert binds == [(str(host), "/usr/lib/wsl")]
    assert env["GALLIUM_DRIVER"] == "d3d12"
    assert leaf("wsl", desktop.root).read_text() == "/usr/lib/wsl/lib\n"

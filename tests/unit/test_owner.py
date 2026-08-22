"""Tests for chroot_distro.helpers.owner, the `--chown` spec resolver.

The rule worth pinning down is which side a name is asked of: the same name
answers to a different number in a container than on the host, so the wrong side
silently hands the files to whoever holds that number over there. The rest is
chown(1) spellings (`user`, `user:group`, `:group`) and the fact that a rootfs
`/etc/passwd` is guest content, so a field that is not a number must fail the
lookup rather than the command.
"""

import pytest

from chroot_distro.exceptions import ChrootDistroError
from chroot_distro.helpers.owner import resolve_owner


@pytest.fixture
def rootfs(tmp_path, monkeypatch):
    """A container named `distro` whose passwd knows `app` and `nobody`."""
    root = tmp_path / "containers" / "distro" / "rootfs"
    (root / "etc").mkdir(parents=True)
    (root / "etc" / "passwd").write_text(
        "root:x:0:0:root:/root:/bin/sh\n"
        "app:x:1002:1500:app:/home/app:/bin/sh\n"
        "broken:x:notanumber:1:broken:/:/bin/sh\n"
    )
    (root / "etc" / "group").write_text("root:x:0:\nstaff:x:2000:\n")
    monkeypatch.setattr("chroot_distro.paths.CONTAINERS_DIR", str(tmp_path / "containers"))
    return root


class _Entry:
    def __init__(self, uid, gid):
        self.pw_uid = uid
        self.pw_gid = gid


@pytest.fixture
def host(monkeypatch):
    """A host passwd/group that knows `hostuser` and `hostgroup`."""
    users = {"hostuser": _Entry(4000, 4100)}
    monkeypatch.setattr(
        "chroot_distro.helpers.owner.pwd.getpwnam",
        lambda name: users[name],
    )
    monkeypatch.setattr(
        "chroot_distro.helpers.owner.pwd.getpwuid",
        lambda uid: {4000: _Entry(4000, 4100)}[uid],
    )
    monkeypatch.setattr(
        "chroot_distro.helpers.owner.grp.getgrnam",
        lambda name: type("G", (), {"gr_gid": {"hostgroup": 4200}[name]}),
    )


# ── the destination decides which passwd answers ──────────────────────────────
def test_a_container_destination_is_asked_of_its_own_passwd(rootfs, host):
    # `hostuser` exists on the fake host and not in the container, so an answer
    # of 4000 here would mean the wrong side was consulted.
    assert resolve_owner("app", "distro:/home/app") == (1002, 1500)


def test_a_host_destination_is_asked_of_the_host(rootfs, host):
    assert resolve_owner("hostuser", "/tmp/dest") == (4000, 4100)


def test_a_path_with_a_colon_in_it_is_still_a_host_path(rootfs, host):
    assert resolve_owner("hostuser", "./odd:name") == (4000, 4100)


# ── chown(1) spellings ────────────────────────────────────────────────────────
def test_a_named_group_replaces_the_primary_one(rootfs):
    assert resolve_owner("app:staff", "distro:/opt") == (1002, 2000)


def test_a_trailing_colon_still_means_the_primary_group(rootfs):
    # `app:` must not be read as "the group named app", which does not exist.
    assert resolve_owner("app:", "distro:/opt") == (1002, 1500)


def test_a_group_alone_leaves_the_user_alone(rootfs):
    assert resolve_owner(":staff", "distro:/opt") == (-1, 2000)


def test_numbers_are_taken_as_they_stand(rootfs):
    assert resolve_owner("7:9", "distro:/opt") == (7, 9)


def test_a_numeric_user_still_gets_its_primary_group_from_passwd(rootfs):
    assert resolve_owner("1002", "distro:/opt") == (1002, 1500)


def test_an_empty_spec_is_refused(rootfs):
    with pytest.raises(ChrootDistroError, match="needs a user or a group"):
        resolve_owner(":", "distro:/opt")


# ── what cannot be answered ───────────────────────────────────────────────────
def test_an_unknown_user_names_the_container_it_was_looked_for_in(rootfs):
    with pytest.raises(ChrootDistroError, match="unknown user 'ghost' on container 'distro'"):
        resolve_owner("ghost", "distro:/opt")


def test_an_unknown_group_is_refused(rootfs):
    with pytest.raises(ChrootDistroError, match="unknown group 'wheel'"):
        resolve_owner("app:wheel", "distro:/opt")


def test_an_unknown_host_user_names_the_host(rootfs, host):
    with pytest.raises(ChrootDistroError, match="unknown user 'ghost' on this host"):
        resolve_owner("ghost", "/tmp/dest")


def test_a_numeric_user_with_no_entry_asks_for_a_group_by_name(rootfs):
    # There is no primary group to read for an id nothing is named after, and
    # guessing the uid would hand the files to an unrelated group.
    with pytest.raises(ChrootDistroError, match="no passwd entry for '4242'"):
        resolve_owner("4242", "distro:/opt")


def test_a_passwd_field_that_is_not_a_number_fails_the_lookup(rootfs):
    with pytest.raises(ChrootDistroError, match="unknown user 'broken'"):
        resolve_owner("broken", "distro:/opt")


def test_an_id_beyond_the_kernel_range_is_not_taken_for_a_number(rootfs):
    # 4294967295 is (uid_t)-1, which chown(2) reads as "leave this alone"; it is
    # not an owner, so the spec is treated as a name and found missing.
    with pytest.raises(ChrootDistroError, match="unknown user '4294967295'"):
        resolve_owner("4294967295", "distro:/opt")

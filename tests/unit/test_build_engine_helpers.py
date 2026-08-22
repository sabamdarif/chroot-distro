
import os
import shutil

import pytest

from chroot_distro.helpers.build_engine import dockerignore, parsing, users
from chroot_distro.helpers.build_engine.constants import needs_chroot
from chroot_distro.helpers.build_engine.errors import BuildError


# ── parsing.split_arg ─────────────────────────────────────────────────────────
def test_split_arg_key_only():
    assert parsing.split_arg("FOO") == ("FOO", None)


def test_split_arg_key_value():
    assert parsing.split_arg("FOO=bar") == ("FOO", "bar")


def test_split_arg_empty_value_after_equals():
    assert parsing.split_arg("FOO=") == ("FOO", "")


def test_split_arg_blank():
    assert parsing.split_arg("   ") == ("", None)


def test_split_arg_list_is_joined():
    assert parsing.split_arg(["FOO=a", "b"]) == ("FOO", "a b")


def test_split_arg_quoted_value():
    assert parsing.split_arg('FOO="https://example.com/file.zip"') == ("FOO", "https://example.com/file.zip")
    assert parsing.split_arg("FOO='https://example.com/file.zip'") == ("FOO", "https://example.com/file.zip")


# ── parsing.parse_kv_list ─────────────────────────────────────────────────────
def test_parse_kv_list_equals_form():
    assert parsing.parse_kv_list("A=1 B=2") == [("A", "1"), ("B", "2")]


def test_parse_kv_list_quoted_value_with_spaces():
    assert parsing.parse_kv_list('A="hello world"') == [("A", "hello world")]


def test_parse_kv_list_legacy_env_form():
    # `ENV KEY value` with no equals -> single pair, value is the remainder.
    assert parsing.parse_kv_list("KEY the rest") == [("KEY", "the rest")]


def test_parse_kv_list_legacy_single_token():
    assert parsing.parse_kv_list("LONELY") == [("LONELY", "")]


def test_parse_kv_list_skips_tokens_without_equals():
    assert parsing.parse_kv_list("A=1 bare B=2") == [("A", "1"), ("B", "2")]


def test_parse_kv_list_bad_quoting_raises():
    with pytest.raises(BuildError):
        parsing.parse_kv_list('A="unterminated')


# ── parsing.to_argv ───────────────────────────────────────────────────────────
def test_to_argv_exec_form_passthrough():
    instr = {"exec_form": True, "value": ["echo", "hi"]}
    assert parsing.to_argv(instr, ["/bin/sh", "-c"]) == ["echo", "hi"]


def test_to_argv_shell_form_wraps():
    instr = {"exec_form": False, "value": "echo hi"}
    assert parsing.to_argv(instr, ["/bin/sh", "-c"]) == ["/bin/sh", "-c", "echo hi"]


# ── parsing.looks_like_url ────────────────────────────────────────────────────
@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("http://x", True),
        ("https://x", True),
        ("ftp://x", False),
        ("/local/path", False),
    ],
)
def test_looks_like_url(value, expected):
    assert parsing.looks_like_url(value) is expected


# ── parsing.is_tar_header ─────────────────────────────────────────────────────
@pytest.mark.parametrize(
    ("head", "expected"),
    [
        (b"\x00" * 257 + b"ustar\x00" + b"\x00" * 10, True),
        (b"\x00" * 257 + b"ustar  \x00" + b"\x00" * 10, True),
        (b"\x1f\x8b\x08" + b"\x00" * 300, True),
        (b"BZh" + b"\x00" * 300, True),
        (b"\xfd7zXZ\x00" + b"\x00" * 300, True),
        (b"\x00" * 300, False),
        # Shorter than the ustar magic's offset, so nothing can be concluded.
        (b"short", False),
        (b"\x1f\x8b\x08" + b"\x00" * 10, False),
        (b"", False),
    ],
)
def test_is_tar_header(head, expected):
    assert parsing.is_tar_header(head) is expected


# ── constants.needs_chroot ────────────────────────────────────────────────────
def test_needs_chroot_true_for_run():
    assert needs_chroot([{"name": "COPY"}, {"name": "RUN"}]) is True


def test_needs_chroot_false_without_run():
    assert needs_chroot([{"name": "COPY"}, {"name": "ENV"}]) is False


def test_needs_chroot_onbuild_run():
    assert needs_chroot([{"name": "ONBUILD", "value": {"name": "RUN"}}]) is True


def test_needs_chroot_onbuild_non_run():
    assert needs_chroot([{"name": "ONBUILD", "value": {"name": "COPY"}}]) is False


# ── dockerignore ──────────────────────────────────────────────────────────────
def test_load_dockerignore_reads_patterns(tmp_path):
    (tmp_path / ".dockerignore").write_text("# comment\n\nnode_modules\n*.log\n!keep.log\n")
    assert dockerignore.load_dockerignore(str(tmp_path)) == ["node_modules", "*.log", "!keep.log"]


def test_load_dockerignore_missing(tmp_path):
    assert dockerignore.load_dockerignore(str(tmp_path)) == []


def test_is_ignored_no_patterns():
    assert dockerignore.is_ignored("a.txt", []) is False


def test_is_ignored_dockerfile_never_ignored():
    assert dockerignore.is_ignored("Dockerfile", ["*"]) is False
    assert dockerignore.is_ignored(".dockerignore", ["*"]) is False


def test_is_ignored_glob_match():
    assert dockerignore.is_ignored("app.log", ["*.log"]) is True


def test_is_ignored_negation_reincludes():
    assert dockerignore.is_ignored("keep.log", ["*.log", "!keep.log"]) is False


def test_is_ignored_directory_prefix():
    assert dockerignore.is_ignored("node_modules/lib/x.js", ["node_modules"]) is True


def test_is_ignored_double_star():
    assert dockerignore.is_ignored("a/b/c.py", ["**/c.py"]) is True


def test_simple_glob(tmp_path):
    (tmp_path / "a.txt").write_text("")
    (tmp_path / "b.txt").write_text("")
    (tmp_path / "c.md").write_text("")
    assert sorted(dockerignore.simple_glob(str(tmp_path), "*.txt")) == ["a.txt", "b.txt"]


# ── users ─────────────────────────────────────────────────────────────────────
@pytest.fixture
def rootfs(tmp_path):
    # Nested under tmp_path so a test can put something *outside* the rootfs.
    etc = tmp_path / "rootfs" / "etc"
    etc.mkdir(parents=True)
    (etc / "passwd").write_text("root:x:0:0:root:/root:/bin/sh\napp:x:1000:1000::/home/app:/bin/sh\n")
    (etc / "group").write_text("root:x:0:\napp:x:2000:\n")
    return str(tmp_path / "rootfs")


def test_resolve_id_numeric_passthrough(rootfs):
    assert users.resolve_id(rootfs, "1234", is_group=False, default=0) == 1234


def test_resolve_id_by_name(rootfs):
    assert users.resolve_id(rootfs, "app", is_group=False, default=0) == 1000


def test_resolve_id_group_by_name(rootfs):
    assert users.resolve_id(rootfs, "app", is_group=True, default=0) == 2000


def test_resolve_id_unknown_falls_back(rootfs):
    assert users.resolve_id(rootfs, "ghost", is_group=False, default=42) == 42


def test_resolve_id_empty_is_default(rootfs):
    assert users.resolve_id(rootfs, "", is_group=False, default=7) == 7


def test_resolve_id_missing_db_falls_back(tmp_path):
    assert users.resolve_id(str(tmp_path), "app", is_group=False, default=9) == 9


def test_resolve_chown_user_only(rootfs):
    # group defaults to the resolved uid.
    assert users.resolve_chown(rootfs, "app") == (1000, 1000)


def test_resolve_chown_user_and_group(rootfs):
    assert users.resolve_chown(rootfs, "app:app") == (1000, 2000)


def test_resolve_chown_numeric(rootfs):
    assert users.resolve_chown(rootfs, "5:6") == (5, 6)


def test_resolve_user_for_chroot_empty():
    assert users.resolve_user_for_chroot("/nonexistent", "") == (0, 0)


def test_resolve_user_for_chroot_user_group(rootfs):
    assert users.resolve_user_for_chroot(rootfs, "app:app") == (1000, 2000)


# ── parsing.split_operands ────────────────────────────────────────────────────
def test_split_operands_splits_with_shell_quoting():
    instr = {"name": "COPY", "lineno": 3, "value": '"a b" c'}
    assert parsing.split_operands(instr["value"], instr) == ["a b", "c"]


def test_split_operands_names_the_line_it_could_not_parse():
    # shlex answers an unbalanced quote with ValueError, which `build` does not
    # catch — one mistyped line used to end it in a traceback.
    instr = {"name": "COPY", "lineno": 7, "value": '"unterminated /app'}
    with pytest.raises(BuildError, match="Cannot parse COPY at line 7"):
        parsing.split_operands(instr["value"], instr)


def test_split_operands_refuses_a_trailing_backslash():
    instr = {"name": "VOLUME", "lineno": 2, "value": "/data\\"}
    with pytest.raises(BuildError, match="Cannot parse VOLUME at line 2"):
        parsing.split_operands(instr["value"], instr)


# ── users: /etc/passwd is image content, and so is the path to it ─────────────
def test_etc_symlinked_out_of_the_rootfs_reads_nothing(rootfs, tmp_path):
    outside = tmp_path / "outside"
    (outside / "etc").mkdir(parents=True)
    (outside / "etc" / "passwd").write_text("intruder:x:1337:1337::/:/bin/sh\n")

    shutil.rmtree(os.path.join(rootfs, "etc"))
    os.symlink(str(outside / "etc"), os.path.join(rootfs, "etc"))

    assert users.resolve_id(rootfs, "intruder", is_group=False, default=7) == 7


def test_passwd_symlinked_at_a_host_file_reads_nothing(rootfs, tmp_path):
    victim = tmp_path / "host_passwd"
    victim.write_text("intruder:x:1337:1337::/:/bin/sh\n")

    passwd = os.path.join(rootfs, "etc", "passwd")
    os.remove(passwd)
    os.symlink(str(victim), passwd)

    assert users.resolve_id(rootfs, "intruder", is_group=False, default=7) == 7


def test_passwd_symlink_is_re_rooted_inside_the_rootfs(rootfs):
    # The Nix case: /etc/passwd points at an absolute path that only exists
    # inside the guest. The link is followed, just anchored at the rootfs.
    store = os.path.join(rootfs, "nix", "store")
    os.makedirs(store)
    with open(os.path.join(store, "passwd"), "w") as fh:
        fh.write("nixuser:x:2000:2000::/:/bin/sh\n")

    passwd = os.path.join(rootfs, "etc", "passwd")
    os.remove(passwd)
    os.symlink("/nix/store/passwd", passwd)

    assert users.resolve_id(rootfs, "nixuser", is_group=False, default=7) == 2000


def test_dotdot_in_a_symlink_target_clamps_at_the_rootfs(rootfs, tmp_path):
    victim = tmp_path / "host_passwd"
    victim.write_text("intruder:x:1337:1337::/:/bin/sh\n")

    passwd = os.path.join(rootfs, "etc", "passwd")
    os.remove(passwd)
    # <rootfs>/etc/../../host_passwd is the victim, as the host resolves it.
    os.symlink("../../host_passwd", passwd)

    assert users.resolve_id(rootfs, "intruder", is_group=False, default=7) == 7


def test_symlink_loop_gives_up(rootfs):
    passwd = os.path.join(rootfs, "etc", "passwd")
    os.remove(passwd)
    os.symlink("/etc/passwd2", passwd)
    os.symlink("/etc/passwd", os.path.join(rootfs, "etc", "passwd2"))

    assert users.resolve_id(rootfs, "root", is_group=False, default=7) == 7


def test_a_fifo_named_passwd_does_not_block(rootfs):
    passwd = os.path.join(rootfs, "etc", "passwd")
    os.remove(passwd)
    os.mkfifo(passwd)

    assert users.resolve_id(rootfs, "root", is_group=False, default=7) == 7


def test_an_enormous_passwd_is_read_only_up_to_the_cap(rootfs):
    passwd = os.path.join(rootfs, "etc", "passwd")
    with open(passwd, "w") as fh:
        fh.write("root:x:0:0::/root:/bin/sh\n")
        fh.write("x" * (users._MAX_ID_FILE_BYTES * 2))

    # The entry before the padding still resolves; the padding never becomes a
    # single multi-megabyte line in memory.
    assert users.resolve_id(rootfs, "root", is_group=False, default=7) == 0


def test_undecodable_passwd_does_not_raise(rootfs):
    passwd = os.path.join(rootfs, "etc", "passwd")
    with open(passwd, "wb") as fh:
        fh.write(b"root:x:0:0::/root:/bin/sh\n\xff\xfe:x:1:1::/:/bin/sh\n")

    assert users.resolve_id(rootfs, "root", is_group=False, default=7) == 0


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


# ── parsing.is_tar_archive ────────────────────────────────────────────────────
def _write(tmp_path, name, data):
    p = tmp_path / name
    p.write_bytes(data)
    return str(p)


def test_is_tar_archive_ustar(tmp_path):
    head = b"\x00" * 257 + b"ustar\x00" + b"\x00" * 10
    assert parsing.is_tar_archive(_write(tmp_path, "a.tar", head)) is True


def test_is_tar_archive_gzip(tmp_path):
    assert parsing.is_tar_archive(_write(tmp_path, "a.gz", b"\x1f\x8b\x08" + b"\x00" * 300)) is True


def test_is_tar_archive_bzip2(tmp_path):
    assert parsing.is_tar_archive(_write(tmp_path, "a.bz2", b"BZh" + b"\x00" * 300)) is True


def test_is_tar_archive_xz(tmp_path):
    assert parsing.is_tar_archive(_write(tmp_path, "a.xz", b"\xfd7zXZ\x00" + b"\x00" * 300)) is True


def test_is_tar_archive_too_short(tmp_path):
    assert parsing.is_tar_archive(_write(tmp_path, "a", b"short")) is False


def test_is_tar_archive_not_tar(tmp_path):
    assert parsing.is_tar_archive(_write(tmp_path, "a", b"\x00" * 300)) is False


def test_is_tar_archive_missing_file(tmp_path):
    assert parsing.is_tar_archive(str(tmp_path / "nope")) is False


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
    etc = tmp_path / "etc"
    etc.mkdir()
    (etc / "passwd").write_text("root:x:0:0:root:/root:/bin/sh\napp:x:1000:1000::/home/app:/bin/sh\n")
    (etc / "group").write_text("root:x:0:\napp:x:2000:\n")
    return str(tmp_path)


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

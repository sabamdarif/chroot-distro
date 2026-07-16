import os

from chroot_distro.helpers import tar_extract


# ── _safe_resolve ──────────────────────────────────────────────────────────────
def test_safe_resolve_plain_path(tmp_path):
    root = str(tmp_path)
    assert tar_extract._safe_resolve(root, ["etc", "hostname"]) == os.path.join(root, "etc", "hostname")


def test_safe_resolve_skips_dot_and_empty(tmp_path):
    root = str(tmp_path)
    assert tar_extract._safe_resolve(root, ["etc", "", ".", "x"]) == os.path.join(root, "etc", "x")


def test_safe_resolve_parent_clamped_at_root(tmp_path):
    root = str(tmp_path)
    # Leading ".." can't ascend above root; it's just discarded.
    assert tar_extract._safe_resolve(root, ["..", "..", "etc"]) == os.path.join(root, "etc")


def test_safe_resolve_parent_pops(tmp_path):
    root = str(tmp_path)
    assert tar_extract._safe_resolve(root, ["a", "b", "..", "c"]) == os.path.join(root, "a", "c")


def test_safe_resolve_absolute_symlink_reroots_in_rootfs(tmp_path):
    root = str(tmp_path)
    # A symlink pointing at absolute "/" resolves back to root, not the host.
    os.symlink("/", os.path.join(root, "link"))
    assert tar_extract._safe_resolve(root, ["link", "etc"]) == os.path.join(root, "etc")


def test_safe_resolve_symlink_loop_returns_none(tmp_path):
    root = str(tmp_path)
    # a -> b, b -> a : resolving through them blows the link budget.
    os.symlink("a", os.path.join(root, "b"))
    os.symlink("b", os.path.join(root, "a"))
    assert tar_extract._safe_resolve(root, ["a", "x"]) is None


# ── _apply_whiteout ─────────────────────────────────────────────────────────────
def test_apply_whiteout_regular(tmp_path):
    parent = str(tmp_path)
    victim = tmp_path / "gone"
    victim.write_text("x")
    assert tar_extract._apply_whiteout([".wh.gone"], parent) is True
    assert not victim.exists()


def test_apply_whiteout_opaque_clears_dir(tmp_path):
    parent = str(tmp_path)
    (tmp_path / "a").write_text("1")
    (tmp_path / "b").mkdir()
    assert tar_extract._apply_whiteout([".wh..wh..opq"], parent) is True
    assert list(tmp_path.iterdir()) == []


def test_apply_whiteout_not_a_whiteout(tmp_path):
    assert tar_extract._apply_whiteout(["regular.txt"], str(tmp_path)) is False

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


# ── _is_whiteout / _apply_whiteout ─────────────────────────────────────────────
def test_is_whiteout():
    assert tar_extract._is_whiteout(".wh.gone")
    assert tar_extract._is_whiteout(".wh..wh..opq")
    assert not tar_extract._is_whiteout("regular.txt")


def test_apply_whiteout_regular(tmp_path):
    victim = tmp_path / "gone"
    victim.write_text("x")
    parent_fd = os.open(str(tmp_path), os.O_RDONLY | os.O_DIRECTORY)
    try:
        tar_extract._apply_whiteout(parent_fd, ".wh.gone")
    finally:
        os.close(parent_fd)
    assert not victim.exists()


def test_apply_whiteout_opaque_clears_dir(tmp_path):
    (tmp_path / "a").write_text("1")
    (tmp_path / "b").mkdir()
    (tmp_path / "b" / "deep").write_text("2")
    parent_fd = os.open(str(tmp_path), os.O_RDONLY | os.O_DIRECTORY)
    try:
        tar_extract._apply_whiteout(parent_fd, ".wh..wh..opq")
    finally:
        os.close(parent_fd)
    assert list(tmp_path.iterdir()) == []


def test_apply_whiteout_cannot_name_the_parent_or_above(tmp_path):
    """`.wh...`, `.wh..` and `.wh.` name no sibling, so they remove nothing.

    Without the guard the slice after the prefix is '..', '.' or '', and the
    removal took the parent's parent (for a whiteout at the top of a layer,
    one level above the extraction root) or the parent's own contents.
    """
    root = tmp_path / "rootfs"
    root.mkdir()
    (root / "keep").write_text("x")
    sibling = tmp_path / "manifest.json"
    sibling.write_text("{}")
    parent_fd = os.open(str(root), os.O_RDONLY | os.O_DIRECTORY)
    try:
        for name in (".wh...", ".wh..", ".wh."):
            tar_extract._apply_whiteout(parent_fd, name)
    finally:
        os.close(parent_fd)
    assert (root / "keep").exists()
    assert sibling.exists()

import os

import pytest

from chroot_distro.helpers import max_iso_holder as mih


# ── main: setup failure is reported over ready-fd ───────────────────────────────
def test_main_setup_failure_writes_error_to_ready_fd():
    # chroot to a nonexistent rootfs fails; main must catch it, write "E..."
    # to the ready-fd, and return 1 without raising.
    r, w = os.pipe()
    config = '{"rootfs": "/nonexistent/does/not/exist"}'
    rc = mih.main(["--config", config, "--ready-fd", str(w)])
    assert rc == 1
    msg = os.read(r, 240)
    os.close(r)
    assert msg.startswith(b"E")


def test_main_missing_config_arg_exits():
    with pytest.raises(SystemExit):
        mih.main([])


# ── setup: chroot into a bad rootfs raises (best-effort mounts aside) ────────────
def test_setup_bad_rootfs_raises():
    with pytest.raises(OSError):
        mih.setup({"rootfs": "/nonexistent/does/not/exist"})


# ── _make_node: FileExistsError and OSError are swallowed (best-effort) ──────────
def test_make_node_existing_is_silent(tmp_path):
    target = tmp_path / "already"
    target.write_text("")
    # mknod on an existing path raises FileExistsError, which _make_node swallows.
    mih._make_node(str(target), 1, 3, 0o666)  # must not raise

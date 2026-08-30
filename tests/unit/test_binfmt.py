import os
from unittest.mock import patch

from chroot_distro.helpers import binfmt

# Straight from qemu's own scripts/qemu-binfmt-conf.sh, so a drift in the
# generated signature shows up as a diff against the reference, not a guess.
QEMU_AARCH64_MAGIC = b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\xb7\x00"
QEMU_AARCH64_MASK = b"\xff\xff\xff\xff\xff\xff\xff\x00\xff\xff\xff\xff\xff\xff\xff\xff\xfe\xff\xff\xff"


def _write_entry(directory, name, *, interpreter, magic, mask, enabled=True, offset=0):
    head = "enabled\n" if enabled else "disabled\n"
    body = f"interpreter {interpreter}\nflags: PF\noffset {offset}\nmagic {magic.hex()}\nmask {mask.hex()}\n"
    (directory / name).write_text(head + body)


def test_elf_signature_matches_qemus_own_table():
    assert binfmt._elf_signature("aarch64") == (QEMU_AARCH64_MAGIC, QEMU_AARCH64_MASK)
    assert binfmt._elf_signature("mips") is None


def test_registered_interpreter_matches_by_magic_not_by_name(tmp_path):
    _write_entry(
        tmp_path,
        "some-vendor-name",
        interpreter="/usr/bin/qemu-aarch64-static",
        magic=QEMU_AARCH64_MAGIC,
        mask=QEMU_AARCH64_MASK,
    )
    with patch.object(binfmt, "BINFMT_DIR", str(tmp_path)):
        assert binfmt.registered_interpreter("aarch64") == "/usr/bin/qemu-aarch64-static"
        assert binfmt.registered_interpreter("riscv64") is None


def test_registered_interpreter_ignores_entries_it_cannot_judge(tmp_path):
    _write_entry(
        tmp_path,
        "qemu-aarch64",
        interpreter="/usr/bin/qemu-aarch64-static",
        magic=QEMU_AARCH64_MAGIC,
        mask=QEMU_AARCH64_MASK,
        enabled=False,
    )
    (tmp_path / "python3.12").write_text("enabled\ninterpreter /usr/bin/python3.12\nflags: \nextension .py\n")
    with patch.object(binfmt, "BINFMT_DIR", str(tmp_path)):
        assert binfmt.registered_interpreter("aarch64") is None


def test_ensure_handler_registers_with_the_fix_binary_flag(tmp_path):
    register = tmp_path / "register"
    register.write_text("")
    with (
        patch.object(binfmt, "BINFMT_DIR", str(tmp_path)),
        patch.object(binfmt, "_REGISTER", str(register)),
        patch.object(binfmt, "find_emulator", return_value="/usr/bin/qemu-aarch64-static"),
    ):
        interpreter, reason = binfmt.ensure_handler("aarch64")

    assert (interpreter, reason) == ("/usr/bin/qemu-aarch64-static", "")
    fields = register.read_text().strip("\n").split(":")
    assert fields[1] == "cd-qemu-aarch64"
    assert fields[2] == "M"
    assert fields[6] == "/usr/bin/qemu-aarch64-static"
    # F is what survives the chroot; C would make setuid a host-wide escalation.
    assert "F" in fields[7] and "C" not in fields[7]
    assert fields[4] == "".join(f"\\x{b:02x}" for b in QEMU_AARCH64_MAGIC)


def test_ensure_handler_leaves_an_existing_entry_alone(tmp_path):
    register = tmp_path / "register"
    register.write_text("")
    _write_entry(
        tmp_path,
        "qemu-aarch64",
        interpreter="/opt/qemu-aarch64",
        magic=QEMU_AARCH64_MAGIC,
        mask=QEMU_AARCH64_MASK,
    )
    with (
        patch.object(binfmt, "BINFMT_DIR", str(tmp_path)),
        patch.object(binfmt, "_REGISTER", str(register)),
    ):
        assert binfmt.ensure_handler("aarch64") == ("/opt/qemu-aarch64", "")
    assert register.read_text() == ""


def test_ensure_handler_reports_why_it_could_not_register(tmp_path):
    register = tmp_path / "register"
    register.write_text("")
    with (
        patch.object(binfmt, "BINFMT_DIR", str(tmp_path)),
        patch.object(binfmt, "_REGISTER", str(register)),
        patch.object(binfmt, "find_emulator", return_value=None),
    ):
        interpreter, reason = binfmt.ensure_handler("aarch64")
    assert interpreter is None
    assert "emulator" in reason

    with (
        patch.object(binfmt, "BINFMT_DIR", str(tmp_path)),
        patch.object(binfmt, "_REGISTER", str(tmp_path / "absent")),
    ):
        interpreter, reason = binfmt.ensure_handler("aarch64")
    assert interpreter is None
    assert "CONFIG_BINFMT_MISC" in reason


def test_ensure_handler_honours_cd_no_binfmt(tmp_path, monkeypatch):
    monkeypatch.setenv("CD_NO_BINFMT", "1")
    with patch.object(binfmt, "BINFMT_DIR", str(tmp_path)):
        interpreter, reason = binfmt.ensure_handler("aarch64")
    assert interpreter is None
    assert "CD_NO_BINFMT" in reason


def test_cd_no_binfmt_still_reports_an_entry_someone_else_registered(tmp_path, monkeypatch):
    monkeypatch.setenv("CD_NO_BINFMT", "1")
    _write_entry(
        tmp_path,
        "qemu-aarch64",
        interpreter="/usr/bin/qemu-aarch64-static",
        magic=QEMU_AARCH64_MAGIC,
        mask=QEMU_AARCH64_MASK,
    )
    with patch.object(binfmt, "BINFMT_DIR", str(tmp_path)):
        assert binfmt.ensure_handler("aarch64") == ("/usr/bin/qemu-aarch64-static", "")


def test_find_emulator_prefers_a_static_build(tmp_path):
    for name in ("qemu-aarch64", "qemu-aarch64-static"):
        path = tmp_path / name
        path.write_text("")
        os.chmod(path, 0o755)
    with patch.object(binfmt, "_SEARCH_DIRS", (str(tmp_path),)):
        assert binfmt.find_emulator("aarch64") == f"{tmp_path}/qemu-aarch64-static"
        assert binfmt.find_emulator("riscv64") is None


def test_covered_arches_lists_what_can_run(tmp_path):
    _write_entry(
        tmp_path,
        "qemu-aarch64",
        interpreter="/usr/bin/qemu-aarch64-static",
        magic=QEMU_AARCH64_MAGIC,
        mask=QEMU_AARCH64_MASK,
    )
    with patch.object(binfmt, "BINFMT_DIR", str(tmp_path)):
        assert binfmt.covered_arches() == ["aarch64"]

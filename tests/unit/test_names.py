import pytest

from chroot_distro.exceptions import InvalidNameError
from chroot_distro.names import NAME_RULE_HINT, is_valid_name, require_valid_name


def test_is_valid_name():
    # Valid names
    assert is_valid_name("ubuntu") is True
    assert is_valid_name("debian-11") is True
    assert is_valid_name("alpine.3.15") is True
    assert is_valid_name("arch_linux") is True
    assert is_valid_name("123_456") is True

    # Invalid names
    assert is_valid_name("") is False
    assert is_valid_name(" ") is False
    assert is_valid_name("_ubuntu") is False
    assert is_valid_name(".debian") is False
    assert is_valid_name("-alpine") is False
    assert is_valid_name("ubuntu/debian") is False
    assert is_valid_name("ubuntu@123") is False
    assert is_valid_name("ubuntu ") is False
    assert is_valid_name(" ubuntu") is False


def test_require_valid_name():
    # Should not raise exception
    require_valid_name("ubuntu")
    require_valid_name("debian-11", kind="test name")

    # Should raise InvalidNameError
    with pytest.raises(InvalidNameError) as exc_info:
        require_valid_name("-invalid")
    assert "container name '-invalid' is not valid" in str(exc_info.value)

    with pytest.raises(InvalidNameError) as exc_info:
        require_valid_name("invalid/name", kind="custom name")
    assert "custom name 'invalid/name' is not valid" in str(exc_info.value)


def test_trailing_newline_should_be_rejected():
    assert is_valid_name("foo\n") is False


def test_require_valid_name_escapes_rejected_name():
    with pytest.raises(InvalidNameError) as exc_info:
        require_valid_name("box\x1b[2J\n\x9b\u202e\udc80")

    assert str(exc_info.value) == (
        r"container name 'box\x1b[2J\n\x9b\u202e\udc80' is not valid. " + NAME_RULE_HINT
    )

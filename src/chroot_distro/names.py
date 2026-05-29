import re

from chroot_distro.exceptions import InvalidNameError

_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.\-]*$")

NAME_RULE_HINT = (
    "It must begin with a letter or digit and contain only letters, "
    "digits, underscores, dots, or hyphens."
)


def is_valid_name(name: str) -> bool:
    """Return True iff *name* satisfies the container-name regex."""
    return bool(_NAME_RE.match(name or ""))


def require_valid_name(name: str, kind: str = "container name") -> None:
    """Raise InvalidNameError when *name* is invalid; otherwise return None."""
    if not is_valid_name(name):
        raise InvalidNameError(f"{kind} '{name}' is not valid. {NAME_RULE_HINT}")

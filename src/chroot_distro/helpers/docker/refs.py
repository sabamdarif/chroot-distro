# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
"""Image references: Docker's grammar, and the total lookups on top of it.

`parse_reference()` is distribution/reference's grammar, normalised the way `docker pull`
normalises and refusing what Docker refuses. Every place a reference comes *in* asks it:
`install`, `push`, `build -t`, a Dockerfile's FROM and COPY --from, and pull_image() and
push_image() themselves. Splitting a string was not enough, only wrong: `ubuntu#x` and
`ubuntu&scope=...` reached the registry URL and the token request as written, `ubuntu:`
asked for `/manifests/`, `build -t ../../x:1` was taken with `..` for a registry while
`build -t localhost:5000/app` was refused.

The rest (`canonical_ref`, `parse_image_ref`, `with_explicit_tag`, `derive_alias`) are
total. They are handed strings nothing validated, out of a container's `manifest.json` or
a cache entry, and a lookup must not raise on one: a valid reference gets the grammar's
answer, anything else the old loose split, which is used only to look something up and
never to reach a registry.

`ARCH_TO_DOCKER` maps a `uname -m` value to the (architecture, variant) pair a manifest
list is matched against; `arm` carrying `v7` is the only variant that matters in
practice. `derive_alias` picks the local container name from the last repo component.
"""

import re
from typing import NamedTuple

ARCH_TO_DOCKER = {
    "aarch64": ("arm64", ""),
    "arm": ("arm", "v7"),
    "i686": ("386", ""),
    "x86_64": ("amd64", ""),
    "riscv64": ("riscv64", ""),
}

# Reverse of ARCH_TO_DOCKER: a Docker architecture name to the chroot-distro one.
DOCKER_TO_ARCH = {docker: pd for pd, (docker, _variant) in ARCH_TO_DOCKER.items()}

# The grammar. ASCII throughout (`re.ASCII`), because Go's \w is [0-9A-Za-z_] and
# Python's is every letter in Unicode. Matched with fullmatch(), since `$` also
# matches before a trailing newline.
_ALNUM = r"[a-z0-9]+"
_SEPARATOR = r"(?:[._]|__|-+)"
_PATH_COMPONENT = rf"{_ALNUM}(?:{_SEPARATOR}{_ALNUM})*"
_REMOTE_NAME = rf"{_PATH_COMPONENT}(?:/{_PATH_COMPONENT})*"
_DOMAIN_COMPONENT = r"(?:[a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9])"
_DOMAIN_NAME = rf"{_DOMAIN_COMPONENT}(?:\.{_DOMAIN_COMPONENT})*"
_IPV6_HOST = r"\[[a-fA-F0-9:]+\]"
_TAG = r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}"
_DIGEST = r"[A-Za-z][A-Za-z0-9]*(?:[-_+.][A-Za-z][A-Za-z0-9]*)*:[0-9a-fA-F]{32,}"

_DOMAIN_RE = re.compile(rf"(?:{_DOMAIN_NAME}|{_IPV6_HOST})(?::([0-9]+))?", re.ASCII)
_REMAINDER_RE = re.compile(rf"({_REMOTE_NAME})(?::({_TAG}))?(?:@({_DIGEST}))?", re.ASCII)
_REMOTE_NAME_RE = re.compile(_REMOTE_NAME, re.ASCII)
# A bare image ID, which Docker refuses as a name so one can never be mistaken
# for the other.
_IDENTIFIER_RE = re.compile(r"[a-f0-9]{64}", re.ASCII)
# The one digest this program can compute (see cache.split_digest), in the form
# go-digest validates it to: lowercase, exactly 64 digits.
_SHA256_RE = re.compile(r"sha256:[a-f0-9]{64}", re.ASCII)

_DEFAULT_DOMAIN = "docker.io"
_HUB_ALIASES = frozenset((_DEFAULT_DOMAIN, "index.docker.io"))
_OFFICIAL_PREFIX = "library/"

# Docker's NameTotalLengthMax, counted over the normalised name
# ("docker.io/library/ubuntu" for `ubuntu`).
NAME_MAX = 255
# Far past anything valid (a name, a tag and a digest), checked before any pattern
# runs, so the time a match takes is never an argument's to choose.
_REFERENCE_MAX = 1024
_PORT_MAX = 65535


class InvalidReferenceError(RuntimeError):
    """A string that is not an image reference Docker would accept.

    A RuntimeError because that is what pull_image() promises its callers: `install`
    reports one, and `build`'s FROM and COPY --from turn one into a BuildError. The
    message never contains the reference itself; the caller names it, through
    quote_path, since it is the user's or a Dockerfile's text.
    """


class Reference(NamedTuple):
    """An image reference, normalised.

    *registry* is '' for Docker Hub. *tag* is '' only when the reference is pinned by
    *digest* alone; *digest* is '' unless it is pinned.
    """

    registry: str
    repo: str
    tag: str
    digest: str

    @property
    def name(self) -> str:
        """'[registry/]repo', the repository without tag or digest."""
        return f"{self.registry}/{self.repo}" if self.registry else self.repo

    @property
    def canonical(self) -> str:
        """The one spelling every way of writing this image collapses to.

        A pinned reference drops its tag: `debian:12@sha256:...` and `debian@sha256:...`
        are the same image, and the digest is what is pulled.
        """
        if self.digest:
            return f"{self.name}@{self.digest}"
        return f"{self.name}:{self.tag}"

    @property
    def manifest_ref(self) -> str:
        """What goes after `/manifests/`: the digest when pinned, else the tag."""
        return self.digest or self.tag


def _split_domain(ref: str) -> tuple[str, str]:
    """Docker's splitDockerDomain: (registry, remainder), '' for Docker Hub.

    The first component names a registry when it holds a '.' or a ':', is `localhost`,
    or has an upper-case letter, since a repository path cannot. Otherwise the whole
    string is a Docker Hub path, and a single-component one is an official image under
    `library/`.
    """
    first, slash, rest = ref.partition("/")
    if not slash or (not any(c in first for c in ".:") and first != "localhost" and first.lower() == first):
        domain, remainder = "", ref
    else:
        domain, remainder = first, rest
    if domain in _HUB_ALIASES:
        domain = ""
    if not domain and "/" not in remainder:
        remainder = _OFFICIAL_PREFIX + remainder
    return domain, remainder


def parse_reference(ref: str) -> Reference:
    """Parse *ref* by Docker's reference grammar. Raises InvalidReferenceError.

      'ubuntu'                   -> ('', 'library/ubuntu', 'latest', '')
      'docker.io/myuser/img:1.0' -> ('', 'myuser/img', '1.0', '')
      'localhost:5000/app'       -> ('localhost:5000', 'app', 'latest', '')
      'localhost/app'            -> ('localhost', 'app', 'latest', '')
      'debian:12@sha256:<hex>'   -> ('', 'library/debian', '12', 'sha256:<hex>')

    A digest must be sha256, the one algorithm this program can check a download
    against: a pin that cannot be verified pins nothing.
    """
    if not isinstance(ref, str) or not ref:
        raise InvalidReferenceError("invalid reference format: it is empty")
    if len(ref) > _REFERENCE_MAX:
        raise InvalidReferenceError(f"invalid reference format: longer than {_REFERENCE_MAX} characters")
    if _IDENTIFIER_RE.fullmatch(ref):
        raise InvalidReferenceError(
            "invalid repository name: a 64-character hexadecimal string is an image ID, not a name"
        )

    domain, remainder = _split_domain(ref)
    # Checked on its own, as Docker does, for the message: a name with an upper-case
    # letter is the one mistake worth naming precisely.
    if remainder.partition(":")[0].lower() != remainder.partition(":")[0]:
        raise InvalidReferenceError("invalid reference format: repository name must be lowercase")

    if domain:
        host = _DOMAIN_RE.fullmatch(domain)
        if host is None:
            raise InvalidReferenceError("invalid reference format: registry host is not valid")
        if host.group(1) is not None and int(host.group(1)) > _PORT_MAX:
            raise InvalidReferenceError("invalid reference format: registry port is out of range")

    parts = _REMAINDER_RE.fullmatch(remainder)
    if parts is None:
        raise InvalidReferenceError("invalid reference format")
    repo, tag, digest = parts.groups()

    if len(f"{domain or _DEFAULT_DOMAIN}/{repo}") > NAME_MAX:
        raise InvalidReferenceError(
            f"invalid reference format: repository name must not be more than {NAME_MAX} characters"
        )

    if digest is not None and not _SHA256_RE.fullmatch(digest):
        algorithm = digest.partition(":")[0]
        if algorithm != "sha256":
            raise InvalidReferenceError(f"unsupported digest algorithm '{algorithm}' (only sha256 is supported)")
        raise InvalidReferenceError("invalid digest: sha256 is 64 lowercase hexadecimal digits")

    return Reference(
        registry=domain,
        repo=repo,
        tag=tag or ("" if digest else "latest"),
        digest=digest or "",
    )


def parse_tag_reference(ref: str) -> Reference:
    """parse_reference() for a name an image is given: no digest.

    `build -t` and `push` name the image by its tag, and a digest is what the registry
    computes from the manifest: nothing a build can choose or a push can ask for.
    """
    parsed = parse_reference(ref)
    if parsed.digest:
        raise InvalidReferenceError("a digest reference cannot name an image to build or push; use a tag")
    return parsed


def is_repository_path(name: str) -> bool:
    """True when *name* is a repository path Docker would accept.

    The path alone (`library/ubuntu`, `myuser/img`), with no registry, tag or digest:
    what Docker Hub's search answers with.
    """
    return (
        isinstance(name, str)
        and len(name) <= NAME_MAX
        and _REMOTE_NAME_RE.fullmatch(name) is not None
    )


def _split_loosely(image_ref: str) -> tuple[str, str, str]:
    """(registry, repo, tag) for a string the grammar does not accept.

    What every reference got before there was a grammar, kept for the total functions
    below and nothing else: a lookup has to answer for a string out of a file or off a
    command line, and nothing that reaches a registry is split this way.
    """
    parts = image_ref.split("/", 1)
    if len(parts) == 2 and ("." in parts[0] or ":" in parts[0]):
        registry = parts[0]
        remainder = parts[1]
    else:
        registry = ""
        remainder = image_ref

    if registry in _HUB_ALIASES:
        registry = ""

    if ":" in remainder:
        name, tag = remainder.rsplit(":", 1)
    else:
        name, tag = remainder, "latest"

    repo = (name if "/" in name else f"{_OFFICIAL_PREFIX}{name}") if not registry else name

    return registry, repo, tag


def parse_image_ref(image_ref: str) -> tuple[str, str, str]:
    """Parse an image reference into (registry, repo, tag). Never raises.

    Docker Hub images (no registry host):
      'ubuntu'           -> ('', 'library/ubuntu', 'latest')
      'ubuntu:24.04'     -> ('', 'library/ubuntu', '24.04')
      'myuser/img:1.0'   -> ('', 'myuser/img', '1.0')
      'docker.io/library/ubuntu:24.04' -> ('', 'library/ubuntu', '24.04')

    Custom registry images (see _split_domain for what names a host):
      'ghcr.io/foo/bar:latest' -> ('ghcr.io', 'foo/bar', 'latest')
      'localhost/app'          -> ('localhost', 'app', 'latest')

    A pinned reference answers with its tag, '' when it has none. A string the grammar
    refuses is split the old loose way; anything that reaches a registry is checked
    with parse_reference() instead.
    """
    try:
        parsed = parse_reference(image_ref)
    except InvalidReferenceError:
        return _split_loosely(image_ref)
    return parsed.registry, parsed.repo, parsed.tag


def canonical_ref(image_ref: str) -> str:
    """Return the fully-qualified '[registry/]repo:tag' form of *image_ref*.

    'ubuntu'                         -> 'library/ubuntu:latest'
    'docker.io/library/ubuntu:24.04' -> 'library/ubuntu:24.04'
    'ghcr.io/foo/bar'                -> 'ghcr.io/foo/bar:latest'
    'debian:12@sha256:<hex>'         -> 'library/debian@sha256:<hex>'

    Every spelling of one image collapses to a single string here, which is what the
    manifest cache key is derived from. The string is the same one the loose split
    always produced for every reference it understood, so no key recorded before the
    grammar moves: `localhost/app` is now a registry and a repository rather than one
    Docker Hub path, and spells `localhost/app:latest` either way.
    """
    try:
        return parse_reference(image_ref).canonical
    except InvalidReferenceError:
        registry, repo, tag = _split_loosely(image_ref)
        return f"{registry}/{repo}:{tag}" if registry else f"{repo}:{tag}"


def with_explicit_tag(image_ref: str) -> str:
    """Append ':latest' when the reference's last component carries no tag.

    Unlike canonical_ref() this preserves the reference as the user spelled it (no
    'library/' insertion), which is what commands echo back. A pinned reference is left
    as it is: its last component holds the digest's ':', so it needs no tag.
    """
    last = image_ref.rsplit("/", maxsplit=1)[-1]
    return image_ref if ":" in last else image_ref + ":latest"


def derive_alias(image_ref: str) -> str:
    """Derive a short local alias from an image reference.

    'ubuntu:24.04'           -> 'ubuntu'
    'myuser/img:tag'         -> 'img'
    'ghcr.io/foo/bar:tag'    -> 'bar'
    'localhost:5000/foo:tag' -> 'foo'
    'debian@sha256:<hex>'    -> 'debian'

    Routes through parse_image_ref so a colon in a registry host (a port number) is not
    mistaken for the start of the tag.
    """
    _registry, repo, _tag = parse_image_ref(image_ref)
    return repo.split("/")[-1]

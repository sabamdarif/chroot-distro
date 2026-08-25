# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
"""Image reference parsing: the one place a user's string becomes (registry, repo, tag).

A reference has no delimiter that says "this is a host", so the rule is Docker's own: a
first component holding a dot or a colon is a registry, anything else is part of the
repository. That is what makes `localhost:5000/foo` a registry and `myuser/img` a repo,
and it is why the bare-name case gets `library/` prefixed only when no registry was
found. `docker.io` and `index.docker.io` normalise to the empty string, so Docker Hub
has exactly one spelling everywhere downstream.

`ARCH_TO_DOCKER` maps a `uname -m` value to the (architecture, variant) pair a manifest
list is matched against; `arm` carrying `v7` is the only variant that matters in
practice. `derive_alias` picks the local container name from the last repo component.
"""

ARCH_TO_DOCKER = {
    "aarch64": ("arm64", ""),
    "arm": ("arm", "v7"),
    "i686": ("386", ""),
    "x86_64": ("amd64", ""),
    "riscv64": ("riscv64", ""),
}


def parse_image_ref(image_ref: str) -> tuple[str, str, str]:
    """Parse an image reference into (registry, repo, tag).

    Docker Hub images (no registry host):
      'ubuntu'           -> ('', 'library/ubuntu', 'latest')
      'ubuntu:24.04'     -> ('', 'library/ubuntu', '24.04')
      'myuser/img:1.0'   -> ('', 'myuser/img', '1.0')
      'docker.io/library/ubuntu:24.04' -> ('', 'library/ubuntu', '24.04')

    Custom registry images (host contains a dot or colon):
      'ghcr.io/foo/bar:latest' -> ('ghcr.io', 'foo/bar', 'latest')
    """
    parts = image_ref.split("/", 1)
    if len(parts) == 2 and ("." in parts[0] or ":" in parts[0]):
        registry = parts[0]
        remainder = parts[1]
    else:
        registry = ""
        remainder = image_ref

    if registry in ("docker.io", "index.docker.io"):
        registry = ""

    if ":" in remainder:
        name, tag = remainder.rsplit(":", 1)
    else:
        name, tag = remainder, "latest"

    repo = (name if "/" in name else f"library/{name}") if not registry else name

    return registry, repo, tag


def derive_alias(image_ref: str) -> str:
    """Derive a short local alias from an image reference.

    'ubuntu:24.04'             -> 'ubuntu'
    'myuser/img:tag'           -> 'img'
    'ghcr.io/foo/bar:tag'      -> 'bar'
    'localhost:5000/foo:tag'   -> 'foo'
    """
    _registry, repo, _tag = parse_image_ref(image_ref)
    return repo.split("/")[-1]

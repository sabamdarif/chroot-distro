ARCH_TO_DOCKER = {
    "aarch64": ("arm64",   ""),
    "arm":     ("arm",     "v7"),
    "i686":    ("386",     ""),
    "x86_64":  ("amd64",   ""),
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

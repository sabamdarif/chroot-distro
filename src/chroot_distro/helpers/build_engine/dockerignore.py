import fnmatch
import glob as _glob
import os


def load_dockerignore(build_dir: str) -> list[str]:
    """Return the list of `.dockerignore` patterns from *build_dir*."""
    path = os.path.join(build_dir, ".dockerignore")
    patterns = []
    try:
        with open(path) as fh:
            for line in fh:
                s = line.rstrip("\n").rstrip("\r").strip()
                if not s or s.startswith("#"):
                    continue
                patterns.append(s)
    except OSError:
        pass
    return patterns


def is_ignored(rel_path: str, patterns: list[str]) -> bool:
    """Return True iff *rel_path* matches the loaded ignore patterns."""
    if not patterns:
        return False
    # `Dockerfile` and `.dockerignore` themselves are never ignored.
    if rel_path in ("Dockerfile", ".dockerignore"):
        return False
    ignored = False
    for pat in patterns:
        negate = pat.startswith("!")
        p = pat[1:] if negate else pat
        if _match(rel_path, p):
            ignored = not negate
    return ignored


def _match(rel_path: str, pattern: str) -> bool:
    pat = pattern.replace(os.sep, "/").strip("/")
    rel = rel_path.replace(os.sep, "/").strip("/")
    if "**" in pat:
        pat = pat.replace("**", "*")
    if fnmatch.fnmatchcase(rel, pat):
        return True
    # Prefix match: a pattern like `node_modules` ignores its children.
    parts = rel.split("/")
    for i in range(1, len(parts) + 1):
        prefix = "/".join(parts[:i])
        if fnmatch.fnmatchcase(prefix, pat):
            return True
    return False


def simple_glob(base: str, pattern: str) -> list[str]:
    """Tiny glob: supports * and ? only (no ** recursion). Returns rel paths."""
    abs_pat = os.path.join(base, pattern)
    matches = _glob.glob(abs_pat)
    return [os.path.relpath(p, base) for p in matches]

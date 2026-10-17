# Named build contexts: what --build-context accepts, and how FROM and
# COPY --from= resolve a name against the table.

# A context value is a local directory or an image reference; git and URL
# shapes are refused by name before the locks. A stage name keeps priority
# over a named context, a local context in FROM is scratch plus a copy of the
# tree with that tree's own .dockerignore, and an image context pulls the
# reference it names, so a name that shadows a registry name is what Docker
# gives the same spelling.

import os

import pytest

from chroot_distro import dirfd
from chroot_distro.arch import Platform
from chroot_distro.helpers import build_contexts
from chroot_distro.helpers.build_engine import BuildRequest, copy_step, solve_platform
from chroot_distro.helpers.build_engine.errors import BuildError
from chroot_distro.helpers.dockerfile import parse_dockerfile

ARM64 = Platform("linux", "arm64")
AMD64 = Platform("linux", "amd64")


# ── parsing ─────────────────────────────────────────────────────────────
def test_names_are_lowercased_and_values_kept():
    assert build_contexts.parse_build_contexts(["Foo=/tmp/x", "img=alpine:3"]) == {
        "foo": "/tmp/x",
        "img": "alpine:3",
    }


@pytest.mark.parametrize("spec", ["noeq", "=/tmp/x", "foo=", "foo= "])
def test_a_malformed_spec_is_refused(spec):
    with pytest.raises(BuildError, match="--build-context"):
        build_contexts.parse_build_contexts([spec])


@pytest.mark.parametrize("name", ["dockerfile", "DOCKERFILE", "bad name", "-foo", "f!oo"])
def test_a_reserved_or_invalid_name_is_refused(name):
    with pytest.raises(BuildError, match="--build-context"):
        build_contexts.parse_build_contexts([f"{name}=/tmp/x"])


@pytest.mark.parametrize(
    "value",
    [
        "git+https://github.com/a/b.git",
        "git://example.com/repo",
        "ssh://git@example.com/a/b.git",
        "git@github.com:a/b.git",
        "https://github.com/a/b.git",
    ],
)
def test_a_git_source_is_refused_with_the_alternative(value):
    with pytest.raises(BuildError, match="no git client") as exc_info:
        build_contexts.parse_build_contexts([f"src={value}"])
    message = str(exc_info.value)
    assert "build context" in message
    if value.startswith("git+http"):
        assert "/archive/" in message


def test_an_http_tarball_is_refused_as_a_context():
    with pytest.raises(BuildError, match="not a build context"):
        build_contexts.parse_build_contexts(["src=https://example.com/repo.tar.gz"])


def test_a_directory_value_is_resolved_and_an_image_ref_left_alone(tmp_path):
    assert build_contexts.resolve_context_dir(str(tmp_path)) == str(tmp_path)
    assert build_contexts.resolve_context_dir("alpine:3.20") == "alpine:3.20"
    assert build_contexts.resolve_context_dir("./missing").endswith("missing")


# ── the ADD refusal shares the wording ──────────────────────────────────
def test_add_git_refusal_names_the_alternative():
    message = copy_step.refuse_git_message("git+https://github.com/a/b.git")
    assert "no git client" in message
    assert "/archive/" in message
    assert "checkout" in message


# ── engine resolution ───────────────────────────────────────────────────
@pytest.fixture
def scratch(tmp_path):
    root = tmp_path / "scratch"
    root.mkdir()
    fd = dirfd.opendir(str(root))
    try:
        yield root, fd
    finally:
        os.close(fd)


@pytest.fixture
def packed(monkeypatch):
    """The bytes write_files_layer packed, keyed by layer digest.

    publish_file is what crosses from the scratch tree into the layer cache;
    intercepting it keeps a test from needing one.
    """
    blobs = {}

    def capture(src, dest):
        # layer_cache_path names a blob `sha256_<hex>`; the stage records
        # `sha256:<hex>`, so the key a test looks one up by is the digest.
        blobs["sha256:" + os.path.basename(dest).removeprefix("sha256_")] = open(src, "rb").read()

    monkeypatch.setattr(copy_step, "publish_file", capture)
    return blobs


def _solve(scratch, context_dir, text, build_contexts):
    root, fd = scratch
    _, instructions = parse_dockerfile(text)
    return solve_platform(
        BuildRequest(
            build_dir=str(context_dir),
            instructions=instructions,
            target_platform=ARM64,
            build_platform=AMD64,
            scratch_dir=str(root),
            scratch_fd=fd,
            quiet=True,
            build_contexts=build_contexts,
        )
    )


def test_copy_from_a_named_local_context(scratch, tmp_path, packed):
    context = tmp_path / "ctx"
    context.mkdir()
    extra = tmp_path / "extra"
    extra.mkdir()
    (extra / "hello.txt").write_text("hello")
    (extra / "noise.log").write_text("x")
    (extra / ".dockerignore").write_text("*.log\n")

    result = _solve(
        scratch,
        context,
        "FROM scratch\nCOPY --from=extra . /files/\n",
        {"extra": str(extra)},
    )

    names = _layer_names(packed[result.layers[-1]["digest"]])
    assert "files/hello.txt" in names
    assert not any("noise.log" in n for n in names)


def test_from_a_named_local_context_is_scratch_plus_the_tree(scratch, tmp_path, packed):
    context = tmp_path / "ctx"
    context.mkdir()
    (context / "app.py").write_text("print(1)\n")

    result = _solve(
        scratch,
        context,
        "FROM app\n",
        {"app": str(context)},
    )

    assert result.layers, "a FROM over a local context packs the tree as a layer"
    assert "app.py" in _layer_names(packed[result.layers[-1]["digest"]])
    # Scratch, not an image: one diff per copy, and no config a base left behind.
    assert [h["created_by"] for h in result.image_config["history"]] == ["COPY . / # --build-context app=" + str(context)]


def test_from_a_named_image_context_pulls_the_named_reference(scratch, tmp_path, monkeypatch):
    context = tmp_path / "ctx"
    context.mkdir()
    pulled = []

    def fake_pull(image_ref, _rootfs_fd, _platform):
        pulled.append(image_ref)
        return {"manifest": {}, "image_config": {"config": {}}}

    monkeypatch.setattr("chroot_distro.helpers.build_engine.engine.pull_image", fake_pull)

    _solve(scratch, context, "FROM base\n", {"base": "registry.example.com/real/image:1"})

    assert pulled == ["registry.example.com/real/image:1"]


def test_copy_from_a_named_image_context_pulls_it(scratch, tmp_path, monkeypatch, packed):
    context = tmp_path / "ctx"
    context.mkdir()
    pulled = []

    def fake_pull(image_ref, rootfs_fd, _platform):
        pulled.append(image_ref)
        fd, _st = dirfd.open_new_at(rootfs_fd, "artifact.txt", 0o644)
        os.write(fd, b"packed")
        os.close(fd)
        return {"manifest": {}, "image_config": {"config": {}}}

    monkeypatch.setattr(copy_step, "pull_image", fake_pull)

    result = _solve(
        scratch,
        context,
        "FROM scratch\nCOPY --from=imgsrc artifact.txt /a.txt\n",
        {"imgsrc": "registry.example.com/real/image:1"},
    )

    assert pulled == ["registry.example.com/real/image:1"]
    assert "a.txt" in _layer_names(packed[result.layers[-1]["digest"]])


def test_a_stage_name_keeps_priority_over_a_named_context(scratch, tmp_path):
    context = tmp_path / "ctx"
    context.mkdir()
    extra = tmp_path / "extra"
    extra.mkdir()
    (extra / "from-context.txt").write_text("ctx")

    # The COPY --from=deps below must read the stage's rootfs (empty), not the
    # context directory, so a source only the context holds is reported missing.
    with pytest.raises(BuildError, match="not found in stage"):
        _solve(
            scratch,
            context,
            "FROM scratch AS deps\nCOPY --from=deps from-context.txt /x\n",
            {"deps": str(extra)},
        )


def _layer_names(blob):
    import io
    import tarfile

    with tarfile.open(fileobj=io.BytesIO(blob), mode="r:*") as tf:
        return tf.getnames()

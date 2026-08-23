# Containment tests for a base image's own config document.
#
# `FROM <image>` adopts a config this program did not write: a registry sends
# one, and the manifest cache holds one -- a cache that on Termux sits under the
# bound $TERMUX_PREFIX and so is a guest's to compose. Every field is read back
# afterwards (User and Shell decide what a RUN step runs and who as, WorkingDir
# becomes the step's cwd, OnBuild is parsed as Dockerfile lines, the rest are
# merged into by their handlers and published in the image the build produces),
# and every consumer subscripts it as the type OCI says it is. So a wrong type
# is a message naming the field, never a traceback and never a value carried on.

import os
from types import SimpleNamespace

import pytest

from chroot_distro.helpers.build_engine import engine as engine_mod
from chroot_distro.helpers.build_engine.engine import _adopt_image_config
from chroot_distro.helpers.build_engine.errors import BuildError
from chroot_distro.helpers.build_engine.stage import Stage


# ── the shapes a wrong type takes ─────────────────────────────────────────────
@pytest.mark.parametrize("doc", ["a config", ["a config"], 5, None])
def test_a_document_that_is_not_an_object_is_refused(doc):
    with pytest.raises(BuildError, match="the document is not an object"):
        _adopt_image_config(doc, "img:1")


@pytest.mark.parametrize("cfg", ["x", ["x"], 5, True])
def test_config_that_is_not_an_object_is_refused(cfg):
    with pytest.raises(BuildError) as exc:
        _adopt_image_config({"config": cfg}, "img:1")
    assert "'config'" in str(exc.value)


@pytest.mark.parametrize("key", ["Cmd", "Entrypoint", "OnBuild", "Shell"])
@pytest.mark.parametrize("value", ["sh", 5, {"a": 1}, ["ok", 5]])
def test_argv_fields_must_be_lists_of_strings(key, value):
    with pytest.raises(BuildError) as exc:
        _adopt_image_config({"config": {key: value}}, "img:1")
    assert key in str(exc.value)


@pytest.mark.parametrize("key", ["User", "WorkingDir"])
@pytest.mark.parametrize("value", [5, ["root"], {"name": "root"}])
def test_user_and_workdir_must_be_strings(key, value):
    with pytest.raises(BuildError) as exc:
        _adopt_image_config({"config": {key: value}}, "img:1")
    assert key in str(exc.value)


@pytest.mark.parametrize("key", ["ExposedPorts", "Labels", "Volumes"])
@pytest.mark.parametrize("value", ["x", ["x"], 5])
def test_maps_must_be_objects(key, value):
    with pytest.raises(BuildError) as exc:
        _adopt_image_config({"config": {key: value}}, "img:1")
    assert key in str(exc.value)


def test_a_label_value_that_is_not_a_string_is_refused():
    with pytest.raises(BuildError, match="Labels"):
        _adopt_image_config({"config": {"Labels": {"a": [1]}}}, "img:1")


@pytest.mark.parametrize("value", ["A=1", ["A=1", 2]])
def test_env_must_be_a_list_of_strings(value):
    with pytest.raises(BuildError, match="Env"):
        _adopt_image_config({"config": {"Env": value}}, "img:1")


@pytest.mark.parametrize("value", ["nope", 5, {"a": 1}])
def test_history_must_be_a_list(value):
    with pytest.raises(BuildError) as exc:
        _adopt_image_config({"history": value, "config": {}}, "img:1")
    assert "history" in str(exc.value)


@pytest.mark.parametrize(
    "doc",
    [
        {"rootfs": "layers", "config": {}},
        {"rootfs": {"diff_ids": "sha256:x"}, "config": {}},
        {"rootfs": {"diff_ids": ["sha256:x", 7]}, "config": {}},
    ],
)
def test_rootfs_and_its_diff_ids_are_held_to_shape(doc):
    with pytest.raises(BuildError, match="rootfs"):
        _adopt_image_config(doc, "img:1")


def test_the_refusal_names_the_image():
    with pytest.raises(BuildError, match="FROM base:1"):
        _adopt_image_config({"config": {"OnBuild": 5}}, "base:1")


# ── what a registry really sends ──────────────────────────────────────────────
def test_null_is_not_set_and_is_removed_outright():
    # `.get(k) or default` and `setdefault(k, default)` do not answer alike for
    # a null: a setdefault for "history" finds the key and appends to None.
    doc = _adopt_image_config(
        {
            "history": None,
            "rootfs": None,
            "config": {
                "Env": None,
                "Cmd": None,
                "Entrypoint": None,
                "Shell": None,
                "OnBuild": None,
                "User": None,
                "WorkingDir": None,
                "Labels": None,
                "ExposedPorts": None,
                "Volumes": None,
            },
        },
        "img:1",
    )
    assert "history" not in doc and "rootfs" not in doc
    assert doc["config"] == {}


def test_a_missing_config_becomes_an_empty_one():
    assert _adopt_image_config({"architecture": "amd64"}, "img:1")["config"] == {}


def test_an_ordinary_config_survives_unchanged():
    doc = _adopt_image_config(
        {
            "architecture": "amd64",
            "os": "linux",
            "history": [{"created_by": "FROM x"}],
            "rootfs": {"type": "layers", "diff_ids": ["sha256:" + "a" * 64]},
            "config": {
                "Env": ["PATH=/usr/bin", "LANG=C.UTF-8"],
                "Cmd": ["/bin/sh"],
                "Entrypoint": ["/entry"],
                "Shell": ["/bin/bash", "-c"],
                "OnBuild": ["RUN echo hi"],
                "User": "app",
                "WorkingDir": "/srv",
                "Labels": {"maintainer": "someone", "empty": None},
                "ExposedPorts": {"80/tcp": {}},
                "Volumes": {"/data": {}},
            },
        },
        "img:1",
    )
    cfg = doc["config"]
    assert cfg["Env"] == ["PATH=/usr/bin", "LANG=C.UTF-8"]
    assert cfg["Cmd"] == ["/bin/sh"]
    assert cfg["Entrypoint"] == ["/entry"]
    assert cfg["Shell"] == ["/bin/bash", "-c"]
    assert cfg["OnBuild"] == ["RUN echo hi"]
    assert cfg["User"] == "app" and cfg["WorkingDir"] == "/srv"
    # A null label value is the empty string, as it is to every other reader of
    # a map of strings.
    assert cfg["Labels"] == {"maintainer": "someone", "empty": ""}
    assert cfg["ExposedPorts"] == {"80/tcp": {}}
    assert cfg["Volumes"] == {"/data": {}}
    assert doc["history"] == [{"created_by": "FROM x"}]
    assert doc["architecture"] == "amd64"


def test_a_port_or_volume_value_of_any_shape_becomes_the_empty_object():
    doc = _adopt_image_config({"config": {"ExposedPorts": {"80/tcp": 5}, "Volumes": {"/d": "x"}}}, "img:1")
    assert doc["config"]["ExposedPorts"] == {"80/tcp": {}}
    assert doc["config"]["Volumes"] == {"/d": {}}


def test_a_base_images_host_exec_env_is_dropped_where_it_is_adopted():
    # Filtered at the adopt rather than at each use: the stage env is seeded
    # from this list at FROM, `FROM <earlier stage>` copies the whole config,
    # and the config the build publishes as its own comes from here too.
    cfg = _adopt_image_config(
        {
            "config": {
                "Env": [
                    "LD_LIBRARY_PATH=lib",
                    "LD_AUDIT=lib/audit.so",
                    "LD_PRELOAD=/evil/pre.so",
                    "PATH=/usr/bin",
                    "LANG=C.UTF-8",
                ]
            }
        },
        "img:1",
    )["config"]
    assert cfg["Env"] == ["PATH=/usr/bin", "LANG=C.UTF-8"]


def test_an_env_entry_without_an_equals_is_left_alone():
    # Not this function's business to decide: do_env and login both read the
    # list as `k=v` and skip what is not.
    cfg = _adopt_image_config({"config": {"Env": ["LD_AUDIT", "bare"]}}, "img:1")["config"]
    assert cfg["Env"] == ["LD_AUDIT", "bare"]


# ── the manifest read alongside it ────────────────────────────────────────────
def _pulled(monkeypatch, tmp_path, meta):
    """Run _pull_base_image against a stubbed pull and return the stage."""
    rootfs = tmp_path / "rootfs"
    rootfs.mkdir()
    stage = Stage(index=0, name="", rootfs_dir=str(rootfs), target_arch_pd="x86_64")
    monkeypatch.setattr(engine_mod, "pull_image", lambda *_a, **_k: meta)
    monkeypatch.setattr(engine_mod, "log_info", lambda *_a, **_k: None)
    eng = SimpleNamespace(target_arch_pd="x86_64")
    before = set(os.listdir("/proc/self/fd"))
    engine_mod.BuildEngine._pull_base_image(eng, stage, "img:1")
    assert set(os.listdir("/proc/self/fd")) - before == set()
    return stage


def test_a_layer_size_that_is_not_an_int_is_read_as_absent(monkeypatch, tmp_path):
    # The digests here were all read by the pull already; `size` was not, and it
    # is copied into the manifest this build publishes.
    stage = _pulled(
        monkeypatch,
        tmp_path,
        {
            "image_config": {"config": {}},
            "manifest": {"layers": [{"digest": "sha256:a", "size": "12"}, {"digest": "sha256:b", "size": True}]},
        },
    )
    assert [layer["size"] for layer in stage.layers] == [0, 0]
    assert stage.parent_layer_digest == "sha256:b"


def test_a_diff_id_falls_back_to_the_digest_when_the_config_is_short(monkeypatch, tmp_path):
    stage = _pulled(
        monkeypatch,
        tmp_path,
        {
            "image_config": {"config": {}, "rootfs": {"diff_ids": ["sha256:one"]}},
            "manifest": {"layers": [{"digest": "sha256:a", "size": 3}, {"digest": "sha256:b", "size": 4}]},
        },
    )
    assert [layer["diff_id"] for layer in stage.layers] == ["sha256:one", "sha256:b"]


def test_a_malformed_config_ends_the_pull(monkeypatch, tmp_path):
    before = set(os.listdir("/proc/self/fd"))
    with pytest.raises(BuildError, match="OnBuild"):
        _pulled(monkeypatch, tmp_path, {"image_config": {"config": {"OnBuild": 5}}, "manifest": {}})
    assert set(os.listdir("/proc/self/fd")) - before == set()

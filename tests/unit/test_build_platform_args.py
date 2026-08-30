from chroot_distro.arch import Platform
from chroot_distro.helpers.build_engine.engine import BuildEngine


def test_engine_platform_defaults_include_variants(tmp_path):
    engine = BuildEngine(
        build_dir=str(tmp_path),
        tmp_root=str(tmp_path / "tmp"),
        target_arch_pd="x86_64",
        user_build_args={},
        target_stage=None,
        verbose=False,
        quiet=True,
        no_cache=False,
        emulator=None,
        target_platform=Platform("linux", "arm", "v7"),
        build_platform=Platform("linux", "amd64"),
    )

    scope = {}
    engine._set_arch_defaults(scope)

    assert scope == {
        "TARGETPLATFORM": "linux/arm/v7",
        "TARGETOS": "linux",
        "TARGETARCH": "arm",
        "TARGETVARIANT": "v7",
        "BUILDPLATFORM": "linux/amd64",
        "BUILDOS": "linux",
        "BUILDARCH": "amd64",
        "BUILDVARIANT": "",
    }


def test_stage_keeps_normalized_platform_and_legacy_arch(tmp_path):
    from chroot_distro.helpers.build_engine.stage import Stage

    stage = Stage(
        index=0,
        name="builder",
        rootfs_dir=str(tmp_path),
        target_arch_pd="x86_64",
        platform=Platform("linux", "arm", "v7"),
    )

    assert stage.platform == Platform("linux", "arm", "v7")
    assert stage.target_arch_pd == "arm"

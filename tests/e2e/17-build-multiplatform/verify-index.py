# Read a multi-platform OCI archive the way a consumer would: the index first,
# then one manifest and one config per descriptor, then the report the build
# wrote into each platform's own layers.
#
# Two things no single-platform archive could show are checked here. Every
# descriptor's platform has to match what its config declares, since that pairing
# is what a registry hands a puller. And each platform's /report has to name that
# platform, which is the automatic TARGET* ARGs of one solve reaching a layer
# rather than the other solve's.

import gzip
import hashlib
import io
import json
import sys
import tarfile

# `uname -m` for each Docker architecture name, so the report's own two answers
# can be held against each other.
UNAME_M = {"amd64": "x86_64", "arm64": "aarch64", "arm": "armv7l", "386": "i686", "riscv64": "riscv64"}


def blob(tf, digest):
    hex_digest = digest.split(":", 1)[1]
    member = f"blobs/sha256/{hex_digest}"
    data = tf.extractfile(member).read()
    if hashlib.sha256(data).hexdigest() != hex_digest:
        sys.exit(f"FAIL: {member} does not hash to its own name")
    return data


def platform_name(platform):
    name = platform["os"] + "/" + platform["architecture"]
    return name + "/" + platform["variant"] if platform.get("variant") else name


def report_of(tf, manifest):
    """The /report this platform's layers hold, as a dict of its key=value lines."""
    found = None
    for layer in manifest["layers"]:
        data = blob(tf, layer["digest"])
        if layer["mediaType"].endswith("+gzip"):
            data = gzip.decompress(data)
        with tarfile.open(fileobj=io.BytesIO(data)) as layer_tf:
            for name in ("report", "./report"):
                if name in layer_tf.getnames():
                    found = layer_tf.extractfile(name).read().decode()
    if found is None:
        sys.exit("FAIL: no layer of this platform carries /report")
    return dict(line.split("=", 1) for line in found.splitlines() if "=" in line)


expected = sys.argv[2:]
with tarfile.open(sys.argv[1]) as tf:
    names = tf.getnames()
    if names[0] != "oci-layout":
        sys.exit(f"FAIL: first member is '{names[0]}', not oci-layout")
    index = json.loads(tf.extractfile("index.json").read())
    docker = json.loads(tf.extractfile("manifest.json").read())

    described = []
    config_members = []
    for position, descriptor in enumerate(index["manifests"]):
        platform = descriptor["platform"]
        name = platform_name(platform)
        described.append(name)
        manifest = json.loads(blob(tf, descriptor["digest"]))
        config = json.loads(blob(tf, manifest["config"]["digest"]))
        config_members.append("blobs/sha256/" + manifest["config"]["digest"].split(":", 1)[1])
        for field in ("os", "architecture", "variant"):
            claimed = platform.get(field, "")
            if config.get(field, claimed) != claimed:
                sys.exit(
                    f"FAIL: descriptor {position} claims {field} '{claimed}', its config says '{config.get(field)}'"
                )

        report = report_of(tf, manifest)
        if report.get("target") != name:
            sys.exit(f"FAIL: the {name} image reports TARGETPLATFORM '{report.get('target')}'")
        if report.get("targetarch") != platform["architecture"]:
            sys.exit(f"FAIL: the {name} image reports TARGETARCH '{report.get('targetarch')}'")
        # The builder stage is pinned to the build platform, so it ran on this
        # host's own CPU whichever platform it was building for.
        ran_on = UNAME_M.get(report.get("buildarch", ""))
        if ran_on is not None and report.get("ran-on") != ran_on:
            sys.exit(f"FAIL: the {name} builder stage ran on '{report.get('ran-on')}', not '{ran_on}'")
        print(f"platform {name} target={report.get('target')} ran-on={report.get('ran-on')}")

    if expected and described != expected:
        sys.exit(f"FAIL: the index describes {described}, not {expected}")
    if len(docker) != 1:
        sys.exit(f"FAIL: the docker-legacy manifest holds {len(docker)} images, not one")
    if docker[0]["Config"] != config_members[0]:
        sys.exit("FAIL: the docker-legacy manifest does not describe the first platform asked for")

print(f"index {len(index['manifests'])} platforms")

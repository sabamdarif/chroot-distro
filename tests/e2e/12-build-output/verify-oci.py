import hashlib
import json
import sys
import tarfile


def blob(tf, digest):
    hex_digest = digest.split(":", 1)[1]
    member = f"blobs/sha256/{hex_digest}"
    data = tf.extractfile(member).read()
    if hashlib.sha256(data).hexdigest() != hex_digest:
        sys.exit(f"FAIL: {member} does not hash to its own name")
    return data


with tarfile.open(sys.argv[1]) as tf:
    names = tf.getnames()
    if names[0] != "oci-layout":
        sys.exit(f"FAIL: first member is '{names[0]}', not oci-layout")
    for required in ("index.json", "manifest.json"):
        if required not in names:
            sys.exit(f"FAIL: {required} missing from the archive")
    index = json.loads(tf.extractfile("index.json").read())
    docker = json.loads(tf.extractfile("manifest.json").read())
    manifest = json.loads(blob(tf, index["manifests"][0]["digest"]))
    config = json.loads(blob(tf, manifest["config"]["digest"]))

    config_member = "blobs/sha256/" + manifest["config"]["digest"].split(":", 1)[1]
    if docker[0]["Config"] != config_member:
        sys.exit("FAIL: the docker-legacy manifest points at another config blob")
    layer_members = []
    for layer in manifest["layers"]:
        data = blob(tf, layer["digest"])
        if len(data) != layer["size"]:
            sys.exit(f"FAIL: {layer['digest']} is {len(data)} bytes, the manifest says {layer['size']}")
        layer_members.append("blobs/sha256/" + layer["digest"].split(":", 1)[1])
    if docker[0]["Layers"] != layer_members:
        sys.exit("FAIL: the docker-legacy manifest lists another layer set")
    if len(config["rootfs"]["diff_ids"]) != len(manifest["layers"]):
        sys.exit("FAIL: diff_ids and layers disagree on how many layers there are")

print(f"layers {len(manifest['layers'])}")
print(f"arch {config['architecture']}")
for tag in docker[0]["RepoTags"]:
    print(f"tag {tag}")
for entry in config.get("config", {}).get("Env", []):
    print(f"env {entry}")

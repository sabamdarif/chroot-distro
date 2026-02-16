#!/bin/bash

# Enable strict mode
set -euo pipefail

if ! command -v npm &>/dev/null; then
	echo "Error: npm is not installed or not in PATH."
	exit 1
fi

echo "✅ npm found."

echo "Building WebUI..."
cd webui
npm ci
npm run build
cd ..
echo "✅ Built WebUI"

echo "Creating chroot-distro.zip..."
rm -f chroot-distro.zip

WORKDIR=$(mktemp -d)
trap 'rm -rf "$WORKDIR"' EXIT

cp -r module/* "$WORKDIR/"

rm -rf "$WORKDIR/screeenshots"

cp -r data "$WORKDIR/"

cp -r serviced "$WORKDIR/tools"

pushd "$WORKDIR" >/dev/null
zip -r "$OLDPWD/chroot-distro.zip" .
popd >/dev/null

ls -lh chroot-distro.zip
echo "✅ Created chroot-distro.zip"

#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
# Verify (output): both archives are complete OCI images
# Needs: 02-build.sh (the two archives), verify-oci.py.

set -eo pipefail

here=$(cd "$(dirname "$0")" && pwd)

# Root-owned: the archive is published from a 0600 temporary.
sudo python3 "$here/verify-oci.py" /tmp/out-build.tar | tee /tmp/oci-report.txt
sudo python3 "$here/verify-oci.py" /tmp/out-build.tar.gz > /tmp/oci-report-gz.txt
cat /tmp/oci-report-gz.txt

# Every blob hashed to its own name, so the tar carries the whole
# image rather than the prefix a lost write would have left.
diff /tmp/oci-report.txt /tmp/oci-report-gz.txt
echo "PASS: .tar and .tar.gz describe the same image"

layers=$(sed -n 's/^layers //p' /tmp/oci-report.txt)
[ "$layers" -ge 1 ] || { echo "FAIL: the image has no layers"; exit 1; }
grep -qx "tag test-build-out:latest" /tmp/oci-report.txt
echo "PASS: archive holds $layers layers and the primary tag"

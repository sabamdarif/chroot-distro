#!/usr/bin/env python3
import argparse
import json
import os
import re
import sys
from pathlib import Path

import requests

DISTRO_BUILD_DIR = Path("distro-build")
PROOT_DISTRO_BASE_URL = (
    "https://raw.githubusercontent.com/termux/proot-distro/master/distro-build"
)
KALI_MIRROR_URL = "http://cdimage.kali.org/current/"


def get_local_version(file_path):
    """Extracts dist_version from a local shell script."""
    with open(file_path, "r") as f:
        content = f.read()
        match = re.search(r'dist_version="([^"]+)"', content)
        if match:
            return match.group(1)
    return None


def get_upstream_proot_version(distro_name):
    """Fetches dist_version from upstream proot-distro."""
    url = f"{PROOT_DISTRO_BASE_URL}/{distro_name}.sh"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            match = re.search(r'dist_version="([^"]+)"', response.text)
            if match:
                return match.group(1)
    except Exception as e:
        print(f"Error fetching upstream for {distro_name}: {e}", file=sys.stderr)
    return None


def get_kali_version():
    """Fetches the latest Kali version from the mirror."""
    try:
        response = requests.get(KALI_MIRROR_URL, timeout=10)
        if response.status_code == 200:
            # Look for kali-linux-<VERSION>-installer-amd64.iso
            # Example: kali-linux-2025.4-installer-amd64.iso
            match = re.search(
                r"kali-linux-([0-9.]+)-installer-amd64\.iso", response.text
            )
            if match:
                return match.group(1)

            # Fallback: check for 'kali-linux-<VERSION>-installer-netinst-amd64.iso'
            match = re.search(
                r"kali-linux-([0-9.]+)-installer-netinst-amd64\.iso", response.text
            )
            if match:
                return match.group(1)

    except Exception as e:
        print(f"Error fetching Kali version: {e}", file=sys.stderr)
    return None


def update_file(file_path, new_version):
    """Updates the dist_version in the specified file."""
    with open(file_path, "r") as f:
        content = f.read()

    new_content = re.sub(
        r'dist_version="[^"]+"', f'dist_version="{new_version}"', content, count=1
    )

    with open(file_path, "w") as f:
        f.write(new_content)
    print(f"Updated {file_path} to version {new_version}")


def main():
    parser = argparse.ArgumentParser(description="Check and update distro versions.")
    parser.add_argument(
        "--check", action="store_true", help="Check for updates and output JSON."
    )
    parser.add_argument(
        "--update",
        nargs=2,
        metavar=("DISTRO", "VERSION"),
        help="Update a specific distro to a version.",
    )

    args = parser.parse_args()

    if args.update:
        distro_name, new_version = args.update
        file_path = DISTRO_BUILD_DIR / f"{distro_name}.sh"
        if file_path.exists():
            update_file(file_path, new_version)
        else:
            print(f"Error: {file_path} does not exist.", file=sys.stderr)
            sys.exit(1)
        return

    if args.check:
        updates = []
        if not DISTRO_BUILD_DIR.exists():
            print(f"Error: {DISTRO_BUILD_DIR} not found.", file=sys.stderr)
            sys.exit(1)

        # Iterate over all .sh files in distro-build
        for file_path in DISTRO_BUILD_DIR.glob("*.sh"):
            distro_name = file_path.stem
            local_version = get_local_version(file_path)

            if not local_version:
                print(
                    f"Warning: Could not find dist_version in {file_path}",
                    file=sys.stderr,
                )
                continue

            upstream_version = None
            if distro_name == "kali":
                upstream_version = get_kali_version()
            else:
                upstream_version = get_upstream_proot_version(distro_name)

            if upstream_version and upstream_version != local_version:
                updates.append(
                    {
                        "name": distro_name,
                        "current": local_version,
                        "new": upstream_version,
                        "file": str(file_path),
                    }
                )

        print(json.dumps(updates, indent=2))


if __name__ == "__main__":
    main()

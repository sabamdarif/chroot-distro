#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2025-2026 Md Arif
# Every check that must pass before a commit.

set -e

# Define color codes for pretty printing
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}=== Starting Pre-Commit Checks ===${NC}"

# Function to run a check and print status
run_check() {
	local name="$1"
	shift
	echo -e "\n${BLUE}Running ${name}...${NC}"
	if "$@"; then
		echo -e "${GREEN}✓ ${name} passed!${NC}"
	else
		echo -e "${RED}✗ ${name} failed!${NC}"
		exit 1
	fi
}

# Every package file needs the license header and a module docstring; a script needs
# the header, below the shebang or `#compdef` line that has to come first
# (CLAUDE.md, Code conventions, has the form).
check_headers() {
	uv run python - <<'PY'
import ast
import pathlib
import sys

SPDX = "# SPDX-License-Identifier: GPL-3.0-only"

bad = []
for path in sorted(pathlib.Path("src/chroot_distro").rglob("*.py")):
	text = path.read_text()
	if not text.startswith(f"{SPDX}\n"):
		bad.append(f"{path}: no SPDX license header")
	elif not ast.get_docstring(ast.parse(text)):
		bad.append(f"{path}: no module docstring")

scripts = [pathlib.Path("check-before-commit.sh"), pathlib.Path(".githooks/commit-msg")]
scripts += sorted(pathlib.Path("src/chroot_distro/completions").iterdir())
scripts += sorted(pathlib.Path("tests/e2e").rglob("*.sh"))
for path in scripts:
	if SPDX not in path.read_text().splitlines()[:3]:
		bad.append(f"{path}: no SPDX license header")

if bad:
	print("\n".join(bad))
	sys.exit(1)
PY
}

# The em dash ban covers what this commit adds, not the tree: files older than the
# rule still hold em dashes. \x{2014}/\x{2013} keep this script clean of its own
# pattern, and letters either side of `--` keep CLI syntax (`login ubuntu -- cmd`)
# out of it.
check_no_em_dash() {
	local hits
	hits=$(git diff --cached -U0 | grep '^+' | grep -v '^+++' |
		grep -P '[\x{2014}\x{2013}]|[[:alpha:]]--[[:alpha:]]' || true)
	if [ -n "$hits" ]; then
		echo "Em dash in added lines, a comma, a colon or two sentences says it:"
		echo "$hits"
		return 1
	fi
}

# Git never clones hooks, so .githooks/commit-msg is inert until this points at it.
check_git_hooks() {
	if [ "$(git config core.hooksPath || true)" != ".githooks" ]; then
		echo "commit-msg hook not installed, run: git config core.hooksPath .githooks"
		return 1
	fi
}

# Run the checks
run_check "No Em Dash (staged)" check_no_em_dash
run_check "Git Hooks Installed" check_git_hooks
run_check "License Headers" check_headers
run_check "Ruff Check" uv run ruff check src/chroot_distro
run_check "Pyright Type Check" uv run pyright src/chroot_distro
run_check "Mypy Type Check" uv run mypy src/chroot_distro
run_check "Pytest (Unit Tests & Coverage)" uv run pytest tests/ --cov=chroot_distro

echo -e "\n${GREEN}=== All checks passed successfully! Ready to commit. ===${NC}"

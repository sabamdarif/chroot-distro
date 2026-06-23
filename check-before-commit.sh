#!/usr/bin/env bash

# Exit immediately if a command exits with a non-zero status
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

# Run the checks
run_check "Ruff Check" uv run ruff check src/chroot_distro
run_check "Pyright Type Check" uv run pyright src/chroot_distro
run_check "Mypy Type Check" uv run mypy src/chroot_distro
run_check "Pytest (Unit Tests & Coverage)" uv run pytest tests/ --cov=chroot_distro

echo -e "\n${GREEN}=== All checks passed successfully! Ready to commit. ===${NC}"

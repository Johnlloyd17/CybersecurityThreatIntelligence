#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

python_exe="${PYTHON_EXE:-python3}"

exec "$python_exe" -m python.cti_service

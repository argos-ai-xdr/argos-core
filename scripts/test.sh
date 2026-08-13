#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

if command -v pytest >/dev/null 2>&1; then
  pytest
else
  python3 -m pytest
fi

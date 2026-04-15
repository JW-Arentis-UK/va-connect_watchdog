#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_SCRIPT="$SCRIPT_DIR/../../bootstrap_v2_gateway.sh"

if [[ ! -f "$ROOT_SCRIPT" ]]; then
  echo "Root bootstrap script not found at $ROOT_SCRIPT"
  exit 1
fi

exec bash "$ROOT_SCRIPT" "$@"

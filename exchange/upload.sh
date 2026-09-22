#!/usr/bin/env bash
# Copyright 2024 CrowdStrike, Inc. All rights reserved.
#
# Publish the CrowdStrike AIDR policy to Anypoint Exchange.
#
# Prerequisites:
#   - cargo anypoint CLI installed and authenticated
#   - WASM binary built: make build-asset-files && cargo build --release --target wasm32-wasip1
#
# Required environment variables:
#   ANYPOINT_ORG_ID        Anypoint Platform organization ID
#   ANYPOINT_ENV_ID        Anypoint Platform environment ID (optional; defaults to org root)
#
# Optional environment variables:
#   VERSION                Policy version to publish (default: read from Cargo.toml)
#   ANYPOINT_TOKEN         Access token (if not using anypoint CLI login)
#
# Usage:
#   export ANYPOINT_ORG_ID=<your-org-id>
#   export ANYPOINT_ENV_ID=<your-env-id>   # optional
#   ./exchange/upload.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# ---- Validate required env vars ----
if [[ -z "${ANYPOINT_ORG_ID:-}" ]]; then
  echo "ERROR: ANYPOINT_ORG_ID is not set." >&2
  echo "  export ANYPOINT_ORG_ID=<your-anypoint-org-id>" >&2
  exit 1
fi

# ---- Read version from Cargo.toml if not overridden ----
VERSION="${VERSION:-$(grep '^version' "${REPO_ROOT}/Cargo.toml" | head -1 | sed 's/.*= *"\(.*\)"/\1/')}"
if [[ -z "${VERSION}" ]]; then
  echo "ERROR: Could not determine version from Cargo.toml or VERSION env var." >&2
  exit 1
fi

WASM_BINARY="${REPO_ROOT}/target/wasm32-wasip1/release/crowdstrike_aidr.wasm"
if [[ ! -f "${WASM_BINARY}" ]]; then
  echo "ERROR: WASM binary not found at ${WASM_BINARY}" >&2
  echo "  Run: make build-asset-files && cargo build --release --target wasm32-wasip1" >&2
  exit 1
fi

echo "Publishing CrowdStrike AIDR policy v${VERSION} to Anypoint Exchange..."
echo "  Org ID:  ${ANYPOINT_ORG_ID}"
echo "  Version: ${VERSION}"

# ---- Publish via cargo anypoint ----
cd "${REPO_ROOT}"
cargo anypoint publish \
  --organization-id "${ANYPOINT_ORG_ID}" \
  --version "${VERSION}"

echo "Done. Policy v${VERSION} published to Exchange."
echo ""
echo "Next steps:"
echo "  1. Log in to Anypoint Platform and find the policy in Exchange."
echo "  2. Set the lifecycle state to 'Stable' when ready for production."
echo "  3. Apply the policy to API instances via API Manager."

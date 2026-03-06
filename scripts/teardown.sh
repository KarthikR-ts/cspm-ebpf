#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────
# Sentinel-Core — Teardown
# Deletes the Kind cluster cleanly.
# ─────────────────────────────────────────────────────────────────
set -euo pipefail

CLUSTER_NAME="sentinel-core"

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

echo -e "${RED}[TEARDOWN]${NC} Deleting Kind cluster '$CLUSTER_NAME'..."

if kind get clusters 2>/dev/null | grep -q "^${CLUSTER_NAME}$"; then
    kind delete cluster --name "$CLUSTER_NAME"
    echo -e "${GREEN}[OK]${NC} Cluster '$CLUSTER_NAME' deleted."
else
    echo -e "${GREEN}[OK]${NC} Cluster '$CLUSTER_NAME' does not exist. Nothing to delete."
fi

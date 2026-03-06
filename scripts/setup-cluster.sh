#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────
# Sentinel-Core — Cluster Bootstrap Script
# Creates a Kind cluster and installs Tetragon with TracingPolicies.
# ─────────────────────────────────────────────────────────────────
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

CLUSTER_NAME="sentinel-core"
KIND_CONFIG="$PROJECT_ROOT/infra/kind-config.yaml"
POLICIES_DIR="$PROJECT_ROOT/policies"

CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

info()  { echo -e "${CYAN}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
fail()  { echo -e "${RED}[FAIL]${NC}  $*"; exit 1; }

# ── Pre-flight checks ────────────────────────────────────────────
for cmd in docker kind kubectl helm; do
    command -v "$cmd" &>/dev/null || fail "'$cmd' is required but not installed."
done

docker info &>/dev/null || fail "Docker daemon is not running."

# ── Step 1: Create Kind cluster ──────────────────────────────────
if kind get clusters 2>/dev/null | grep -q "^${CLUSTER_NAME}$"; then
    warn "Cluster '$CLUSTER_NAME' already exists. Skipping creation."
else
    info "Creating Kind cluster '$CLUSTER_NAME'..."
    kind create cluster --config "$KIND_CONFIG"
    ok "Kind cluster created."
fi

# Wait for nodes
info "Waiting for all nodes to become Ready..."
kubectl wait --for=condition=Ready nodes --all --timeout=120s
ok "All nodes are Ready."

# ── Step 2: Install Tetragon via Helm ────────────────────────────
"$SCRIPT_DIR/install-tetragon.sh"

# ── Step 3: Apply TracingPolicies ────────────────────────────────
info "Applying TracingPolicies from $POLICIES_DIR..."
for policy in "$POLICIES_DIR"/*.yaml; do
    kubectl apply -f "$policy"
    ok "Applied: $(basename "$policy")"
done

# ── Step 4: Verify ───────────────────────────────────────────────
info "Verifying Tetragon pods..."
kubectl -n kube-system get pods -l app.kubernetes.io/name=tetragon

info "Verifying TracingPolicies..."
kubectl get tracingpolicies 2>/dev/null || kubectl get tp 2>/dev/null || warn "TracingPolicy CRD not yet available."

echo ""
ok "╔══════════════════════════════════════════════════╗"
ok "║  Sentinel-Core cluster is READY! 🚀             ║"
ok "║                                                  ║"
ok "║  Next steps:                                     ║"
ok "║    1. Start port-forward:                        ║"
ok "║       kubectl -n kube-system port-forward        ║"
ok "║         svc/tetragon 54321:54321 &               ║"
ok "║                                                  ║"
ok "║    2. Start the event forwarder:                 ║"
ok "║       python -m forwarder.main                   ║"
ok "║                                                  ║"
ok "║    3. Run the demo:                              ║"
ok "║       make demo                                  ║"
ok "╚══════════════════════════════════════════════════╝"

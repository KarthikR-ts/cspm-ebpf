#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────
# Sentinel-Core — Host-Level Tetragon Launcher
# Runs Tetragon directly on the host kernel (no Kubernetes needed).
# This provides real eBPF monitoring of all processes on the machine.
# ─────────────────────────────────────────────────────────────────
set -euo pipefail

CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

info()  { echo -e "${CYAN}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
fail()  { echo -e "${RED}[FAIL]${NC}  $*"; exit 1; }

# ── Pre-flight ────────────────────────────────────────────────────
[[ $EUID -eq 0 ]] || fail "This script must be run as root (sudo)."
command -v tetragon &>/dev/null || fail "'tetragon' binary not found in PATH."

# ── Directories ───────────────────────────────────────────────────
mkdir -p /var/run/tetragon /var/log/tetragon /etc/tetragon/tetragon.tp.d

# ── Kill any existing Tetragon ────────────────────────────────────
if pgrep -x tetragon &>/dev/null; then
    warn "Tetragon already running. Stopping..."
    pkill -x tetragon || true
    sleep 2
fi

# ── Copy policies ─────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
POLICIES_DIR="$PROJECT_ROOT/policies"

if [ -d "$POLICIES_DIR" ]; then
    info "Copying TracingPolicies from $POLICIES_DIR..."
    cp -v "$POLICIES_DIR"/*.yaml /etc/tetragon/tetragon.tp.d/ 2>/dev/null || true
    ok "Policies installed."
fi

# ── Start Tetragon ────────────────────────────────────────────────
info "Starting Tetragon (host-level eBPF)..."
info "BTF:    /sys/kernel/btf/vmlinux"
info "BPF:    /usr/local/lib/tetragon/bpf/"
info "Socket: /var/run/tetragon/tetragon.sock"
info "gRPC:   localhost:54321"
info "Log:    /var/log/tetragon/tetragon.log"

tetragon \
    --btf /sys/kernel/btf/vmlinux \
    --bpf-lib /usr/local/lib/tetragon/bpf/ \
    --server-address "localhost:54321" \
    --export-filename /var/log/tetragon/tetragon.log \
    --tracing-policy-dir /etc/tetragon/tetragon.tp.d \
    --log-level info \
    &

TETRA_PID=$!
echo "$TETRA_PID" > /var/run/tetragon/tetragon.pid
sleep 3

if kill -0 "$TETRA_PID" 2>/dev/null; then
    ok "Tetragon is running (PID: $TETRA_PID)"
    ok "╔══════════════════════════════════════════════════╗"
    ok "║  Tetragon is LIVE on your Arch Linux host! 🚀   ║"
    ok "║                                                  ║"
    ok "║  gRPC endpoint: localhost:54321                  ║"
    ok "║  Logs:          /var/log/tetragon/tetragon.log   ║"
    ok "║                                                  ║"
    ok "║  Test it:                                        ║"
    ok "║    tetra getevents -o compact                    ║"
    ok "║                                                  ║"
    ok "║  Start the forwarder:                            ║"
    ok "║    python -m forwarder.main                      ║"
    ok "╚══════════════════════════════════════════════════╝"
else
    fail "Tetragon failed to start. Check: journalctl | tail -50"
fi

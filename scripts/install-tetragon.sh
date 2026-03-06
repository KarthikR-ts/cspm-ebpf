#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────
# Sentinel-Core — Tetragon Helm Installation
# Installs Tetragon into the Kind cluster via Helm.
# ─────────────────────────────────────────────────────────────────
set -euo pipefail

CYAN='\033[0;36m'
GREEN='\033[0;32m'
NC='\033[0m'

info()  { echo -e "${CYAN}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[OK]${NC}    $*"; }

NAMESPACE="kube-system"
RELEASE_NAME="tetragon"
CHART_REPO="https://helm.cilium.io"
CHART_NAME="cilium/tetragon"

# ── Add Cilium Helm repo ─────────────────────────────────────────
info "Adding Cilium Helm repository..."
helm repo add cilium "$CHART_REPO" 2>/dev/null || true
helm repo update

# ── Install Tetragon ─────────────────────────────────────────────
if helm status "$RELEASE_NAME" -n "$NAMESPACE" &>/dev/null; then
    info "Tetragon already installed. Upgrading..."
    helm upgrade "$RELEASE_NAME" "$CHART_NAME" \
        --namespace "$NAMESPACE" \
        --set tetragon.grpc.enabled=true \
        --set tetragon.grpc.address="0.0.0.0:54321" \
        --set tetragon.enableProcessCred=true \
        --set tetragon.enableProcessNs=true \
        --wait --timeout 120s
else
    info "Installing Tetragon via Helm..."
    helm install "$RELEASE_NAME" "$CHART_NAME" \
        --namespace "$NAMESPACE" \
        --set tetragon.grpc.enabled=true \
        --set tetragon.grpc.address="0.0.0.0:54321" \
        --set tetragon.enableProcessCred=true \
        --set tetragon.enableProcessNs=true \
        --wait --timeout 120s
fi

# ── Wait for DaemonSet ────────────────────────────────────────────
info "Waiting for Tetragon DaemonSet rollout..."
kubectl -n "$NAMESPACE" rollout status daemonset/tetragon --timeout=120s
ok "Tetragon is running."

# ── Show Tetragon pods ────────────────────────────────────────────
kubectl -n "$NAMESPACE" get pods -l app.kubernetes.io/name=tetragon -o wide

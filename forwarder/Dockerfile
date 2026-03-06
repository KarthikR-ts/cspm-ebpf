# ─── Stage 1: Builder ────────────────────────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /app

# Install tetra CLI
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates && \
    TETRA_VERSION="v1.2.0" && \
    curl -fsSL "https://github.com/cilium/tetragon/releases/download/${TETRA_VERSION}/tetra-linux-amd64.tar.gz" \
    | tar xz -C /usr/local/bin/ && \
    apt-get purge -y curl && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# ─── Stage 2: Runtime ────────────────────────────────────────────
FROM python:3.12-slim

WORKDIR /app

# Copy tetra CLI from builder
COPY --from=builder /usr/local/bin/tetra /usr/local/bin/tetra

# Copy Python deps from builder
COPY --from=builder /install /usr/local

# Copy application code
COPY . .

# Health check
HEALTHCHECK --interval=10s --timeout=3s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8081/health')" || exit 1

EXPOSE 8081

ENTRYPOINT ["python", "-m", "forwarder.main"]

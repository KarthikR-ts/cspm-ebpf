# 🛡️ Sentinel-Core — Muscle Module

> **eBPF-powered kernel security event pipeline for Kubernetes**
> 
> Part of the Sentinel-Core closed-loop security platform. This module is "The Muscle" — it detects, captures, and streams kernel-level security events from Kubernetes pods using Tetragon eBPF.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                      Kind Kubernetes Cluster                    │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │
│  │ control-plane │  │   worker-1   │  │   worker-2   │          │
│  │               │  │              │  │              │          │
│  │  ┌─────────┐  │  │  ┌────────┐  │  │  ┌────────┐  │          │
│  │  │Tetragon │  │  │  │Tetragon│  │  │  │Tetragon│  │          │
│  │  │DaemonSet│  │  │  │  Pod   │  │  │  │  Pod   │  │          │
│  │  └────┬────┘  │  │  └───┬────┘  │  │  └───┬────┘  │          │
│  └───────┼───────┘  └──────┼───────┘  └──────┼───────┘          │
│          │                 │                 │                   │
│          └─────── gRPC (port 54321) ─────────┘                  │
│                          │                                      │
└──────────────────────────┼──────────────────────────────────────┘
                           │
              ┌────────────▼────────────┐
              │   Event Forwarder       │
              │   (Python)              │
              │                         │
              │  tetra CLI → Transform  │
              │  → Sentinel JSON Schema │
              │  → Redis / stdout       │
              │                         │
              │  FastAPI :8081          │
              │  /health /metrics       │
              │  /events/latest         │
              └────────────┬────────────┘
                           │
              ┌────────────▼────────────┐
              │   Redis Stream          │
              │   sentinel:events       │
              └────────────┬────────────┘
                           │
              ┌────────────▼────────────┐
              │   Downstream Consumers  │
              │   (AI Triage, RAG)      │
              └─────────────────────────┘
```

## Folder Structure

```
sentinel-core/
├── Makefile                    # One-command orchestration
├── README.md                   # This file
├── infra/
│   └── kind-config.yaml        # Kind cluster configuration
├── policies/
│   ├── trace-execve.yaml       # Monitor process execution
│   ├── trace-connect.yaml      # Monitor network connections
│   └── sentinel-full.yaml      # Combined policy for demo
├── forwarder/
│   ├── __init__.py
│   ├── main.py                 # Entry point (tetra CLI / file / stdin)
│   ├── transformer.py          # Raw Tetragon → Sentinel JSON Schema
│   ├── publisher.py            # Redis Streams publisher
│   ├── api.py                  # FastAPI health/metrics server
│   ├── config.py               # Environment-based configuration
│   ├── requirements.txt        # Python dependencies
│   ├── Dockerfile              # Container build
│   └── tests/
│       ├── __init__.py
│       └── test_transformer.py # Unit tests
├── demo/
│   └── attacker-pod.yaml       # Attack simulation manifest
├── scripts/
│   ├── setup-cluster.sh        # Create cluster + install Tetragon
│   ├── install-tetragon.sh     # Standalone Tetragon install
│   ├── teardown.sh             # Delete cluster
│   └── run-demo.sh             # Run attack demo
└── fixtures/
    ├── sample-event.json       # Reference Sentinel event (for teammates)
    └── sample-tetragon-raw.jsonl  # Raw Tetragon events (for testing)
```

## Quickstart

### Prerequisites

| Tool       | Min Version | Install                                       |
|------------|-------------|-----------------------------------------------|
| Docker     | 24.x       | https://docs.docker.com/get-docker/           |
| kind       | 0.22+      | `go install sigs.k8s.io/kind@latest`          |
| kubectl    | 1.28+      | https://kubernetes.io/docs/tasks/tools/       |
| Helm       | 3.14+      | https://helm.sh/docs/intro/install/           |
| Python     | 3.11+      | System package manager                         |

### 1. Install Python deps

```bash
make install
source .venv/bin/activate
```

### 2. Spin up the cluster (requires Docker)

```bash
make up
```

This will:
- Create a 3-node Kind cluster
- Install Tetragon via Helm
- Apply all TracingPolicies
- Print next steps

### 3. Start the Event Forwarder

```bash
# Live mode (after port-forward):
make port-forward
make forwarder

# OR offline/demo mode (no cluster needed):
make forwarder-offline
```

### 4. Run the demo

```bash
make demo
```

### 5. View events

```bash
# Via API:
curl http://localhost:8081/events/latest

# Via Redis:
redis-cli XRANGE sentinel:events - + COUNT 10
```

### 6. Tear down

```bash
make down
```

## Unified JSON Event Schema

Every event produced by this module follows the team's unified schema:

```json
{
  "event_id": "uuid",
  "timestamp": "ISO8601",
  "source": "tetragon",
  "event_type": "process_exec | process_kprobe | process_exit",
  "node_name": "kind-worker",
  "telemetry": {
    "pid": 4821,
    "binary": "/usr/bin/curl",
    "args": ["-k", "http://evil.com"],
    "uid": 33,
    "user": "www-data",
    "namespace": "default",
    "pod": "attacker-pod",
    "container_id": "abc123",
    "parent_binary": "/bin/bash",
    "parent_pid": 4800,
    "kprobe": { "...if applicable..." }
  },
  "triage": null,
  "explanation": null,
  "remediation": null
}
```

> **Note for teammates**: The `triage`, `explanation`, and `remediation` fields are `null` when produced by this module. The AI Triage and RAG Agent services will fill these fields downstream.

## Environment Variables

| Variable              | Default            | Description                        |
|-----------------------|--------------------|------------------------------------|
| `TETRAGON_GRPC_ADDRESS` | `localhost:54321`  | Tetragon gRPC endpoint            |
| `TETRA_BIN`           | `tetra`            | Path to tetra CLI binary           |
| `REDIS_HOST`          | `localhost`        | Redis host                         |
| `REDIS_PORT`          | `6379`             | Redis port                         |
| `REDIS_STREAM_KEY`    | `sentinel:events`  | Redis stream name                  |
| `EVENT_BUFFER_SIZE`   | `100`              | In-memory event ring buffer size   |
| `API_PORT`            | `8081`             | FastAPI metrics server port        |
| `LOG_LEVEL`           | `INFO`             | Logging level                      |

## Running Tests

```bash
make test
```

## License

Internal hackathon project — Sentinel-Core 2026.

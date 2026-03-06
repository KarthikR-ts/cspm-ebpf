"""
Sentinel-Core Event Forwarder — FastAPI Health & Metrics API

Provides liveness probes, metrics, and a recent-events endpoint.
"""

import time
from collections import deque
from threading import Lock
from typing import Any

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

app = FastAPI(
    title="Sentinel-Core Event Forwarder",
    description="Health, metrics, and live event stream for the Sentinel eBPF pipeline",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Shared State ──────────────────────────────────────────────────
_lock = Lock()
_metrics: dict[str, Any] = {
    "events_total": 0,
    "events_by_type": {},
    "errors_total": 0,
    "last_event_timestamp": None,
    "start_time": time.time(),
    "redis_connected": False,
}
_recent_events: deque[dict] = deque(maxlen=100)
_ml_triage: Any = None


def set_ml_triage(triage_instance: Any) -> None:
    """Register the ML triage instance with the API."""
    global _ml_triage
    _ml_triage = triage_instance


def record_event(event: dict) -> None:
    """Record a processed event for metrics and recent-events buffer."""
    with _lock:
        _metrics["events_total"] += 1
        _metrics["last_event_timestamp"] = event.get("timestamp")
        etype = event.get("event_type", "unknown")
        _metrics["events_by_type"][etype] = _metrics["events_by_type"].get(etype, 0) + 1
        _recent_events.appendleft(event)


def record_error() -> None:
    """Increment the error counter."""
    with _lock:
        _metrics["errors_total"] += 1


def set_redis_status(connected: bool) -> None:
    """Update Redis connection status in metrics."""
    with _lock:
        _metrics["redis_connected"] = connected


# ── Endpoints ─────────────────────────────────────────────────────


@app.get("/health")
async def health():
    """Liveness probe."""
    return {"status": "ok", "service": "sentinel-event-forwarder"}


@app.get("/metrics")
async def metrics():
    """Return event processing metrics."""
    with _lock:
        uptime = time.time() - _metrics["start_time"]
        return JSONResponse(
            content={
                **_metrics,
                "uptime_seconds": round(uptime, 1),
                "events_per_second": round(
                    _metrics["events_total"] / max(uptime, 1), 2
                ),
            }
        )


@app.get("/events/latest")
async def latest_events(limit: int = 20):
    """Return the most recent processed events."""
    with _lock:
        events = list(_recent_events)[:limit]
    return {"count": len(events), "events": events}


@app.get("/events/stream")
async def event_stream_info():
    """Info about how to consume events."""
    return {
        "redis_stream": "sentinel:events",
        "consume_command": "redis-cli XREAD BLOCK 0 STREAMS sentinel:events $",
        "api_latest": "/events/latest?limit=50",
    }


@app.post("/triage")
async def triage_event(event: dict):
    """
    Accept an event and return a Unified Event Schema response.
    
    Deliverable: "This event is a 98% True Positive."
    """
    if _ml_triage is None:
        return JSONResponse(
            status_code=503,
            content={"error": "ML Triage service is not initialized."}
        )
    
    # Run triage
    results = _ml_triage.triage_event(event)

    # Return full unified schema
    return {
        "event_id": event.get("event_id", "manual-triage"),
        "telemetry": event.get("telemetry", event),
        "triage": results.get("triage"),
        "explanation": results.get("explanation"),
        "remediation": None, # Future Advisor task
        "deliverable": results.get("deliverable")
    }

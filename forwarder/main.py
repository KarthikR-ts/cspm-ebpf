"""
Sentinel-Core Event Forwarder — Main Entry Point

Spawns the `tetra getevents -o json` subprocess (or reads from a JSON file
for offline/demo mode), transforms each event, and publishes to Redis.

Also starts a background FastAPI server for health/metrics.

Usage:
    # Live mode (requires tetra CLI + port-forward to Tetragon):
    python -m forwarder.main

    # Offline/demo mode (reads from a JSON-lines file):
    python -m forwarder.main --file fixtures/sample-tetragon-raw.jsonl

    # Stdin mode (pipe events in):
    cat events.jsonl | python -m forwarder.main --stdin
"""

import argparse
import json
import logging
import signal
import subprocess
import sys
import threading
from pathlib import Path

import uvicorn

from .api import app as fastapi_app
from .api import record_error, record_event, set_ml_triage, set_redis_status
from .config import Config
from .publisher import EventPublisher
from .transformer import transform_event
from .ml_triage import MLTriage

# ── Logging Setup ─────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s │ %(name)-22s │ %(levelname)-5s │ %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("sentinel.forwarder")

# ── Globals ───────────────────────────────────────────────────────
_shutdown = threading.Event()
_ml_triage = None


def start_api_server(config: Config) -> None:
    """Run the FastAPI metrics server in a background thread."""
    uvicorn.run(
        fastapi_app,
        host=config.API_HOST,
        port=config.API_PORT,
        log_level="warning",
    )


def process_line(line: str, publisher: EventPublisher) -> None:
    """Parse a single JSON line, transform, and publish."""
    line = line.strip()
    if not line:
        return

    try:
        raw_event = json.loads(line)
    except json.JSONDecodeError as e:
        logger.warning("Skipping malformed JSON: %s", e)
        record_error()
        return

    sentinel_event = transform_event(raw_event)
    if sentinel_event is None:
        return  # Not a relevant event type

    # Run ML Triage if enabled
    if _ml_triage:
        triage_results = _ml_triage.triage_event(sentinel_event)
        sentinel_event["triage"] = triage_results["triage"]
        sentinel_event["explanation"] = triage_results["explanation"]

    # Publish to Redis (or stdout fallback)
    publisher.publish(sentinel_event)

    # Record for API metrics
    record_event(sentinel_event)

    logger.info(
        "📡 [%s] grade=%s confidence=%s pid=%d binary=%s pod=%s",
        sentinel_event["event_type"],
        sentinel_event.get("triage", {}).get("grade", "n/a") if sentinel_event.get("triage") else "n/a",
        sentinel_event.get("triage", {}).get("confidence", "n/a") if sentinel_event.get("triage") else "n/a",
        sentinel_event["telemetry"]["pid"],
        sentinel_event["telemetry"]["binary"],
        sentinel_event["telemetry"].get("pod", "n/a"),
    )


def stream_from_tetra(config: Config, publisher: EventPublisher) -> None:
    """Stream events from the tetra CLI subprocess."""
    cmd = [
        config.TETRA_BIN,
        "getevents",
        "-o", "json",
        "--server-address", config.TETRAGON_GRPC_ADDRESS,
    ]
    logger.info("🚀 Starting tetra stream: %s", " ".join(cmd))

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,  # Line-buffered
        )
    except FileNotFoundError:
        logger.error(
            "❌ '%s' not found. Install tetra CLI or set TETRA_BIN env var.",
            config.TETRA_BIN,
        )
        sys.exit(1)

    try:
        assert proc.stdout is not None
        for line in proc.stdout:
            if _shutdown.is_set():
                break
            process_line(line, publisher)
    except KeyboardInterrupt:
        pass
    finally:
        proc.terminate()
        proc.wait(timeout=5)
        logger.info("🛑 Tetra process terminated.")


def stream_from_file(filepath: str, publisher: EventPublisher) -> None:
    """Read events from a JSON-lines file (offline/demo mode)."""
    path = Path(filepath)
    if not path.exists():
        logger.error("❌ File not found: %s", filepath)
        sys.exit(1)

    logger.info("📂 Reading events from file: %s", filepath)
    with open(path, "r") as f:
        for line in f:
            if _shutdown.is_set():
                break
            process_line(line, publisher)
    logger.info("✅ Finished reading %s", filepath)


def stream_from_stdin(publisher: EventPublisher) -> None:
    """Read events from stdin (pipe mode)."""
    logger.info("📥 Reading events from stdin...")
    try:
        for line in sys.stdin:
            if _shutdown.is_set():
                break
            process_line(line, publisher)
    except KeyboardInterrupt:
        pass
    logger.info("✅ Stdin stream ended.")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Sentinel-Core Event Forwarder — eBPF → Redis Pipeline"
    )
    parser.add_argument(
        "--file", "-f",
        help="Path to a JSON-lines file for offline/demo mode",
    )
    parser.add_argument(
        "--stdin",
        action="store_true",
        help="Read events from stdin instead of tetra CLI",
    )
    args = parser.parse_args()

    config = Config()
    logging.getLogger().setLevel(config.LOG_LEVEL)

    # ── Signal Handling ───────────────────────────────────────────
    def _handle_signal(signum, frame):
        logger.info("Received signal %d, shutting down...", signum)
        _shutdown.set()

    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    # ── Publisher ─────────────────────────────────────────────────
    publisher = EventPublisher(config)
    set_redis_status(publisher.is_connected)

    # ── ML Triage ─────────────────────────────────────────────────
    _ml_triage = MLTriage(
        model_path=Path(config.ML_MODEL_PATH),
        feature_list_path=Path(config.FEATURE_LIST_PATH)
    )
    set_ml_triage(_ml_triage)

    # ── API Server (background thread) ────────────────────────────
    api_thread = threading.Thread(
        target=start_api_server,
        args=(config,),
        daemon=True,
    )
    api_thread.start()
    logger.info("🌐 API server started on http://%s:%d", config.API_HOST, config.API_PORT)

    # ── Event Stream ──────────────────────────────────────────────
    try:
        if args.file:
            stream_from_file(args.file, publisher)
        elif args.stdin:
            stream_from_stdin(publisher)
        else:
            stream_from_tetra(config, publisher)
    finally:
        publisher.close()
        logger.info("👋 Sentinel Event Forwarder stopped.")


if __name__ == "__main__":
    main()

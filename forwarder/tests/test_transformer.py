"""
Sentinel-Core — Transformer Unit Tests

Validates that raw Tetragon events are correctly transformed
into the unified Sentinel JSON Schema.
"""

import json
from pathlib import Path

import pytest

from forwarder.transformer import transform_event

FIXTURES_DIR = Path(__file__).parent.parent.parent / "fixtures"


# ─── Fixtures ─────────────────────────────────────────────────────


def load_raw_events() -> list[dict]:
    """Load raw Tetragon events from the JSONL fixture file."""
    filepath = FIXTURES_DIR / "sample-tetragon-raw.jsonl"
    events = []
    with open(filepath, "r") as f:
        for line in f:
            line = line.strip()
            if line:
                events.append(json.loads(line))
    return events


RAW_EVENTS = load_raw_events()


# ─── Schema Validation Helpers ────────────────────────────────────


REQUIRED_TOP_LEVEL_KEYS = {
    "event_id",
    "timestamp",
    "source",
    "event_type",
    "node_name",
    "telemetry",
    "triage",
    "explanation",
    "remediation",
}

REQUIRED_TELEMETRY_KEYS = {
    "pid",
    "binary",
    "args",
    "uid",
    "user",
    "namespace",
    "pod",
    "parent_binary",
    "parent_pid",
}


def assert_sentinel_schema(event: dict) -> None:
    """Assert that an event matches the Sentinel schema structure."""
    for key in REQUIRED_TOP_LEVEL_KEYS:
        assert key in event, f"Missing top-level key: {key}"

    assert event["source"] == "tetragon"
    assert isinstance(event["event_id"], str)
    assert len(event["event_id"]) == 36  # UUID format

    # Downstream fields should be None (not yet triaged)
    assert event["triage"] is None
    assert event["explanation"] is None
    assert event["remediation"] is None

    telemetry = event["telemetry"]
    for key in REQUIRED_TELEMETRY_KEYS:
        assert key in telemetry, f"Missing telemetry key: {key}"

    assert isinstance(telemetry["pid"], int)
    assert isinstance(telemetry["args"], list)
    assert isinstance(telemetry["binary"], str)


# ─── Tests ────────────────────────────────────────────────────────


class TestTransformProcessExec:
    """Tests for process_exec event transformation."""

    def test_curl_exec_event(self):
        """Test transforming a curl process_exec event."""
        raw = RAW_EVENTS[0]  # curl event
        result = transform_event(raw)

        assert result is not None
        assert_sentinel_schema(result)
        assert result["event_type"] == "process_exec"
        assert result["node_name"] == "kind-worker"
        assert result["telemetry"]["binary"] == "/usr/bin/curl"
        assert result["telemetry"]["pid"] == 4821
        assert result["telemetry"]["uid"] == 33
        assert result["telemetry"]["user"] == "www-data"
        assert result["telemetry"]["pod"] == "attacker-pod"
        assert result["telemetry"]["namespace"] == "default"

    def test_nc_exec_event(self):
        """Test transforming a netcat (reverse shell) event."""
        raw = RAW_EVENTS[1]  # nc event
        result = transform_event(raw)

        assert result is not None
        assert_sentinel_schema(result)
        assert result["event_type"] == "process_exec"
        assert result["telemetry"]["binary"] == "/bin/nc"
        assert result["telemetry"]["uid"] == 0
        assert result["telemetry"]["user"] == "root"
        # Args should contain the reverse shell target
        assert "-e" in result["telemetry"]["args"]

    def test_parent_process_info(self):
        """Test that parent process info is correctly extracted."""
        raw = RAW_EVENTS[0]
        result = transform_event(raw)

        assert result is not None
        assert result["telemetry"]["parent_binary"] == "/bin/bash"
        assert result["telemetry"]["parent_pid"] == 4800


class TestTransformProcessKprobe:
    """Tests for process_kprobe event transformation."""

    def test_connect_kprobe_event(self):
        """Test transforming a connect syscall kprobe event."""
        raw = RAW_EVENTS[2]  # process_kprobe connect event
        result = transform_event(raw)

        assert result is not None
        assert_sentinel_schema(result)
        assert result["event_type"] == "process_kprobe"
        assert "kprobe" in result["telemetry"]
        assert result["telemetry"]["kprobe"]["function"] == "__x64_sys_connect"
        assert result["telemetry"]["kprobe"]["policy"] == "sentinel-full"

    def test_kprobe_args_extracted(self):
        """Test that kprobe arguments are correctly extracted."""
        raw = RAW_EVENTS[2]
        result = transform_event(raw)

        assert result is not None
        kprobe_args = result["telemetry"]["kprobe"]["args"]
        assert len(kprobe_args) > 0
        # Should contain the socket fd and sock_arg
        arg_types = set()
        for arg in kprobe_args:
            arg_types.update(arg.keys())
        assert "int_arg" in arg_types or "sock_arg" in arg_types


class TestTransformProcessExit:
    """Tests for process_exit event transformation."""

    def test_exit_event(self):
        """Test transforming a process_exit event."""
        raw = RAW_EVENTS[3]  # process_exit
        result = transform_event(raw)

        assert result is not None
        assert_sentinel_schema(result)
        assert result["event_type"] == "process_exit"
        assert result["telemetry"]["binary"] == "/usr/bin/curl"


class TestTransformEdgeCases:
    """Tests for edge cases and unknown event types."""

    def test_unknown_event_type_returns_none(self):
        """Unknown event types should be skipped (return None)."""
        raw = {"unknown_type": {"some": "data"}, "time": "2026-01-01T00:00:00Z"}
        result = transform_event(raw)
        assert result is None

    def test_empty_dict_returns_none(self):
        """An empty dict should return None."""
        result = transform_event({})
        assert result is None

    def test_minimal_process_exec(self):
        """A minimal process_exec with missing fields should still work."""
        raw = {
            "process_exec": {
                "process": {
                    "pid": 1,
                    "binary": "/bin/test",
                }
            },
            "time": "2026-01-01T00:00:00Z",
            "node_name": "test-node",
        }
        result = transform_event(raw)
        assert result is not None
        assert_sentinel_schema(result)
        assert result["telemetry"]["pid"] == 1
        assert result["telemetry"]["binary"] == "/bin/test"
        assert result["telemetry"]["pod"] == ""  # No pod info

    def test_event_id_is_unique(self):
        """Each transformation should produce a unique event_id."""
        raw = RAW_EVENTS[0]
        result1 = transform_event(raw)
        result2 = transform_event(raw)
        assert result1 is not None and result2 is not None
        assert result1["event_id"] != result2["event_id"]

    def test_uid_mapping(self):
        """Test UID to username mapping."""
        raw = {
            "process_exec": {
                "process": {
                    "pid": 1,
                    "uid": 65534,
                    "binary": "/bin/test",
                }
            },
            "time": "2026-01-01T00:00:00Z",
        }
        result = transform_event(raw)
        assert result is not None
        assert result["telemetry"]["user"] == "nobody"

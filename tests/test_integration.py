"""
Sentinel-Core Integration Tests

Uses pytest + httpx to test the FastAPI /analyze endpoint
against mock TP and FP events.

Run with:
    pytest tests/test_integration.py -v
"""

import pytest
from httpx import AsyncClient, ASGITransport
from unittest.mock import patch, MagicMock

# We import the FastAPI app for ASGI testing
from main import app


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def tp_payload() -> dict:
    """Mock True-Positive security event payload."""
    return {
        "raw_event": {
            "process_name": "runc",
            "syscall": "execve",
            "file_path": "/bin/sh",
            "pod_name": "vulnerable-app-7d8f9c",
            "namespace": "production",
            "user": "root",
            "pid": 1234
        },
        "guide_score": 0.92,
        "guide_grade": "TP"
    }


@pytest.fixture
def fp_payload() -> dict:
    """Mock False-Positive security event payload."""
    return {
        "raw_event": {
            "process_name": "nginx",
            "syscall": "read",
            "file_path": "/etc/nginx/nginx.conf",
            "pod_name": "webserver-abc123",
            "namespace": "default",
            "user": "www-data",
            "pid": 5678
        },
        "guide_score": 0.15,
        "guide_grade": "FP"
    }


def _fake_analyze_alert_tp(**kwargs):
    """Fake orchestrator response simulating a True-Positive analysis."""
    return {
        "raw_event": kwargs.get("raw_event", {}),
        "guide_score": kwargs.get("guide_score", 0.92),
        "guide_grade": kwargs.get("guide_grade", "TP"),
        "mitre_context": "T1059.004 - Command and Scripting Interpreter: Unix Shell",
        "azure_context": "NS-1 Network Security",
        "final_report": (
            "INCIDENT REPORT: Suspicious execve syscall detected from runc. "
            "This maps to MITRE ATT&CK technique T1059.004 (Command and Scripting "
            "Interpreter: Unix Shell) and T1611 (Escape to Host). "
            "Immediate remediation recommended."
        ),
        "yaml_fix": "apiVersion: v1\nkind: Pod\nmetadata:\n  name: fix",
        "error": ""
    }


def _fake_analyze_alert_fp(**kwargs):
    """Fake orchestrator response simulating a False-Positive suppression."""
    return {
        "raw_event": kwargs.get("raw_event", {}),
        "guide_score": kwargs.get("guide_score", 0.15),
        "guide_grade": kwargs.get("guide_grade", "FP"),
        "mitre_context": "",
        "azure_context": "",
        "final_report": "Auto-suppressed: False Positive. No action needed.",
        "yaml_fix": "",
        "error": ""
    }


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_analyze_tp_event(tp_payload):
    """POST a mock TP event → assert final_report, yaml_fix, mitre_techniques."""
    with patch("main.analyze_alert", side_effect=_fake_analyze_alert_tp):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://testserver") as client:
            resp = await client.post("/analyze", json=tp_payload)

    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"
    data = resp.json()

    # Must contain the key deliverables
    assert "final_report" in data
    assert len(data["final_report"]) > 0

    assert "yaml_fix" in data
    assert len(data["yaml_fix"]) > 0

    assert "mitre_techniques" in data
    assert len(data["mitre_techniques"]) >= 1, (
        f"Expected at least 1 MITRE technique, got {data['mitre_techniques']}"
    )
    # Verify techniques match T#### or T####.### format
    for t in data["mitre_techniques"]:
        assert t.startswith("T"), f"Invalid MITRE ID format: {t}"


@pytest.mark.asyncio
async def test_analyze_fp_event(fp_payload):
    """POST a mock FP event → assert final_report contains 'False Positive'."""
    with patch("main.analyze_alert", side_effect=_fake_analyze_alert_fp):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://testserver") as client:
            resp = await client.post("/analyze", json=fp_payload)

    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"
    data = resp.json()

    assert "False Positive" in data["final_report"], (
        f"Expected 'False Positive' in report, got: {data['final_report']}"
    )


@pytest.mark.asyncio
async def test_analyze_invalid_grade():
    """POST with an invalid guide_grade → expect 400 validation error."""
    bad_payload = {
        "raw_event": {
            "process_name": "test",
            "syscall": "open",
            "file_path": "/tmp/x",
            "pod_name": "pod",
            "namespace": "default",
            "user": "root",
            "pid": 1
        },
        "guide_score": 0.5,
        "guide_grade": "INVALID"
    }
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        resp = await client.post("/analyze", json=bad_payload)

    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_health_endpoint():
    """GET /health → must return 200 with status 'ok'."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        resp = await client.get("/health")

    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"

#!/usr/bin/env python3
"""
Test suite for Sentinel-Core FastAPI application.

Run with:
    pytest tests/test_api.py -v
    
Run with coverage:
    pytest tests/test_api.py --cov=main --cov-report=html
"""

import pytest
from fastapi.testclient import TestClient
from unittest.mock import Mock, patch, MagicMock
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@pytest.fixture
def client():
    """Create test client for the API."""
    from main import app
    return TestClient(app)


@pytest.fixture
def mock_orchestrator():
    """Create mock orchestrator for testing."""
    mock = Mock()
    mock.process_alert_sync.return_value = {
        "guide_grade": "TP",
        "guide_score": 0.92,
        "final_report": "This is a test security incident report.",
        "yaml_fix": "apiVersion: v1\nkind: Pod\nmetadata:\n  name: test-pod"
    }
    return mock


class TestHealthEndpoint:
    """Test GET /health endpoint."""
    
    def test_health_check_returns_ok(self, client):
        """Test that health endpoint returns ok status."""
        response = client.get("/health")
        
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert data["version"] == "1.0.0"
    
    def test_health_check_response_format(self, client):
        """Test health endpoint response format."""
        response = client.get("/health")
        data = response.json()
        
        assert "status" in data
        assert "version" in data
        assert isinstance(data["status"], str)
        assert isinstance(data["version"], str)


class TestRootEndpoint:
    """Test GET / endpoint."""
    
    def test_root_returns_welcome_message(self, client):
        """Test root endpoint returns welcome message."""
        response = client.get("/")
        
        assert response.status_code == 200
        data = response.json()
        assert "message" in data
        assert "Sentinel-Core" in data["message"]
        assert "version" in data
        assert "docs" in data
        assert "health" in data


class TestStatusEndpoint:
    """Test GET /status endpoint."""
    
    def test_status_returns_system_info(self, client):
        """Test status endpoint returns system information."""
        response = client.get("/status")
        
        assert response.status_code == 200
        data = response.json()
        
        assert "orchestrator" in data
        assert "rag_system" in data
        assert "ingestor" in data
        assert "version" in data
        assert "healthy" in data


class TestAnalyzeEndpoint:
    """Test POST /analyze endpoint."""
    
    @patch('main.SentinelOrchestrator')
    def test_analyze_tp_alert(self, mock_orchestrator_class, client, mock_orchestrator):
        """Test analysis of true positive alert."""
        # Setup mock
        mock_orchestrator_class.return_value = mock_orchestrator
        
        payload = {
            "raw_event": {
                "process_name": "runc",
                "syscall": "execve",
                "file_path": "/bin/sh",
                "pod_name": "vulnerable-app-7d8f9c",
                "namespace": "production",
                "user": "root",
                "pid": 12345
            },
            "guide_score": 0.92,
            "guide_grade": "TP"
        }
        
        response = client.post("/analyze", json=payload)
        
        assert response.status_code == 200
        data = response.json()
        
        assert "status" in data
        assert data["status"] == "TP"
        assert "confidence" in data
        assert data["confidence"] == 0.92
        assert "final_report" in data
        assert "yaml_fix" in data
        assert "processing_time_ms" in data
        assert isinstance(data["mitre_techniques"], list)
    
    @patch('main.SentinelOrchestrator')
    def test_analyze_fp_alert(self, mock_orchestrator_class, client, mock_orchestrator):
        """Test analysis of false positive alert."""
        mock_orchestrator_class.return_value = mock_orchestrator
        mock_orchestrator.process_alert_sync.return_value = {
            "guide_grade": "FP",
            "guide_score": 0.15,
            "final_report": "Auto-suppressed: False Positive. No action needed.",
            "yaml_fix": ""
        }
        
        payload = {
            "raw_event": {
                "process_name": "kubectl",
                "syscall": "connect",
                "file_path": "/etc/kubernetes/admin.conf",
                "pod_name": "admin-tools",
                "namespace": "kube-system",
                "user": "admin",
                "pid": 67890
            },
            "guide_score": 0.15,
            "guide_grade": "FP"
        }
        
        response = client.post("/analyze", json=payload)
        
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "FP"
        assert "Auto-suppressed" in data["final_report"]
    
    def test_analyze_invalid_guide_grade(self, client):
        """Test validation rejects invalid guide_grade."""
        payload = {
            "raw_event": {
                "process_name": "test",
                "syscall": "read",
                "file_path": "/tmp",
                "pod_name": "test-pod",
                "namespace": "default",
                "user": "user",
                "pid": 1
            },
            "guide_score": 0.5,
            "guide_grade": "INVALID"  # Should be TP/BP/FP
        }
        
        response = client.post("/analyze", json=payload)
        
        # Pydantic validation error (422)
        assert response.status_code == 422
        data = response.json()
        assert "detail" in data
    
    def test_analyze_invalid_score_range(self, client):
        """Test validation rejects score outside 0.0-1.0 range."""
        payload = {
            "raw_event": {
                "process_name": "test",
                "syscall": "read",
                "file_path": "/tmp",
                "pod_name": "test-pod",
                "namespace": "default",
                "user": "user",
                "pid": 1
            },
            "guide_score": 1.5,  # Invalid: > 1.0
            "guide_grade": "TP"
        }
        
        response = client.post("/analyze", json=payload)
        
        assert response.status_code == 422
        data = response.json()
        assert "detail" in data
    
    def test_analyze_missing_required_fields(self, client):
        """Test validation rejects missing required fields."""
        payload = {
            "raw_event": {
                "process_name": "test",
                # Missing other required fields
            },
            "guide_score": 0.5,
            "guide_grade": "TP"
        }
        
        response = client.post("/analyze", json=payload)
        
        assert response.status_code == 422
    
    @patch('main.SentinelOrchestrator')
    def test_analyze_response_time_header(self, mock_orchestrator_class, client, mock_orchestrator):
        """Test that response includes processing time header."""
        mock_orchestrator_class.return_value = mock_orchestrator
        
        payload = {
            "raw_event": {
                "process_name": "test",
                "syscall": "execve",
                "file_path": "/bin/sh",
                "pod_name": "test-pod",
                "namespace": "default",
                "user": "user",
                "pid": 123
            },
            "guide_score": 0.9,
            "guide_grade": "TP"
        }
        
        response = client.post("/analyze", json=payload)
        
        assert response.status_code == 200
        assert "X-Process-Time-Ms" in response.headers
    
    @patch('main.SentinelOrchestrator')
    def test_analyze_mitre_extraction(self, mock_orchestrator_class, client, mock_orchestrator):
        """Test MITRE technique IDs are extracted from report."""
        mock_orchestrator_class.return_value = mock_orchestrator
        mock_orchestrator.process_alert_sync.return_value = {
            "guide_grade": "TP",
            "guide_score": 0.92,
            "final_report": "This alert matches MITRE techniques T1059 and T1068.",
            "yaml_fix": "apiVersion: v1"
        }
        
        payload = {
            "raw_event": {
                "process_name": "test",
                "syscall": "execve",
                "file_path": "/bin/sh",
                "pod_name": "test-pod",
                "namespace": "default",
                "user": "user",
                "pid": 123
            },
            "guide_score": 0.92,
            "guide_grade": "TP"
        }
        
        response = client.post("/analyze", json=payload)
        
        assert response.status_code == 200
        data = response.json()
        assert "mitre_techniques" in data
        assert isinstance(data["mitre_techniques"], list)
        # Should extract T1059 and T1068
        assert len(data["mitre_techniques"]) > 0


class TestIngestTriggerEndpoint:
    """Test POST /ingest/trigger endpoint."""
    
    @patch('main.SentinelIngestor')
    def test_ingest_trigger_starts_background_task(self, mock_ingestor_class, client):
        """Test ingestion trigger starts background task."""
        mock_ingestor = Mock()
        mock_ingestor_class.return_value = mock_ingestor
        
        response = client.post("/ingest/trigger")
        
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ingestion_started"
    
    def test_ingest_trigger_unavailable(self, client):
        """Test ingestion trigger when ingestor unavailable."""
        # Temporarily make ingestor unavailable
        with patch('main.INGESTOR_AVAILABLE', False):
            response = client.post("/ingest/trigger")
            
            assert response.status_code == 503
            data = response.json()
            assert "detail" in data
            assert "unavailable" in data["detail"].lower()


class TestMiddlewareAndLogging:
    """Test middleware functionality."""
    
    def test_request_logging_middleware(self, client, caplog):
        """Test that requests are logged with timing."""
        with caplog.at_level("INFO"):
            response = client.get("/health")
            
            assert response.status_code == 200
            
            # Check log contains method, path, status, and time
            log_record = caplog.records[0]
            assert "GET" in log_record.message
            assert "/health" in log_record.message
            assert "Status: 200" in log_record.message
            assert "Time:" in log_record.message
    
    def test_process_time_header(self, client):
        """Test that X-Process-Time-Ms header is added."""
        response = client.get("/health")
        
        assert response.status_code == 200
        assert "X-Process-Time-Ms" in response.headers


class TestCORSConfiguration:
    """Test CORS middleware."""
    
    def test_cors_headers_present(self, client):
        """Test CORS headers are included in responses."""
        response = client.get("/health", headers={"Origin": "http://localhost:3000"})
        
        assert response.status_code == 200
        assert "access-control-allow-origin" in response.headers


class TestErrorHandling:
    """Test error handling."""
    
    @patch('main.SentinelOrchestrator')
    def test_orchestrator_error_returns_500(self, mock_orchestrator_class, client):
        """Test orchestrator errors return 500 status."""
        mock_orchestrator_class.side_effect = Exception("Orchestrator failed")
        
        payload = {
            "raw_event": {
                "process_name": "test",
                "syscall": "execve",
                "file_path": "/bin/sh",
                "pod_name": "test-pod",
                "namespace": "default",
                "user": "user",
                "pid": 123
            },
            "guide_score": 0.9,
            "guide_grade": "TP"
        }
        
        response = client.post("/analyze", json=payload)
        
        assert response.status_code == 500
        data = response.json()
        assert "detail" in data


class TestRequestValidation:
    """Test request validation."""
    
    def test_case_insensitive_guide_grade(self, client, patch):
        """Test guide_grade accepts lowercase values."""
        with patch('main.SentinelOrchestrator') as mock_orchestrator_class:
            mock_orchestrator = Mock()
            mock_orchestrator.process_alert_sync.return_value = {
                "guide_grade": "TP",
                "guide_score": 0.9,
                "final_report": "Test report",
                "yaml_fix": "test: yaml"
            }
            mock_orchestrator_class.return_value = mock_orchestrator
            
            payload = {
                "raw_event": {
                    "process_name": "test",
                    "syscall": "execve",
                    "file_path": "/bin/sh",
                    "pod_name": "test-pod",
                    "namespace": "default",
                    "user": "user",
                    "pid": 123
                },
                "guide_score": 0.9,
                "guide_grade": "tp"  # Lowercase
            }
            
            response = client.post("/analyze", json=payload)
            
            # Should accept lowercase and convert to uppercase
            assert response.status_code == 200


def run_tests():
    """Run all tests manually (alternative to pytest)."""
    print("="*80)
    print("SENTINEL-CORE API TEST SUITE")
    print("="*80)
    
    # Create test client
    from main import app
    test_client = TestClient(app)
    
    # Run health check test
    print("\n1. Testing health endpoint...")
    response = test_client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"
    print("   ✓ Health check passed")
    
    # Run root endpoint test
    print("\n2. Testing root endpoint...")
    response = test_client.get("/")
    assert response.status_code == 200
    assert "Sentinel-Core" in response.json()["message"]
    print("   ✓ Root endpoint passed")
    
    # Run status endpoint test
    print("\n3. Testing status endpoint...")
    response = test_client.get("/status")
    assert response.status_code == 200
    assert "version" in response.json()
    print("   ✓ Status endpoint passed")
    
    print("\n" + "="*80)
    print("BASIC TESTS COMPLETE")
    print("="*80)


if __name__ == "__main__":
    # Can run directly or with pytest
    if len(sys.argv) > 1 and sys.argv[1] == "--manual":
        run_tests()
    else:
        # Run with pytest
        pytest.main([__file__, "-v"])

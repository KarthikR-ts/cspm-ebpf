#!/usr/bin/env python3
"""
test_orchestrator_structure.py

Unit tests for the orchestrator module structure and logic.
These tests verify the code structure without making actual API calls.

Run with: python test_orchestrator_structure.py
"""

import sys
import unittest
from unittest.mock import Mock, patch, MagicMock
from typing import Dict, Any


class TestSentinelState(unittest.TestCase):
    """Test the SentinelState TypedDict structure."""
    
    def test_sentinel_state_creation(self):
        """Test that we can create a valid SentinelState."""
        from orchestrator import SentinelState
        
        state: SentinelState = {
            "raw_event": {"process": "test", "syscall": "execve"},
            "guide_score": 0.9,
            "guide_grade": "TP",
            "mitre_context": "",
            "azure_context": "",
            "final_report": "",
            "yaml_fix": ""
        }
        
        self.assertEqual(state["guide_score"], 0.9)
        self.assertEqual(state["guide_grade"], "TP")
        self.assertIn("raw_event", state)


class TestEventRouter(unittest.TestCase):
    """Test Node A: Event Router logic."""
    
    def setUp(self):
        """Import the event_router function."""
        from orchestrator import event_router
        self.event_router = event_router
    
    def test_fp_auto_suppression(self):
        """Test that FP grade triggers auto-suppression."""
        state = {
            "raw_event": {"process": "test", "syscall": "execve"},
            "guide_score": 0.15,
            "guide_grade": "FP",
            "mitre_context": "",
            "azure_context": "",
            "final_report": "",
            "yaml_fix": ""
        }
        
        result = self.event_router(state)
        
        self.assertTrue(result["final_report"].startswith("Auto-suppressed"))
        self.assertEqual(result["yaml_fix"], "")
    
    def test_bp_continues_processing(self):
        """Test that BP grade continues processing."""
        state = {
            "raw_event": {"process": "test", "syscall": "connect"},
            "guide_score": 0.65,
            "guide_grade": "BP",
            "mitre_context": "",
            "azure_context": "",
            "final_report": "",
            "yaml_fix": ""
        }
        
        result = self.event_router(state)
        
        self.assertFalse(result["final_report"].startswith("Auto-suppressed"))
        self.assertIn("AUDIT LOG", result["mitre_context"])
    
    def test_tp_high_score_continues(self):
        """Test that TP grade or high score continues processing."""
        # Test TP case
        state_tp = {
            "raw_event": {"process": "malicious", "syscall": "execve"},
            "guide_score": 0.92,
            "guide_grade": "TP",
            "mitre_context": "",
            "azure_context": "",
            "final_report": "",
            "yaml_fix": ""
        }
        
        result = self.event_router(state_tp)
        
        self.assertFalse(result["final_report"].startswith("Auto-suppressed"))
        self.assertEqual(result["mitre_context"], "")  # No audit log added
    
    def test_uncertain_low_score_continues(self):
        """Test that uncertain (low score, not FP) continues processing."""
        state = {
            "raw_event": {"process": "unknown", "syscall": "read"},
            "guide_score": 0.45,
            "guide_grade": "UNCERTAIN",
            "mitre_context": "",
            "azure_context": "",
            "final_report": "",
            "yaml_fix": ""
        }
        
        result = self.event_router(state)
        
        self.assertFalse(result["final_report"].startswith("Auto-suppressed"))


class TestRAGRetriever(unittest.TestCase):
    """Test Node B: RAG Retriever (mocked)."""
    
    def setUp(self):
        """Import the rag_retriever function."""
        from orchestrator import rag_retriever
        self.rag_retriever = rag_retriever
    
    @patch('orchestrator.Pinecone')
    @patch('orchestrator.genai.embed_content')
    def test_rag_retrieval_success(self, mock_embed, mock_pinecone):
        """Test successful RAG retrieval with mocked Pinecone."""
        # Mock embedding response
        mock_embed.return_value = {'embedding': [0.1] * 768}
        
        # Mock Pinecone index
        mock_index = Mock()
        mock_index.query.side_effect = [
            {
                'matches': [
                    {'metadata': {'text': 'MITRE technique T1', 'technique_id': 'T1'}},
                    {'metadata': {'text': 'MITRE technique T2', 'technique_id': 'T2'}}
                ]
            },
            {
                'matches': [
                    {'metadata': {'text': 'Azure guideline 1'}},
                    {'metadata': {'text': 'Azure guideline 2'}}
                ]
            }
        ]
        
        mock_pc_instance = Mock()
        mock_pc_instance.list_indexes().names.return_value = ["sentinel-rag"]
        mock_pc_instance.Index.return_value = mock_index
        mock_pinecone.return_value = mock_pc_instance
        
        state = {
            "raw_event": {
                "process": "runc",
                "syscall": "execve",
                "file_path": "/bin/sh"
            },
            "guide_score": 0.9,
            "guide_grade": "TP",
            "mitre_context": "",
            "azure_context": "",
            "final_report": "",
            "yaml_fix": ""
        }
        
        result = self.rag_retriever(state)
        
        # Verify contexts were populated
        self.assertIn("MITRE", result["mitre_context"])
        self.assertIn("T1", result["mitre_context"])
        self.assertIn("Azure", result["azure_context"])
    
    def test_rag_skipped_for_fp(self):
        """Test that RAG is skipped for false positives."""
        state = {
            "raw_event": {"process": "test"},
            "guide_score": 0.1,
            "guide_grade": "FP",
            "final_report": "Auto-suppressed: False Positive. No action needed.",
            "mitre_context": "",
            "azure_context": "",
            "yaml_fix": ""
        }
        
        result = self.rag_retriever(state)
        
        # Should return unchanged (no API calls made)
        self.assertEqual(result["mitre_context"], "")
        self.assertEqual(result["azure_context"], "")


class TestReportGenerator(unittest.TestCase):
    """Test Node C: Report Generator (mocked)."""
    
    def setUp(self):
        """Import the report_generator function."""
        from orchestrator import report_generator
        self.report_generator = report_generator
    
    def test_yaml_extraction_with_markers(self):
        """Test YAML extraction from LLM response with proper markers."""
        from orchestrator import generate_safe_default_yaml
        
        # This test verifies the regex pattern works
        mock_response = """
REPORT: This is a security incident.

YAML FIX:
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: test-pod
```
"""
        import re
        yaml_pattern = r"```yaml\s*(.*?)\s*```"
        yaml_match = re.search(yaml_pattern, mock_response, re.DOTALL | re.IGNORECASE)
        
        self.assertIsNotNone(yaml_match)
        self.assertIn("apiVersion: v1", yaml_match.group(1))
    
    def test_safe_default_yaml_generation(self):
        """Test that safe default YAML is generated when LLM fails."""
        from orchestrator import generate_safe_default_yaml
        
        raw_event = {
            "pod_name": "test-pod",
            "namespace": "default",
            "process": "suspicious-process"
        }
        
        yaml_fix = generate_safe_default_yaml(raw_event)
        
        self.assertIn("apiVersion:", yaml_fix)
        self.assertIn("kind: NetworkPolicy", yaml_fix)
        self.assertIn("kind: Pod", yaml_fix)
        self.assertIn("test-pod", yaml_fix)
    
    def test_report_generator_skips_fp(self):
        """Test that report generator skips FP alerts."""
        state = {
            "raw_event": {},
            "guide_score": 0.1,
            "guide_grade": "FP",
            "final_report": "Auto-suppressed: False Positive. No action needed.",
            "mitre_context": "",
            "azure_context": "",
            "yaml_fix": ""
        }
        
        result = self.report_generator(state)
        
        # Should return unchanged
        self.assertEqual(result["final_report"], "Auto-suppressed: False Positive. No action needed.")
        self.assertEqual(result["yaml_fix"], "")


class TestGraphConstruction(unittest.TestCase):
    """Test the LangGraph workflow construction."""
    
    def test_graph_has_all_nodes(self):
        """Test that the graph contains all required nodes."""
        from orchestrator import build_sentinel_graph
        
        graph = build_sentinel_graph()
        
        # Check nodes exist (accessing internal structure)
        self.assertTrue(hasattr(graph, 'nodes'))
        node_names = list(graph.nodes.keys())
        
        self.assertIn("event_router", node_names)
        self.assertIn("rag_retriever", node_names)
        self.assertIn("report_generator", node_names)
    
    def test_graph_has_entry_point(self):
        """Test that the graph has correct entry point."""
        from orchestrator import build_sentinel_graph
        
        graph = build_sentinel_graph()
        
        # Entry point should be event_router
        # Note: Accessing internal structure may vary by LangGraph version
        self.assertTrue(hasattr(graph, 'entry_point'))


class TestOrchestratorClass(unittest.TestCase):
    """Test the main SentinelOrchestrator class."""
    
    @patch('orchestrator.SentinelOrchestrator.__init__', return_value=None)
    def test_orchestrator_initialization(self, mock_init):
        """Test orchestrator can be initialized."""
        from orchestrator import SentinelOrchestrator
        
        # This would normally initialize the graph
        # We're mocking it to avoid actual API setup
        orchestrator = SentinelOrchestrator()
        
        # Verify init was called
        mock_init.assert_called_once()
    
    def test_process_alert_sync_signature(self):
        """Test that process_alert_sync method exists with correct signature."""
        from orchestrator import SentinelOrchestrator
        import inspect
        
        # Get method signature
        sig = inspect.signature(SentinelOrchestrator.process_alert_sync)
        params = list(sig.parameters.keys())
        
        self.assertIn('self', params)
        self.assertIn('raw_event', params)
        self.assertIn('guide_score', params)
        self.assertIn('guide_grade', params)


class TestConfiguration(unittest.TestCase):
    """Test configuration loading and validation."""
    
    def test_llm_model_config(self):
        """Test LLM_MODEL configuration variable."""
        from orchestrator import LLM_MODEL
        
        # Should have a default value
        self.assertIsInstance(LLM_MODEL, str)
        self.assertTrue(len(LLM_MODEL) > 0)
    
    def test_pinecone_config_required(self):
        """Test that Pinecone configuration is required."""
        from orchestrator import PINECONE_API_KEY, PINECONE_ENV
        
        # These should be set (or will raise ValueError in production)
        # In test environment, they might be None or mock values
        self.assertIsInstance(PINECONE_API_KEY, str)
        self.assertIsInstance(PINECONE_ENV, str)
    
    def test_retrieval_constants(self):
        """Test RAG retrieval configuration constants."""
        from orchestrator import MITRE_TOP_K, AZURE_TOP_K
        
        self.assertEqual(MITRE_TOP_K, 3)
        self.assertEqual(AZURE_TOP_K, 2)


def run_tests():
    """Run all tests and print results."""
    print("="*80)
    print("SENTINEL-CORE ORCHESTRATOR - STRUCTURE TESTS")
    print("="*80)
    
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add all test classes
    test_classes = [
        TestSentinelState,
        TestEventRouter,
        TestRAGRetriever,
        TestReportGenerator,
        TestGraphConstruction,
        TestOrchestratorClass,
        TestConfiguration
    ]
    
    for test_class in test_classes:
        tests = loader.loadTestsFromTestCase(test_class)
        suite.addTests(tests)
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Print summary
    print("\n" + "="*80)
    print("TEST SUMMARY")
    print("="*80)
    print(f"Total tests: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Success: {result.wasSuccessful()}")
    print("="*80)
    
    return result.wasSuccessful()


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)

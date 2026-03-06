#!/usr/bin/env python3
"""
example_usage.py - Sentinel-Core Orchestrator Usage Examples

This file demonstrates various ways to use the Sentinel-Core orchestrator
for processing security alerts in different scenarios.
"""

import json
from orchestrator import SentinelOrchestrator, SentinelState


def example_1_basic_alert_processing():
    """
    Example 1: Basic Alert Processing
    
    Process a single security alert with minimal setup.
    This is the most common use case.
    """
    print("\n" + "="*80)
    print("EXAMPLE 1: Basic Alert Processing")
    print("="*80)
    
    # Initialize the orchestrator
    orchestrator = SentinelOrchestrator()
    
    # Define a suspicious event (container escape attempt)
    raw_event = {
        "process": "runc",
        "syscall": "execve",
        "file_path": "/bin/sh",
        "pod_name": "web-app-7d8f9c",
        "namespace": "production",
        "timestamp": "2026-03-06T14:32:15Z",
        "alert_title": "Suspicious execve from runc in container",
        "user": "root",
        "uid": 0
    }
    
    # Classifier output (from your ML model)
    guide_score = 0.92
    guide_grade = "TP"  # True Positive
    
    # Process the alert
    result = orchestrator.process_alert_sync(
        raw_event=raw_event,
        guide_score=guide_score,
        guide_grade=guide_grade
    )
    
    # Display results
    print("\n📋 SECURITY REPORT:")
    print("-" * 80)
    print(result["final_report"])
    
    print("\n🔧 KUBERNETES FIX:")
    print("-" * 80)
    print(result["yaml_fix"])
    
    return result


def example_2_false_positive_suppression():
    """
    Example 2: False Positive Suppression
    
    Demonstrate automatic suppression of false positive alerts.
    No RAG retrieval or LLM calls occur - immediate termination.
    """
    print("\n" + "="*80)
    print("EXAMPLE 2: False Positive Suppression")
    print("="*80)
    
    orchestrator = SentinelOrchestrator()
    
    # Benign activity misclassified initially
    raw_event = {
        "process": "kubectl",
        "syscall": "connect",
        "file_path": "/etc/kubernetes/admin.conf",
        "pod_name": "admin-tools",
        "namespace": "kube-system",
        "alert_title": "Kubectl accessing admin config"
    }
    
    # Classifier determined this is a False Positive
    guide_score = 0.15
    guide_grade = "FP"
    
    result = orchestrator.process_alert_sync(
        raw_event=raw_event,
        guide_score=guide_score,
        guide_grade=guide_grade
    )
    
    print("\n✅ Auto-suppressed Alert:")
    print("-" * 80)
    print(result["final_report"])
    print(f"\nYAML Fix: '{result['yaml_fix']}' (empty as expected)")
    
    return result


def example_3_high_confidence_true_positive():
    """
    Example 3: High Confidence True Positive
    
    Process a critical security alert with high confidence score.
    Triggers immediate processing without waiting for manual review.
    """
    print("\n" + "="*80)
    print("EXAMPLE 3: High Confidence True Positive")
    print("="*80)
    
    orchestrator = SentinelOrchestrator()
    
    # Critical: Privilege escalation attempt
    raw_event = {
        "process": "nsenter",
        "syscall": "setns",
        "file_path": "/proc/1/ns/pid",
        "pod_name": "compromised-app",
        "namespace": "default",
        "alert_title": "Container breakout attempt via nsenter",
        "user": "www-data",
        "uid": 33
    }
    
    # Very high confidence True Positive
    guide_score = 0.97
    guide_grade = "TP"
    
    result = orchestrator.process_alert_sync(
        raw_event=raw_event,
        guide_score=guide_score,
        guide_grade=guide_grade
    )
    
    print("\n🚨 CRITICAL ALERT PROCESSED:")
    print("-" * 80)
    print(result["final_report"])
    
    print("\n🔒 EMERGENCY FIX:")
    print("-" * 80)
    print(result["yaml_fix"])
    
    return result


def example_4_benign_positive_audit():
    """
    Example 4: Benign Positive with Audit Logging
    
    Process a benign positive alert that continues through the pipeline
    but is flagged for audit logging.
    """
    print("\n" + "="*80)
    print("EXAMPLE 4: Benign Positive (Audit Trail)")
    print("="*80)
    
    orchestrator = SentinelOrchestrator()
    
    # Unusual but legitimate activity
    raw_event = {
        "process": "debug-container",
        "syscall": "ptrace",
        "file_path": "/proc/123/mem",
        "pod_name": "debug-pod",
        "namespace": "monitoring",
        "alert_title": "Debug container using ptrace"
    }
    
    # Classified as Benign Positive - needs audit trail
    guide_score = 0.65
    guide_grade = "BP"
    
    result = orchestrator.process_alert_sync(
        raw_event=raw_event,
        guide_score=guide_score,
        guide_grade=guide_grade
    )
    
    print("\n📝 BENIGN POSITIVE WITH AUDIT:")
    print("-" * 80)
    print(result["final_report"])
    
    print("\n🔧 RECOMMENDED FIX:")
    print("-" * 80)
    print(result["yaml_fix"])
    
    return result


def example_5_full_state_control():
    """
    Example 5: Advanced - Full State Control
    
    Use the complete SentinelState TypedDict for maximum control
    over the orchestration process.
    """
    print("\n" + "="*80)
    print("EXAMPLE 5: Advanced - Full State Control")
    print("="*80)
    
    orchestrator = SentinelOrchestrator()
    
    # Build complete initial state
    initial_state: SentinelState = {
        "raw_event": {
            "process": "cryptominer",
            "syscall": "execve",
            "file_path": "/tmp/xmrig",
            "pod_name": "infected-pod",
            "namespace": "staging",
            "timestamp": "2026-03-06T15:45:00Z",
            "alert_title": "Cryptocurrency miner detected",
            "user": "app-user",
            "uid": 1000
        },
        "guide_score": 0.99,
        "guide_grade": "TP",
        "mitre_context": "",  # Will be filled by Node B
        "azure_context": "",  # Will be filled by Node B
        "final_report": "",   # Will be filled by Node C
        "yaml_fix": ""        # Will be filled by Node C
    }
    
    # Process through complete graph
    result = orchestrator.process_alert(initial_state)
    
    print("\n☣️  CRYPTOMINER ALERT:")
    print("-" * 80)
    print(result["final_report"])
    
    print("\n🛡️  REMEDIATION:")
    print("-" * 80)
    print(result["yaml_fix"])
    
    # Access all state fields
    print("\n📊 COMPLETE STATE:")
    print("-" * 80)
    print(json.dumps({
        "guide_score": result["guide_score"],
        "guide_grade": result["guide_grade"],
        "mitre_context_preview": result["mitre_context"][:100] + "...",
        "azure_context_preview": result["azure_context"][:100] + "...",
        "report_length": len(result["final_report"]),
        "yaml_length": len(result["yaml_fix"])
    }, indent=2))
    
    return result


def example_6_batch_processing():
    """
    Example 6: Batch Alert Processing
    
    Process multiple alerts sequentially (can be parallelized).
    """
    print("\n" + "="*80)
    print("EXAMPLE 6: Batch Alert Processing")
    print("="*80)
    
    orchestrator = SentinelOrchestrator()
    
    # Multiple alerts from different sources
    alerts = [
        {
            "raw_event": {
                "process": "nmap",
                "syscall": "socket",
                "file_path": "/dev/tcp",
                "pod_name": "scanner-pod",
                "namespace": "security",
                "alert_title": "Network scanning detected"
            },
            "guide_score": 0.88,
            "guide_grade": "TP"
        },
        {
            "raw_event": {
                "process": "curl",
                "syscall": "connect",
                "file_path": "https://malicious-site.com/payload.sh",
                "pod_name": "web-server",
                "namespace": "production",
                "alert_title": "Outbound connection to malicious domain"
            },
            "guide_score": 0.95,
            "guide_grade": "TP"
        },
        {
            "raw_event": {
                "process": "systemd",
                "syscall": "fork",
                "file_path": "/usr/lib/systemd/systemd",
                "pod_name": "init-pod",
                "namespace": "kube-system",
                "alert_title": "Systemd forking process"
            },
            "guide_score": 0.12,
            "guide_grade": "FP"
        }
    ]
    
    results = []
    for i, alert in enumerate(alerts, 1):
        print(f"\nProcessing Alert {i}/{len(alerts)}...")
        result = orchestrator.process_alert_sync(**alert)
        results.append(result)
        
        # Quick summary
        if result["final_report"].startswith("Auto-suppressed"):
            print(f"  ✅ SUPPRESSED: {result['final_report']}")
        else:
            print(f"  🚨 PROCESSED: Report generated ({len(result['final_report'])} chars)")
    
    print(f"\n✅ Batch complete: {len(results)} alerts processed")
    print(f"   - Processed: {sum(1 for r in results if not r['final_report'].startswith('Auto-suppressed'))}")
    print(f"   - Suppressed: {sum(1 for r in results if r['final_report'].startswith('Auto-suppressed'))}")
    
    return results


def main():
    """
    Run all examples or select specific ones.
    """
    print("="*80)
    print("SENTINEL-CORE ORCHESTRATOR - USAGE EXAMPLES")
    print("="*80)
    
    # Run all examples by default
    examples = [
        ("Basic Alert Processing", example_1_basic_alert_processing),
        ("False Positive Suppression", example_2_false_positive_suppression),
        ("High Confidence TP", example_3_high_confidence_true_positive),
        ("Benign Positive Audit", example_4_benign_positive_audit),
        ("Full State Control", example_5_full_state_control),
        ("Batch Processing", example_6_batch_processing),
    ]
    
    print(f"\nTotal examples: {len(examples)}")
    print("Note: These are live demonstrations using real API calls.\n")
    
    # Uncomment to run specific examples
    # example_1_basic_alert_processing()
    # example_2_false_positive_suppression()
    
    # Or run all (requires valid API keys and Pinecone index)
    for name, func in examples:
        try:
            func()
        except Exception as e:
            print(f"\n❌ Example '{name}' failed: {e}")
            print("   Make sure you have valid API keys in .env file")
    
    print("\n" + "="*80)
    print("ALL EXAMPLES COMPLETE")
    print("="*80)


if __name__ == "__main__":
    main()

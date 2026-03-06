#!/usr/bin/env python3
"""
Sentinel-Core Security Orchestration System - LangGraph Module

This module implements a security alert processing pipeline using LangGraph.
It receives structured security alerts (Tetragon eBPF events) and outputs:
1. A security incident report (string)
2. A Kubernetes YAML fix (string)

The pipeline consists of three nodes:
- Node A: event_router - Routes alerts based on classifier grade
- Node B: rag_retriever - Enriches alerts with MITRE and Azure context
- Node C: report_generator - Generates final report and YAML fix
"""

import os
import re
import yaml
import logging
import time
from typing import TypedDict, Optional, Literal, Any
from dotenv import load_dotenv

from langgraph.graph import StateGraph, END
from pinecone import Pinecone
import google.generativeai as genai
from langchain_google_genai import ChatGoogleGenerativeAI

# Load environment variables
load_dotenv()

# Configure logging for observability
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# ============================================================================
# CONFIGURATION
# ============================================================================

LLM_MODEL = os.getenv("LLM_MODEL", "gemini-1.5-pro")
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")

PINECONE_API_KEY = os.getenv("PINECONE_API_KEY")
PINECONE_ENV = os.getenv("PINECONE_ENV")

EMBEDDING_MODEL = os.getenv("EMBEDDING_MODEL", "google")
GOOGLE_EMBEDDING_MODEL = "models/embedding-004"

MITRE_TOP_K = 3
AZURE_TOP_K = 2

if not GOOGLE_API_KEY:
    raise ValueError("GOOGLE_API_KEY must be set in environment variables")
if not PINECONE_API_KEY or not PINECONE_ENV:
    raise ValueError("PINECONE_API_KEY and PINECONE_ENV must be set")

# ============================================================================
# THREAD-SAFE GLOBAL INITIALIZATION
# ============================================================================
# Initializing expensive clients once at the module level for performance 
# and thread safety, instead of inside the nodes.

genai.configure(api_key=GOOGLE_API_KEY)

_pc_client = None
_pc_index = None
try:
    _pc_client = Pinecone(api_key=PINECONE_API_KEY, host=PINECONE_ENV)
    _rag_index_name = "sentinel-rag"
    if _rag_index_name not in _pc_client.list_indexes().names():
        logger.warning(f"Index '{_rag_index_name}' not found. Creating with dimension 768.")
        _pc_client.create_index(name=_rag_index_name, dimension=768, metric="cosine")
    _pc_index = _pc_client.Index(_rag_index_name)
    logger.info(f"Initialized global Pinecone index: {_rag_index_name}")
except Exception as e:
    logger.error(f"Failed to initialize Pinecone global client: {e}")

_llm = ChatGoogleGenerativeAI(
    model=LLM_MODEL,
    api_key=GOOGLE_API_KEY,
    temperature=0.3,
    max_tokens=2000
)

# ============================================================================
# STATE SCHEMA
# ============================================================================

class SentinelState(TypedDict):
    raw_event: dict
    guide_score: float
    guide_grade: str
    stream: bool
    mitre_context: str
    azure_context: str
    final_report: str
    yaml_fix: str
    error: str

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def generate_safe_default_yaml(raw_event: dict) -> str:
    """Generates a safe default K8s YAML if generation fails or extraction is invalid."""
    pod_name = raw_event.get("pod_name", raw_event.get("pod", "affected-pod"))
    namespace = raw_event.get("namespace", "default")
    return f"""apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: restrict-{pod_name}-egress
  namespace: {namespace}
spec:
  podSelector:
    matchLabels:
      app: {pod_name}
  policyTypes:
  - Egress
  - Ingress
  egress:
  - to:
    - namespaceSelector:
        matchLabels:
          name: kube-system
    ports:
    - protocol: UDP
      port: 53
  ingress: []
---
apiVersion: v1
kind: Pod
metadata:
  name: {pod_name}
  namespace: {namespace}
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    fsGroup: 1000
  containers:
  - name: {pod_name}
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop:
        - ALL"""

def robust_yaml_extract(text: str, raw_event: dict) -> str:
    """Robustly extracts YAML block and validates with pyyaml."""
    yaml_str = None
    
    # Try markdown block
    for pattern in [r"```yaml\s*(.*?)\s*```", r"```YAML\s*(.*?)\s*```"]:
        match = re.search(pattern, text, re.DOTALL)
        if match:
            yaml_str = match.group(1).strip()
            break
            
    # Try finding raw apiVersion:
    if not yaml_str and "apiVersion:" in text:
        yaml_str = "apiVersion:" + text.split("apiVersion:", 1)[1]
        if "```" in yaml_str:
            yaml_str = yaml_str.split("```")[0].strip()
            
    # Generic block fallback
    if not yaml_str:
        gen_pattern = r"```\s*(.*?)\s*```"
        gen_match = re.search(gen_pattern, text, re.DOTALL)
        if gen_match and "apiVersion:" in gen_match.group(1):
            yaml_str = gen_match.group(1).strip()

    if yaml_str:
        try:
            yaml.safe_load(yaml_str)
            return yaml_str
        except yaml.YAMLError as e:
            logger.warning(f"Extracted YAML was invalid: {e}")

    logger.warning("Falling back to safe default YAML template.")
    return generate_safe_default_yaml(raw_event)


# ============================================================================
# NODES
# ============================================================================

def event_router(state: SentinelState) -> dict:
    logger.info("="*60)
    logger.info("NODE A: EVENT ROUTER")
    logger.info("="*60)
    start_time = time.time()
    
    try:
        guide_grade = state.get("guide_grade", "")
        guide_score = state.get("guide_score", 0.0)
        
        if guide_grade == "FP":
            result = {
                **state,
                "final_report": "Auto-suppressed: False Positive. No action needed.",
                "yaml_fix": ""
            }
        elif guide_grade == "BP":
            result = {
                **state,
                "mitre_context": f"[AUDIT LOG] BP classification at {guide_score} confidence"
            }
        else:
            result = state
            
        duration = (time.time() - start_time) * 1000
        logger.info(f"[Node: event_router] Time taken: {duration:.2f} ms | Routing decision: {guide_grade}")
        return result
    except Exception as e:
        duration = (time.time() - start_time) * 1000
        err_msg = f"Error in event_router: {str(e)}"
        logger.error(f"[Node: event_router] Failed: {e} | Time taken: {duration:.2f} ms")
        return {**state, "error": str(e), "final_report": err_msg}


def rag_retriever(state: SentinelState) -> dict:
    logger.info("="*60)
    logger.info("NODE B: RAG RETRIEVER")
    logger.info("="*60)
    start_time = time.time()
    
    try:
        if state.get("final_report", "").startswith("Auto-suppressed"):
            duration = (time.time() - start_time) * 1000
            logger.info(f"[Node: rag_retriever] Time taken: {duration:.2f} ms | Skipped (suppressed)")
            return state
            
        if not _pc_index:
            raise RuntimeError("Pinecone global index was not successfully initialized.")
            
        raw_event = state.get("raw_event", {})
        process_name = raw_event.get("process", "unknown_process")
        syscall = raw_event.get("syscall", "unknown_syscall")
        file_path = raw_event.get("file_path", raw_event.get("path", "unknown_path"))
        alert_title = raw_event.get("alert_title", f"{process_name} {syscall} alert")
        
        mitre_query = f"{process_name} {syscall} {file_path}"
        azure_query = alert_title
        
        try:
            m_resp = genai.embed_content(model=GOOGLE_EMBEDDING_MODEL, content=mitre_query, task_type="retrieval_query")
            mitre_results = _pc_index.query(vector=m_resp['embedding'], top_k=MITRE_TOP_K, namespace="mitre", include_metadata=True)
            mitre_texts = []
            for match in mitre_results.get('matches', []):
                meta = match.get('metadata', {})
                text, tid = meta.get('text', ''), meta.get('technique_id', '')
                if text:
                    mitre_texts.append(f"[{tid}] {text}" if tid else text)
            mitre_context = "\n".join(mitre_texts) if mitre_texts else "No MITRE ATT&CK context found."
        except Exception as e:
            logger.warning(f"MITRE retrieval failed: {e}")
            mitre_context = f"Error retrieving MITRE context: {e}"

        try:
            a_resp = genai.embed_content(model=GOOGLE_EMBEDDING_MODEL, content=azure_query, task_type="retrieval_query")
            azure_results = _pc_index.query(vector=a_resp['embedding'], top_k=AZURE_TOP_K, namespace="azure", include_metadata=True)
            azure_texts = [m.get('metadata', {}).get('text', '') for m in azure_results.get('matches', []) if m.get('metadata', {}).get('text')]
            azure_context = "\n".join(azure_texts) if azure_texts else "No Azure Security Benchmark context found."
        except Exception as e:
            logger.warning(f"Azure retrieval failed: {e}")
            azure_context = f"Error retrieving Azure context: {e}"

        duration = (time.time() - start_time) * 1000
        logger.info(f"[Node: rag_retriever] Time taken: {duration:.2f} ms | Output: MITRE {len(mitre_context)} chars, Azure {len(azure_context)} chars")
        
        return {**state, "mitre_context": mitre_context, "azure_context": azure_context}
    except Exception as e:
        duration = (time.time() - start_time) * 1000
        err_msg = f"Error in rag_retriever: {str(e)}"
        logger.error(f"[Node: rag_retriever] Failed: {e} | Time taken: {duration:.2f} ms")
        return {**state, "error": str(e), "final_report": err_msg}


def report_generator(state: SentinelState) -> dict:
    logger.info("="*60)
    logger.info("NODE C: REPORT GENERATOR")
    logger.info("="*60)
    start_time = time.time()
    
    try:
        if state.get("final_report", "").startswith("Auto-suppressed"):
            duration = (time.time() - start_time) * 1000
            logger.info(f"[Node: report_generator] Time taken: {duration:.2f} ms | Skipped (suppressed)")
            return state

        raw_event = state.get("raw_event", {})
        guide_score = state.get("guide_score", 0.0)
        guide_grade = state.get("guide_grade", "UNKNOWN")
        mitre_context = state.get("mitre_context", "No MITRE context available.")
        azure_context = state.get("azure_context", "No Azure context available.")
        
        process_name = raw_event.get("process", "unknown")
        syscall = raw_event.get("syscall", "unknown")
        file_path = raw_event.get("file_path", raw_event.get("path", "unknown"))
        timestamp = raw_event.get("timestamp", "unknown")
        pod_name = raw_event.get("pod_name", raw_event.get("pod", "unknown"))
        namespace = raw_event.get("namespace", "default")
        
        user_prompt = f"""SECURITY ALERT ANALYSIS REQUEST

EVENT DETAILS:
- Process: {process_name}
- Syscall: {syscall}
- File/Path Accessed: {file_path}
- Pod: {pod_name}
- Namespace: {namespace}
- Timestamp: {timestamp}

CLASSIFIER INFORMATION:
- Grade: {guide_grade}
- Confidence Score: {guide_score}

MITRE ATT&CK CONTEXT:
{mitre_context}

AZURE SECURITY BENCHMARK CONTEXT:
{azure_context}

TASK:
Analyze this security alert and provide:
1. A concise incident report (max 200 words) explaining the threat, its MITRE technique mapping, and potential impact
2. A specific Kubernetes YAML patch to remediate or mitigate this issue

Format your response as:
REPORT: [Your incident report here]

YAML FIX:
```yaml
[Your Kubernetes YAML patch here]
```"""

        system_prompt = "You are Sentinel-Core's AI Security Analyst. You write precise, expert-level incident reports for SOC teams. Be concise. Always cite MITRE technique IDs. Always end with a YAML fix."

        stream_enabled = state.get("stream", False)
        full_response = ""
        
        if stream_enabled:
            logger.info("Streaming enabled! Generating report token-by-token...")
            for chunk in _llm.stream(f"{system_prompt}\n\n{user_prompt}"):
                content = chunk.content if hasattr(chunk, 'content') else str(chunk)
                print(content, end="", flush=True)
                full_response += content
            print() # Insert trailing newline after chunk streams end
        else:
            response = _llm.invoke(f"{system_prompt}\n\n{user_prompt}")
            full_response = response.content if hasattr(response, 'content') else str(response)

        # Parse final response robustly
        yaml_marker = "```yaml"
        if yaml_marker in full_response.lower():
            report_part = re.split(r"```[yY][aA][mM][lL]", full_response)[0].replace("REPORT:", "").strip()
        else:
            report_part = full_response.replace("REPORT:", "").strip()
            
        final_report = report_part[:2000]
        yaml_fix = robust_yaml_extract(full_response, raw_event)

        duration = (time.time() - start_time) * 1000
        logger.info(f"[Node: report_generator] Time taken: {duration:.2f} ms | Output: final_report length: {len(final_report)} chars")
        
        return {**state, "final_report": final_report, "yaml_fix": yaml_fix}
    except Exception as e:
        duration = (time.time() - start_time) * 1000
        err_msg = f"Error in report_generator: {str(e)}"
        logger.error(f"[Node: report_generator] Failed: {e} | Time taken: {duration:.2f} ms")
        return {
            **state, 
            "error": str(e), 
            "final_report": err_msg, 
            "yaml_fix": generate_safe_default_yaml(state.get("raw_event", {}))
        }


# ============================================================================
# GRAPH ROUTING & CONSTRUCTION
# ============================================================================

def continue_or_end(state: SentinelState) -> str:
    if "error" in state or state.get("final_report", "").startswith("Auto-suppressed"):
        return END
    return "rag_retriever"

def rag_or_end(state: SentinelState) -> str:
    if "error" in state:
        return END
    return "report_generator"
    
def report_or_end(state: SentinelState) -> str:
    return END

def build_sentinel_graph() -> StateGraph:
    logger.info("Building Sentinel-Core LangGraph workflow...")
    workflow = StateGraph(SentinelState)
    workflow.add_node("event_router", event_router)
    workflow.add_node("rag_retriever", rag_retriever)
    workflow.add_node("report_generator", report_generator)
    
    workflow.set_entry_point("event_router")
    
    workflow.add_conditional_edges("event_router", continue_or_end)
    workflow.add_conditional_edges("rag_retriever", rag_or_end)
    workflow.add_conditional_edges("report_generator", report_or_end)
    
    logger.info("LangGraph workflow built successfully")
    return workflow.compile()


# ============================================================================
# PUBLIC API
# ============================================================================

_shared_graph = build_sentinel_graph()

def run_graph(initial_state: dict, stream: bool = False) -> dict:
    """
    Main function to run the LangGraph graph with streaming support.
    
    Args:
        initial_state: Initial state payload.
        stream: Optional flag to toggle LLM token streaming.
    """
    initial_state["stream"] = stream
    return _shared_graph.invoke(initial_state)

def analyze_alert(raw_event: dict, guide_score: float, guide_grade: str, stream: bool = False) -> dict:
    """
    Clean public function wrapper for FastAPI or external callers to execute.
    
    Args:
        raw_event: Dictionary describing the security event.
        guide_score: Confidence score from the classifier.
        guide_grade: Triage grade ('TP', 'BP', 'FP').
        stream: Whether to stream LLM generation tokens to stdout.
        
    Returns:
        A dict containing at least 'final_report' and 'yaml_fix'.
    """
    initial_state: SentinelState = {
        "raw_event": raw_event,
        "guide_score": guide_score,
        "guide_grade": guide_grade,
        "stream": stream,
        "mitre_context": "",
        "azure_context": "",
        "final_report": "",
        "yaml_fix": "",
        "error": ""
    }
    return run_graph(initial_state, stream=stream)


if __name__ == "__main__":
    print("="*80)
    print("SENTINEL-CORE ORCHESTRATOR - TEST MODE")
    print("="*80)
    
    mock_event = {
        "process": "runc",
        "syscall": "execve",
        "file_path": "/bin/sh",
        "pod_name": "vulnerable-app-7d8f9c",
        "namespace": "production",
        "timestamp": "2026-03-06T14:32:15Z",
        "alert_title": "Suspicious execve from runc in container",
        "user": "root",
        "uid": 0
    }
    
    logger.info("TESTING PUBLICA API: analyze_alert() - TP EVENT (STREAMING=TRUE)")
    res = analyze_alert(mock_event, 0.92, "TP", stream=True)
    
    print("\n" + "="*80)
    print("RESULTS")
    print("="*80)
    
    print("\n📋 FINAL REPORT:")
    print("-" * 80)
    print(res.get("final_report"))
    
    print("\n🔧 YAML FIX:")
    print("-" * 80)
    print(res.get("yaml_fix"))

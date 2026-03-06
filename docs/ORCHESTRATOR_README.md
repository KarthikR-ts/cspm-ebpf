# Sentinel-Core Orchestrator Documentation

## Overview

The `orchestrator.py` module implements a complete security alert processing pipeline using **LangGraph**, Google's Gemini LLM, and Pinecone vector database. It processes Tetragon eBPF security events and generates:

1. **Security Incident Report** - A concise, expert-level analysis for SOC teams
2. **Kubernetes YAML Fix** - A remediation patch to mitigate the detected threat

## Architecture

### Graph Structure

```
START → Node A (event_router)
           ↓
      [Conditional]
           ↓
    ┌──────┴──────┐
    │             │
  END (FP)   Node B (rag_retriever)
               ↓
         Node C (report_generator)
               ↓
             END
```

### Nodes

#### Node A: Event Router
**Function:** Initial alert triage and routing

**Logic:**
- **False Positive (FP)**: Auto-suppress with message "Auto-suppressed: False Positive. No action needed."
- **Benign Positive (BP)**: Log for audit trail, continue processing with low priority flag
- **True Positive (TP) or Score > 0.8**: Process immediately through full pipeline
- **Uncertain (< 0.8, not FP)**: Continue processing with standard priority

**No LLM calls** - Pure deterministic routing logic

---

#### Node B: RAG Retriever
**Function:** Enrich alert with security knowledge context

**Retrieval Strategy:**
1. **MITRE ATT&CK Namespace**
   - Query: `"{process_name} {syscall} {file_path}"`
   - Results: Top 3 matches
   - Format: `[TECHNIQUE_ID] Description`

2. **Azure Security Benchmark Namespace**
   - Query: `"{alert_title}"`
   - Results: Top 2 matches
   - Format: Security guideline text

**Embedding Model:** Uses Google's `models/embedding-004` (configurable via `EMBEDDING_MODEL`)

---

#### Node C: Report Generator
**Function:** Generate final deliverables using LLM

**System Prompt:**
> "You are Sentinel-Core's AI Security Analyst. You write precise, expert-level incident reports for SOC teams. Be concise. Always cite MITRE technique IDs. Always end with a YAML fix."

**Outputs:**
- `final_report`: Max ~200 words, includes MITRE technique citations
- `yaml_fix`: Kubernetes YAML extracted via regex from LLM response

**Fallback:** If LLM fails, generates safe default NetworkPolicy + Pod security template

---

## Installation

### Prerequisites

- Python 3.9+
- Pinecone account (free tier available)
- Google Cloud API key (for Gemini + embeddings)

### Dependencies

Add these to your `requirements.txt`:

```txt
langgraph>=0.2.0
langchain-google-genai>=1.0.0
pinecone-client>=3.0.0
python-dotenv>=1.0.0
google-generativeai>=0.4.0
```

Install:
```bash
pip install langgraph langchain-google-genai pinecone-client python-dotenv google-generativeai
```

---

## Configuration

### Environment Variables (.env)

```env
# Required: Pinecone
PINECONE_API_KEY=pcsk_your_api_key
PINECONE_ENV=your_pinecone_environment

# Required: Google AI (for LLM + embeddings)
GOOGLE_API_KEY=your_google_api_key

# Optional: LLM Model (default: gemini-1.5-pro)
LLM_MODEL=gemini-1.5-pro

# Optional: Embedding Provider (default: google)
EMBEDDING_MODEL=google
```

---

## Usage

### Basic Example

```python
from orchestrator import SentinelOrchestrator

# Initialize orchestrator
orchestrator = SentinelOrchestrator()

# Define a security alert
raw_event = {
    "process": "runc",
    "syscall": "execve",
    "file_path": "/bin/sh",
    "pod_name": "vulnerable-app-7d8f9c",
    "namespace": "production",
    "timestamp": "2026-03-06T14:32:15Z",
    "alert_title": "Suspicious execve from runc in container"
}

# Process the alert
result = orchestrator.process_alert_sync(
    raw_event=raw_event,
    guide_score=0.92,
    guide_grade="TP"
)

# Access outputs
print("Report:", result["final_report"])
print("YAML Fix:", result["yaml_fix"])
```

### Advanced: Full State Control

```python
from orchestrator import SentinelOrchestrator, SentinelState

orchestrator = SentinelOrchestrator()

# Build complete initial state
initial_state: SentinelState = {
    "raw_event": {...},
    "guide_score": 0.92,
    "guide_grade": "TP",
    "mitre_context": "",  # Will be filled by Node B
    "azure_context": "",  # Will be filled by Node B
    "final_report": "",   # Will be filled by Node C
    "yaml_fix": ""        # Will be filled by Node C
}

# Process through graph
result = orchestrator.process_alert(initial_state)
```

### Integration with Classifier

```python
# Assuming you have a classifier model
classifier_output = classifier.predict(raw_event)
guide_score = classifier_output["confidence"]
guide_grade = classifier_output["grade"]  # TP/BP/FP

orchestrator = SentinelOrchestrator()
result = orchestrator.process_alert_sync(
    raw_event=raw_event,
    guide_score=guide_score,
    guide_grade=guide_grade
)
```

---

## Testing

### Run Built-in Test

The module includes a test block with a mock alert:

```bash
python orchestrator.py
```

This will:
1. Create a mock container escape alert
2. Process it through the full pipeline
3. Print the generated report and YAML fix

### Expected Output

```
================================================================================
SENTINEL-CORE ORCHESTRATOR - TEST MODE
================================================================================

Mock Alert Details:
{
  "process": "runc",
  "syscall": "execve",
  ...
}

Classifier Score: 0.92
Classifier Grade: TP

================================================================================
Initializing Orchestrator...
================================================================================

NODE A: EVENT ROUTER
Decision: TRUE POSITIVE/HIGH SCORE (0.92) - Processing immediately

NODE B: RAG RETRIEVER
Querying MITRE namespace (top 3)...
Retrieved 3 MITRE results
Querying Azure namespace (top 2)...
Retrieved 2 Azure results

NODE C: REPORT GENERATOR
Calling Gemini API for report generation...
Successfully extracted YAML fix from LLM response

================================================================================
RESULTS
================================================================================

📋 FINAL REPORT:
[Generated incident report...]

🔧 YAML FIX:
[Generated Kubernetes YAML...]
```

---

## Error Handling

### Pinecone Index Not Found

If the `sentinel-rag` index doesn't exist, the orchestrator will:
1. Log a warning
2. Attempt to create it with default dimensions (768 for Google embeddings)
3. Continue processing

### LLM Failures

If Gemini API fails:
- Returns error message in `final_report`: `"Error generating report: <details>. Manual review required."`
- Generates safe default YAML template

### RAG Retrieval Errors

If Pinecone queries fail:
- Sets context fields to error messages
- Continues to report generation (LLM will note missing context)

---

## Customization

### Change LLM Model

```python
# In .env or before initialization
import os
os.environ["LLM_MODEL"] = "gemini-1.5-flash"  # Faster, cheaper option
```

### Adjust Retrieval Parameters

```python
# At top of orchestrator.py
MITRE_TOP_K = 5       # Default: 3
AZURE_TOP_K = 3       # Default: 2
```

### Modify System Prompt

Edit the `system_prompt` variable in `report_generator()` function:

```python
system_prompt = """Your custom prompt here..."""
```

### Add Custom Routing Logic

Modify `event_router()` function:

```python
def event_router(state: SentinelState) -> dict:
    # Add your custom logic here
    if state["guide_score"] < 0.5:
        return {**state, "custom_flag": True}
    return state
```

---

## Performance Considerations

### Latency Breakdown

- **Node A (Router):** < 1ms (pure logic, no API calls)
- **Node B (RAG):** 200-800ms (embedding generation + Pinecone queries)
- **Node C (Report):** 1000-3000ms (Gemini LLM inference)

**Total:** ~1.2-4 seconds per alert

### Optimization Tips

1. **Use `gemini-1.5-flash`** for faster responses (lower quality)
2. **Reduce TOP_K values** for faster RAG retrieval
3. **Cache embeddings** for common process/syscall combinations
4. **Batch processing** for multiple alerts

---

## Security Notes

### API Key Management

- Store all keys in `.env` (never commit to git)
- Use environment variables in production
- Rotate keys regularly

### Pinecone Index Security

- Use separate indexes per environment (dev/staging/prod)
- Enable authentication on Pinecone serverless
- Restrict network access to Pinecone endpoints

---

## Troubleshooting

### Issue: "GOOGLE_API_KEY must be set"

**Solution:** Ensure `.env` file exists and contains:
```env
GOOGLE_API_KEY=your_actual_key
```

### Issue: "Index 'sentinel-rag' not found"

**Solution:** 
1. Run the ingest.py script first to populate the index
2. Or let orchestrator auto-create it (will be empty initially)

### Issue: "No YAML found in response"

**Solution:** 
- Check that LLM_MODEL is valid
- Verify GOOGLE_API_KEY has Generative AI access
- Review LLM response in logs for formatting issues

---

## File Structure

```
cspm-ebpf/
├── orchestrator.py          # Main orchestration module
├── config.py                # Shared configuration
├── .env                     # Environment variables
├── .env.example             # Template for .env
└── docs/
    └── ORCHESTRATOR_README.md  # This file
```

---

## Contributing

When extending the orchestrator:

1. **Maintain type hints** - Use `SentinelState` TypedDict
2. **Log appropriately** - Use the logger at INFO level
3. **Handle errors gracefully** - Never crash the pipeline
4. **Test thoroughly** - Add test cases to the main block

---

## License

Part of the Sentinel-Core Security AI Platform.

---

## Support

For issues or questions:
- Check logs with `logging.basicConfig(level=logging.INFO)`
- Review Pinecone dashboard for index status
- Verify Google Cloud Console for API quotas

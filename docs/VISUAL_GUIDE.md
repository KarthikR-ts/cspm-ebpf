# Sentinel-Core Orchestrator - Visual Guide

## 🎯 System Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                    SENTINEL-CORE ORCHESTRATOR                   │
│                                                                 │
│  Input: Tetragon eBPF Security Event + Classifier Output        │
│  Output: Security Incident Report + Kubernetes YAML Fix         │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
        ┌────────────────────────────────────────┐
        │         START (Alert Received)         │
        └────────────────────────────────────────┘
                              │
                              ▼
```

---

## 🏗️ Node A: Event Router

```
        ┌────────────────────────────────────────┐
        │      NODE A: EVENT ROUTER              │
        │                                        │
        │  Input:                                │
        │  • raw_event (Tetragon event dict)     │
        │  • guide_score (0.0-1.0)               │
        │  • guide_grade (TP/BP/FP)              │
        │                                        │
        │  Logic:                                │
        │  ┌──────────────────────────────┐     │
        │  │ if grade == "FP":            │     │
        │  │   → Auto-suppress             │     │
        │  │   → Set final_report          │     │
        │  │   → END                       │     │
        │  ├──────────────────────────────┤     │
        │  │ elif grade == "BP":          │     │
        │  │   → Log for audit             │     │
        │  │   → Add audit flag            │     │
        │  │   → Continue to Node B        │     │
        │  ├──────────────────────────────┤     │
        │  │ elif grade == "TP" or        │     │
        │  │      score > 0.8:            │     │
        │  │   → Process immediately       │     │
        │  │   → Continue to Node B        │     │
        │  └──────────────────────────────┘     │
        │                                        │
        │  Latency: < 1ms                        │
        │  LLM Calls: ❌ None                     │
        └────────────────────────────────────────┘
                              │
                    ┌─────────┴─────────┐
                    │                   │
                    ▼                   ▼
            [FP Detected]         [Not FP]
                    │                   │
                    ▼                   ▼
                END            ┌────────────────┐
                               │ Continue to    │
                               │ Node B         │
                               └────────────────┘
                                        │
                                        ▼
```

---

## 🔍 Node B: RAG Retriever

```
        ┌────────────────────────────────────────┐
        │      NODE B: RAG RETRIEVER             │
        │                                        │
        │  Input:                                │
        │  • raw_event fields                    │
        │    - process_name                      │
        │    - syscall                           │
        │    - file_path                         │
        │    - alert_title                       │
        │                                        │
        │  Actions:                              │
        │  ┌──────────────────────────────┐     │
        │  │ 1. Generate Embedding         │     │
        │  │    Query: "{process} {syscall}│     │
        │  │          {file_path}"         │     │
        │  │    Model: Google embed-004    │     │
        │  ├──────────────────────────────┤     │
        │  │ 2. Query Pinecone MITRE       │     │
        │  │    Namespace: "mitre"         │     │
        │  │    Top-K: 3 results           │     │
        │  │    Format: [TECH_ID] Desc     │     │
        │  ├──────────────────────────────┤     │
        │  │ 3. Generate Embedding         │     │
        │  │    Query: "{alert_title}"     │     │
        │  ├──────────────────────────────┤     │
        │  │ 4. Query Pinecone Azure       │     │
        │  │    Namespace: "azure"         │     │
        │  │    Top-K: 2 results           │     │
        │  │    Format: Guideline text     │     │
        │  └──────────────────────────────┘     │
        │                                        │
        │  Output:                               │
        │  • mitre_context (str)                 │
        │  • azure_context (str)                 │
        │                                        │
        │  Latency: 200-800ms                    │
        │  LLM Calls: ✅ Embedding API            │
        └────────────────────────────────────────┘
                              │
                              ▼
        ┌────────────────────────────────────────┐
        │  Example MITRE Context:                │
        │  ────────────────────────────────────  │
        │  [T1053.007] Scheduled Task/Container   │
        │  Adversaries may schedule malicious...  │
        │                                        │
        │  [T1548.001] Abuse Elevation Control... │
        │  To bypass elevation controls...        │
        └────────────────────────────────────────┘
                              │
                              ▼
        ┌────────────────────────────────────────┐
        │  Example Azure Context:                │
        │  ────────────────────────────────────  │
        │  Limit container capabilities to...     │
        │  Containers should run with minimal...  │
        └────────────────────────────────────────┘
                              │
                              ▼
```

---

## 🤖 Node C: Report Generator

```
        ┌────────────────────────────────────────┐
        │      NODE C: REPORT GENERATOR          │
        │                                        │
        │  Input:                                │
        │  • All state fields                    │
        │  • mitre_context (from Node B)         │
        │  • azure_context (from Node B)         │
        │                                        │
        │  LLM: Google Gemini 1.5 Pro            │
        │  System Prompt:                        │
        │  ┌──────────────────────────────┐     │
        │  │ "You are Sentinel-Core's AI  │     │
        │  │ Security Analyst. You write  │     │
        │  │ precise, expert-level        │     │
        │  │ incident reports for SOC     │     │
        │  │ teams. Be concise. Always    │     │
        │  │ cite MITRE technique IDs.    │     │
        │  │ Always end with a YAML fix." │     │
        │  └──────────────────────────────┘     │
        │                                        │
        │  User Prompt (Dynamic):                │
        │  ┌──────────────────────────────┐     │
        │  │ EVENT DETAILS:               │     │
        │  │ - Process: runc              │     │
        │  │ - Syscall: execve            │     │
        │  │ - Path: /bin/sh              │     │
        │  │ - Pod: vulnerable-app        │     │
        │  │ - Namespace: production      │     │
        │  │                              │     │
        │  │ CLASSIFIER INFO:             │     │
        │  │ - Grade: TP                  │     │
        │  │ - Score: 0.92                │     │
        │  │                              │     │
        │  │ MITRE CONTEXT:               │     │
        │  │ [Retrieved from Node B]      │     │
        │  │                              │     │
        │  │ AZURE CONTEXT:               │     │
        │  │ [Retrieved from Node B]      │     │
        │  │                              │     │
        │  │ TASK:                        │     │
        │  │ Generate incident report     │     │
        │  │ and Kubernetes YAML fix      │     │
        │  └──────────────────────────────┘     │
        │                                        │
        │  Output Processing:                    │
        │  ┌──────────────────────────────┐     │
        │  │ 1. Extract Report:           │     │
        │  │    Everything before YAML    │     │
        │  │    Max ~200 words            │     │
        │  ├──────────────────────────────┤     │
        │  │ 2. Extract YAML:             │     │
        │  │    Regex: ```yaml(...)```    │     │
        │  │    Fallback: Default tmpl    │     │
        │  └──────────────────────────────┘     │
        │                                        │
        │  Latency: 1000-3000ms                  │
        │  LLM Calls: ✅ Gemini API               │
        └────────────────────────────────────────┘
                              │
                              ▼
```

---

## 📊 Complete Pipeline Flow

```
START
  │
  ├─→ [Node A: Event Router]
  │      │
  │      ├─→ FP? → Auto-suppress → END
  │      │
  │      └─→ Not FP? ↓
  │
  ├─→ [Node B: RAG Retriever]
  │      │
  │      ├─→ Query MITRE (top 3)
  │      │      └─→ mitre_context
  │      │
  │      └─→ Query Azure (top 2)
  │             └─→ azure_context
  │
  ├─→ [Node C: Report Generator]
  │      │
  │      ├─→ Build prompt
  │      │
  │      ├─→ Call Gemini
  │      │
  │      ├─→ Extract report
  │      │
  │      └─→ Extract YAML
  │
  └─→ END
         │
         ├─→ final_report
         │
         └─→ yaml_fix
```

---

## 🎯 Data Flow Diagram

```
┌──────────────────────────────────────────────────────────────┐
│ INPUT                                                        │
│ ┌─────────────────┐  ┌──────────────────┐  ┌──────────────┐ │
│ │ raw_event       │  │ guide_score      │  │ guide_grade  │ │
│ │ (dict)          │  │ (float: 0.0-1.0) │  │ (str: TP/BP/ │ │
│ │ - process       │  │                  │  │ FP)          │ │
│ │ - syscall       │  │                  │  │              │ │
│ │ - file_path     │  │                  │  │              │ │
│ │ - pod_name      │  │                  │  │              │ │
│ │ - namespace     │  │                  │  │              │ │
│ └─────────────────┘  └──────────────────┘  └──────────────┘ │
└──────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌──────────────────────────────────────────────────────────────┐
│ STATE (SentinelState TypedDict)                              │
│ ┌──────────────────────────────────────────────────────────┐ │
│ │ raw_event: dict                                          │ │
│ │ guide_score: float                                       │ │
│ │ guide_grade: str                                         │ │
│ │ mitre_context: str (filled by Node B)                    │ │
│ │ azure_context: str (filled by Node B)                    │ │
│ │ final_report: str (filled by Node C)                     │ │
│ │ yaml_fix: str (filled by Node C)                         │ │
│ └──────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌──────────────────────────────────────────────────────────────┐
│ OUTPUT                                                       │
│ ┌────────────────────────────┐  ┌──────────────────────────┐ │
│ │ final_report               │  │ yaml_fix                 │ │
│ │ (Security Incident Report) │  │ (Kubernetes YAML Patch)  │ │
│ │                            │  │                          │ │
│ │ "This alert represents..." │  │ apiVersion: v1           │ │
│ │ "MITRE Technique T1234..." │  │ kind: NetworkPolicy      │ │
│ │ "Recommend immediate..."   │  │ metadata:...             │ │
│ │                            │  │ spec:...                 │ │
│ └────────────────────────────┘  └──────────────────────────┘ │
└──────────────────────────────────────────────────────────────┘
```

---

## 🔄 State Transformation Through Pipeline

```
INITIAL STATE:
┌─────────────────────────────────────────┐
│ raw_event:     {...}                    │
│ guide_score:   0.92                     │
│ guide_grade:   "TP"                     │
│ mitre_context: ""                       │ ← Empty
│ azure_context: ""                       │ ← Empty
│ final_report:  ""                       │ ← Empty
│ yaml_fix:      ""                       │ ← Empty
└─────────────────────────────────────────┘
              │
              ▼
AFTER NODE A (Router):
┌─────────────────────────────────────────┐
│ raw_event:     {...}                    │
│ guide_score:   0.92                     │
│ guide_grade:   "TP"                     │
│ mitre_context: ""                       │ ← Still empty (continues)
│ azure_context: ""                       │ ← Still empty
│ final_report:  ""                       │ ← Still empty
│ yaml_fix:      ""                       │ ← Still empty
└─────────────────────────────────────────┘
              │
              ▼
AFTER NODE B (RAG):
┌─────────────────────────────────────────┐
│ raw_event:     {...}                    │
│ guide_score:   0.92                     │
│ guide_grade:   "TP"                     │
│ mitre_context: "[T1234] Description..." │ ← FILLED
│ azure_context: "Azure guideline..."     │ ← FILLED
│ final_report:  ""                       │ ← Still empty
│ yaml_fix:      ""                       │ ← Still empty
└─────────────────────────────────────────┘
              │
              ▼
AFTER NODE C (Report):
┌─────────────────────────────────────────┐
│ raw_event:     {...}                    │
│ guide_score:   0.92                     │
│ guide_grade:   "TP"                     │
│ mitre_context: "[T1234] Description..." │
│ azure_context: "Azure guideline..."     │
│ final_report:  "This alert represents..."│ ← FILLED
│ yaml_fix:      "apiVersion: v1..."      │ ← FILLED
└─────────────────────────────────────────┘
              │
              ▼
           OUTPUT
```

---

## 📈 Performance Timeline

```
Time (ms)
0         500       1000      1500      2000      2500      3000
│─────────│─────────│─────────│─────────│─────────│─────────│
├─ Node A ┤
│ (<1ms)  │
│
│         ├──── Node B ────┤
│         │ (200-800ms)    │
│
│                      ├─────── Node C ───────┤
│                      │ (1000-3000ms)        │
│
└────────────────────────────────────────────┤
                                             │
                                      TOTAL: ~2.5s
```

---

## 🎯 Decision Tree

```
guide_grade?
│
├─ "FP" (False Positive)
│   └─→ Auto-suppress
│       └─→ final_report = "Auto-suppressed..."
│       └─→ yaml_fix = ""
│       └─→ END
│
├─ "BP" (Benign Positive)
│   └─→ Log for audit
│       └─→ mitre_context = "[AUDIT LOG]..."
│       └─→ Continue to Node B
│
├─ "TP" (True Positive)
│   └─→ Process immediately
│       └─→ Continue to Node B
│
└─ Other (Uncertain)
    │
    ├─ guide_score > 0.8
    │   └─→ Process immediately
    │       └─→ Continue to Node B
    │
    └─ guide_score ≤ 0.8
        └─→ Continue processing
            └─→ Continue to Node B
```

---

## 🧩 Component Integration

```
┌────────────────────────────────────────────────────────────┐
│ External Services                                          │
│                                                            │
│ ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│ │ Pinecone     │  │ Google AI    │  │ Classifier   │     │
│ │ Vector DB    │  │ (Gemini)     │  │ (External)   │     │
│ │              │  │              │  │              │     │
│ │ - MITRE ns   │  │ - LLM API    │  │ - raw_event  │     │
│ │ - Azure ns   │  │ - Embeddings │  │ → guide_     │     │
│ └──────────────┘  └──────────────┘  │   score,     │     │
│        ▲                   ▲        │   grade      │     │
│        │                   │        └──────────────┘     │
│        │                   │                 │            │
│        │                   │                 │            │
│        └───────────────────┴─────────────────┘            │
│                            │                               │
│                            ▼                               │
│              ┌─────────────────────────┐                  │
│              │   orchestrator.py       │                  │
│              │                         │                  │
│              │  ┌──────────────────┐   │                  │
│              │  │ Node A: Router   │   │                  │
│              │  └──────────────────┘   │                  │
│              │  ┌──────────────────┐   │                  │
│              │  │ Node B: RAG      │   │                  │
│              │  └──────────────────┘   │                  │
│              │  ┌──────────────────┐   │                  │
│              │  │ Node C: Report   │   │                  │
│              │  └──────────────────┘   │                  │
│              └─────────────────────────┘                  │
│                            │                               │
│                            ▼                               │
│              ┌─────────────────────────┐                  │
│              │   Output                │                  │
│              │   - final_report        │                  │
│              │   - yaml_fix            │                  │
│              └─────────────────────────┘                  │
└────────────────────────────────────────────────────────────┘
```

---

## 📝 Example Alert Journey

```
ALERT RECEIVED:
┌────────────────────────────────────────────┐
│ Process: runc                              │
│ Syscall: execve                            │
│ Path: /bin/sh                              │
│ Pod: vulnerable-app-7d8f9c                 │
│ Namespace: production                      │
│                                            │
│ guide_score: 0.92                          │
│ guide_grade: TP                            │
└────────────────────────────────────────────┘
                │
                ▼
NODE A: EVENT ROUTER
┌────────────────────────────────────────────┐
│ Checking grade: TP                         │
│ Decision: TRUE POSITIVE                    │
│ Action: Process immediately                │
│ Output: Continue to Node B                 │
└────────────────────────────────────────────┘
                │
                ▼
NODE B: RAG RETRIEVER
┌────────────────────────────────────────────┐
│ Query MITRE: "runc execve /bin/sh"         │
│ Results:                                   │
│  - [T1053.007] Scheduled Task/Container    │
│  - [T1548.001] Abuse Elevation Control     │
│  - [T1611] Container Escape                │
│                                            │
│ Query Azure: "Suspicious execve alert"     │
│ Results:                                   │
│  - Limit container capabilities            │
│  - Run as non-root user                    │
│                                            │
│ Output: Context filled                     │
└────────────────────────────────────────────┘
                │
                ▼
NODE C: REPORT GENERATOR
┌────────────────────────────────────────────┐
│ Building prompt with all context           │
│ Calling Gemini API...                      │
│                                            │
│ Response received (847 chars)              │
│ Extracting report... ✓                     │
│ Extracting YAML... ✓                       │
│                                            │
│ Output:                                    │
│ - final_report: "This alert indicates..."  │
│ - yaml_fix: "apiVersion: v1..."            │
└────────────────────────────────────────────┘
                │
                ▼
FINAL OUTPUT
┌────────────────────────────────────────────┐
│ REPORT:                                    │
│ This alert indicates a potential container │
│ escape attempt using runc to execute a     │
│ shell. MITRE Technique T1611 (Container    │
│ Escape) is applicable. Immediate action... │
│                                            │
│ YAML FIX:                                  │
│ apiVersion: networking.k8s.io/v1           │
│ kind: NetworkPolicy                        │
│ metadata:                                  │
│   name: restrict-vulnerable-app            │
│ spec:                                      │
│   podSelector: ...                         │
└────────────────────────────────────────────┘
```

---

**Visual Guide Version:** 1.0  
**Last Updated:** 2026-03-06  
**For:** orchestrator.py

# Sentinel-Core API Documentation

## Overview

The Sentinel-Core API is a FastAPI-based REST interface that provides access to the security orchestration platform. It exposes endpoints for analyzing security alerts, checking system health, and triggering data ingestion pipelines.

---

## Quick Start

### Installation

```bash
# Install dependencies
pip install -r api_requirements.txt

# Or install core dependencies manually
pip install fastapi uvicorn pydantic python-dotenv
```

### Environment Setup

Ensure your `.env` file contains:

```env
# Required
GOOGLE_API_KEY=your_google_api_key
PINECONE_API_KEY=pcsk_your_pinecone_key
PINECONE_ENV=your_pinecone_environment

# Optional
LLM_MODEL=gemini-1.5-pro
EMBEDDING_MODEL=google
```

### Running the Server

```bash
# Development mode (auto-reload)
python main.py

# Or with uvicorn directly
uvicorn main:app --reload --host 0.0.0.0 --port 8000

# Production mode
uvicorn main:app --host 0.0.0.0 --port 8000 --workers 4
```

---

## API Endpoints

### Root Endpoint

#### `GET /`

Welcome message and basic API information.

**Response:**
```json
{
  "message": "Welcome to Sentinel-Core Security Platform",
  "version": "1.0.0",
  "docs": "/docs",
  "health": "/health"
}
```

---

### Health Check

#### `GET /health`

Check API health status. Use this for Kubernetes liveness/readiness probes.

**Response:**
```json
{
  "status": "ok",
  "version": "1.0.0"
}
```

**Status Codes:**
- `200 OK`: API is healthy

---

### System Status (Bonus)

#### `GET /status`

Get detailed system status including component availability.

**Response:**
```json
{
  "orchestrator": "available",
  "rag_system": "available",
  "ingestor": "available",
  "version": "1.0.0",
  "healthy": true
}
```

---

### Alert Analysis

#### `POST /analyze`

Analyze a security alert and generate an incident report with remediation fix.

**Request Body:**
```json
{
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
```

**Response:**
```json
{
  "status": "TP",
  "confidence": 0.92,
  "final_report": "This alert indicates a potential container escape attempt...",
  "yaml_fix": "apiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\n...",
  "mitre_techniques": ["T1611", "T1059.007"],
  "processing_time_ms": 2847.53
}
```

**Status Codes:**
- `200 OK`: Alert analyzed successfully
- `400 Bad Request`: Invalid request data (e.g., invalid guide_grade)
- `500 Internal Server Error`: Analysis failed
- `503 Service Unavailable`: Orchestrator unavailable

**Field Validation:**
- `guide_score`: Must be between 0.0 and 1.0
- `guide_grade`: Must be one of: "TP", "BP", "FP" (case-insensitive)

**Example with cURL:**
```bash
curl -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "raw_event": {
      "process_name": "runc",
      "syscall": "execve",
      "file_path": "/bin/sh",
      "pod_name": "vulnerable-app",
      "namespace": "production",
      "user": "root",
      "pid": 12345
    },
    "guide_score": 0.92,
    "guide_grade": "TP"
  }'
```

---

### Ingestion Trigger

#### `POST /ingest/trigger`

Trigger the RAG ingestion pipeline as a background task.

This endpoint starts the ingestion of MITRE ATT&CK techniques and Azure Security Benchmark guidelines into the Pinecone vector database.

**Response:**
```json
{
  "status": "ingestion_started"
}
```

**Status Codes:**
- `200 OK`: Ingestion triggered successfully
- `500 Internal Server Error`: Failed to trigger ingestion
- `503 Service Unavailable`: Ingestor service unavailable

**Notes:**
- Runs in background using FastAPI's `BackgroundTasks`
- Returns immediately without waiting for completion
- Monitor logs for ingestion progress

**Example with cURL:**
```bash
curl -X POST http://localhost:8000/ingest/trigger
```

---

## Request Logging

All HTTP requests are automatically logged with:
- HTTP method
- Request path
- Response status code
- Processing time in milliseconds

**Example Log Output:**
```
2026-03-06 14:32:15,123 - main - INFO - POST /analyze - Status: 200 - Time: 2847.53ms
```

The response also includes an `X-Process-Time-Ms` header with the processing time.

---

## CORS Configuration

CORS is enabled for **all origins** to support frontend development.

**Current Configuration:**
- `allow_origins`: ["*"] (all origins)
- `allow_credentials`: True
- `allow_methods`: ["*"] (all methods)
- `allow_headers`: ["*"] (all headers)

⚠️ **Warning**: Restrict CORS origins in production by modifying:
```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://your-frontend.com"],  # Restrict in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

---

## Error Handling

All errors return proper HTTP status codes with JSON error messages.

**Error Response Format:**
```json
{
  "detail": "Error message describing what went wrong"
}
```

**Common Status Codes:**
- `400 Bad Request`: Invalid input data
- `500 Internal Server Error`: Server-side error
- `503 Service Unavailable`: Dependent service unavailable

---

## Interactive API Documentation

FastAPI provides automatic interactive documentation:

### Swagger UI
Access at: `http://localhost:8000/docs`

Features:
- Interactive API explorer
- Try out endpoints directly
- View request/response schemas
- Download OpenAPI spec

### ReDoc
Access at: `http://localhost:8000/redoc`

Features:
- Clean, readable documentation
- Three-column layout
- Search functionality

### OpenAPI Schema
Access at: `http://localhost:8000/openapi.json`

Download the complete OpenAPI specification for integration with other tools.

---

## Pydantic Models

### Request Models

#### RawEvent
```python
class RawEvent(BaseModel):
    process_name: str
    syscall: str
    file_path: str
    pod_name: str
    namespace: str
    user: str
    pid: int
```

#### AnalyzeRequest
```python
class AnalyzeRequest(BaseModel):
    raw_event: RawEvent
    guide_score: float  # 0.0 to 1.0
    guide_grade: str    # "TP", "BP", or "FP"
```

### Response Models

#### AnalyzeResponse
```python
class AnalyzeResponse(BaseModel):
    status: str              # "TP", "BP", or "FP"
    confidence: float        # 0.0 to 1.0
    final_report: str        # Incident report
    yaml_fix: str            # Kubernetes YAML patch
    mitre_techniques: List[str]  # MITRE technique IDs
    processing_time_ms: float    # Processing time
```

#### HealthResponse
```python
class HealthResponse(BaseModel):
    status: str
    version: str
```

---

## Startup & Shutdown Events

### Startup Sequence

When the API starts:

1. **Initialize Orchestrator**
   - Create `SentinelOrchestrator` instance
   - Log success or failure

2. **Check Pinecone Connectivity**
   - Verify Pinecone API access
   - Check if `sentinel-rag` index exists
   - Test index accessibility

3. **Log RAG System Status**
   - "RAG system ready" if all checks pass
   - "RAG system UNAVAILABLE" if any check fails

4. **Final Status**
   - Log whether API is fully functional or has limited capabilities

**Example Startup Logs:**
```
================================================================================
SENTINEL-CORE API STARTING UP
================================================================================
Initializing orchestrator...
✓ Orchestrator initialized successfully
✓ RAG system ready
================================================================================
✓ SENTINEL-CORE API READY TO SERVE REQUESTS
================================================================================
```

### Shutdown Sequence

When the API shuts down:

1. Log shutdown initiation
2. Cleanup orchestrator resources (if needed)
3. Log shutdown completion

---

## Testing

### Run Tests

```bash
# Install test dependencies
pip install pytest pytest-asyncio pytest-cov

# Run tests
pytest tests/test_api.py -v

# Run with coverage
pytest tests/test_api.py --cov=main --cov-report=html
```

### Example Test Cases

```python
import pytest
from fastapi.testclient import TestClient
from main import app

client = TestClient(app)

def test_health_check():
    """Test health endpoint returns ok status."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["version"] == "1.0.0"

def test_analyze_alert_tp():
    """Test analysis of true positive alert."""
    payload = {
        "raw_event": {
            "process_name": "runc",
            "syscall": "execve",
            "file_path": "/bin/sh",
            "pod_name": "test-pod",
            "namespace": "default",
            "user": "root",
            "pid": 12345
        },
        "guide_score": 0.92,
        "guide_grade": "TP"
    }
    
    response = client.post("/analyze", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "TP"
    assert "final_report" in data
    assert "yaml_fix" in data
    assert "processing_time_ms" in data

def test_invalid_guide_grade():
    """Test validation rejects invalid guide_grade."""
    payload = {
        "raw_event": {
            "process_name": "test",
            "syscall": "read",
            "file_path": "/tmp",
            "pod_name": "test",
            "namespace": "default",
            "user": "user",
            "pid": 1
        },
        "guide_score": 0.5,
        "guide_grade": "INVALID"  # Should be TP/BP/FP
    }
    
    response = client.post("/analyze", json=payload)
    assert response.status_code == 422  # Validation error
```

---

## Production Deployment

### Using Gunicorn with Uvicorn Workers

```bash
# Production deployment with multiple workers
gunicorn main:app \
  --workers 4 \
  --worker-class uvicorn.workers.UvicornWorker \
  --bind 0.0.0.0:8000 \
  --timeout 120 \
  --access-logfile - \
  --error-logfile -
```

### Docker Deployment

```dockerfile
FROM python:3.11-slim

WORKDIR /app

COPY api_requirements.txt .
RUN pip install --no-cache-dir -r api_requirements.txt

COPY . .

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4"]
```

### Kubernetes Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: sentinel-core-api
spec:
  replicas: 3
  selector:
    matchLabels:
      app: sentinel-core-api
  template:
    metadata:
      labels:
        app: sentinel-core-api
    spec:
      containers:
      - name: api
        image: sentinel-core-api:latest
        ports:
        - containerPort: 8000
        envFrom:
        - secretRef:
            name: sentinel-core-secrets
        livenessProbe:
          httpGet:
            path: /health
            port: 8000
          initialDelaySeconds: 10
          periodSeconds: 30
        readinessProbe:
          httpGet:
            path: /health
            port: 8000
          initialDelaySeconds: 5
          periodSeconds: 10
---
apiVersion: v1
kind: Service
metadata:
  name: sentinel-core-api
spec:
  selector:
    app: sentinel-core-api
  ports:
  - port: 80
    targetPort: 8000
  type: ClusterIP
```

---

## Monitoring & Observability

### Metrics to Monitor

- **Request Rate**: Requests per second
- **Response Time**: P50, P95, P99 latencies
- **Error Rate**: Percentage of 4xx and 5xx responses
- **Orchestrator Availability**: Check `/status` endpoint
- **RAG System Availability**: Check `/status` endpoint

### Log Aggregation

Integrate with log aggregation systems:
- **ELK Stack** (Elasticsearch, Logstash, Kibana)
- **Splunk**
- **Google Cloud Logging**
- **AWS CloudWatch**

### Health Check Integration

Use `/health` and `/status` endpoints for:
- Kubernetes liveness/readiness probes
- Load balancer health checks
- Monitoring dashboards
- Alerting systems

---

## Security Considerations

### Current Security Posture

⚠️ **No Authentication**: The API currently has no authentication layer.

### Recommended Security Enhancements

1. **Add Authentication**
   ```python
   from fastapi import Depends, HTTPException, status
   from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
   
   security = HTTPBearer()
   
   async def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
       # Validate token
       if not valid_token(credentials.credentials):
           raise HTTPException(
               status_code=status.HTTP_401_UNAUTHORIZED,
               detail="Invalid authentication credentials"
           )
       return credentials
   
   @app.post("/analyze", dependencies=[Depends(verify_token)])
   async def analyze_alert(request: AnalyzeRequest):
       ...
   ```

2. **Rate Limiting**
   ```python
   from slowapi import Limiter
   from slowapi.util import get_remote_address
   
   limiter = Limiter(key_func=get_remote_address)
   app.state.limiter = limiter
   
   @app.post("/analyze")
   @limiter.limit("10/minute")  # 10 requests per minute
   async def analyze_alert(request: Request):
       ...
   ```

3. **Input Sanitization**
   - Validate all string inputs
   - Limit string lengths
   - Sanitize file paths

4. **HTTPS/TLS**
   - Always use HTTPS in production
   - Configure TLS certificates
   - Redirect HTTP to HTTPS

---

## Troubleshooting

### Common Issues

#### Issue: "Orchestrator service is currently unavailable"

**Cause**: Orchestrator module failed to initialize  
**Solution**:
- Check that `orchestrator.py` exists
- Verify all dependencies are installed
- Check environment variables are set correctly

#### Issue: "RAG system UNAVAILABLE"

**Cause**: Pinecone connection failed  
**Solution**:
- Verify `PINECONE_API_KEY` and `PINECONE_ENV` in `.env`
- Check network connectivity to Pinecone
- Ensure `sentinel-rag` index exists

#### Issue: Slow response times (>5 seconds)

**Cause**: LLM inference is slow  
**Solution**:
- Use `gemini-1.5-flash` instead of `gemini-1.5-pro`
- Reduce `MITRE_TOP_K` and `AZURE_TOP_K` values
- Cache common queries

#### Issue: CORS errors from frontend

**Cause**: CORS not configured properly  
**Solution**:
- Verify CORS middleware is added in `main.py`
- For production, restrict `allow_origins` to your frontend domain

---

## File Structure

```
cspm-ebpf/
├── main.py                      # FastAPI application
├── api_requirements.txt         # API dependencies
├── orchestrator.py              # Orchestration module
├── ingest.py                    # Ingestion pipeline
├── config.py                    # Configuration
├── .env                         # Environment variables
└── docs/
    └── API_DOCUMENTATION.md     # This file
```

---

## API Versioning

Current version: **1.0.0**

Version is included in:
- Health check response
- Status endpoint response
- OpenAPI schema
- Root endpoint response

For future versions, consider:
- URL versioning: `/api/v1/analyze`
- Header versioning: `Accept-Version: v1`
- Query parameter versioning: `/analyze?version=v1`

---

## Support

For issues or questions:
- Check logs: `tail -f logs/api.log`
- Review API docs: `http://localhost:8000/docs`
- Check system status: `GET /status`

---

**API Version:** 1.0.0  
**Last Updated:** 2026-03-06  
**Framework:** FastAPI 0.110.0+  
**Python:** 3.11+

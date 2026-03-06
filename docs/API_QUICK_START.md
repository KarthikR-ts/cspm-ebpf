# Sentinel-Core API - Quick Start Guide

## 🚀 Get Started in 5 Minutes

### Step 1: Install Dependencies

```bash
# Navigate to project directory
cd c:\SandboxV2_0\cspm-ebpf

# Install API dependencies
pip install -r api_requirements.txt

# Or install core dependencies manually
pip install fastapi uvicorn pydantic python-dotenv
```

---

### Step 2: Configure Environment

Ensure your `.env` file has these variables:

```env
# Required
GOOGLE_API_KEY=your_google_api_key_here
PINECONE_API_KEY=pcsk_your_pinecone_key_here
PINECONE_ENV=your_pinecone_environment_here

# Optional (defaults shown)
LLM_MODEL=gemini-1.5-pro
EMBEDDING_MODEL=google
```

---

### Step 3: Run the API Server

```bash
# Development mode (auto-reload on code changes)
python main.py

# Alternative: run with uvicorn directly
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

**Expected Output:**
```
INFO:     Uvicorn running on http://0.0.0.0:8000 (Press CTRL+C to quit)
INFO:     Started reloader process [6789]
INFO:     Started server process [6791]
INFO:     Waiting for application startup.
INFO:     ✓ Orchestrator initialized successfully
INFO:     ✓ RAG system ready
INFO:     Application startup complete.
```

---

### Step 4: Test the API

#### Open Interactive Docs

Visit: **http://localhost:8000/docs**

You'll see Swagger UI with all endpoints documented.

---

#### Quick Health Check

```bash
curl http://localhost:8000/health
```

**Expected Response:**
```json
{
  "status": "ok",
  "version": "1.0.0"
}
```

---

#### Analyze a Security Alert

```bash
curl -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{
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
  }'
```

**Expected Response:**
```json
{
  "status": "TP",
  "confidence": 0.92,
  "final_report": "This alert indicates a potential container escape attempt...",
  "yaml_fix": "apiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\n...",
  "mitre_techniques": ["T1611"],
  "processing_time_ms": 2847.53
}
```

---

### Step 5: Trigger Ingestion (Optional)

```bash
curl -X POST http://localhost:8000/ingest/trigger
```

**Expected Response:**
```json
{
  "status": "ingestion_started"
}
```

---

## 📋 Common Commands

### Development Mode

```bash
# Auto-reload on code changes
python main.py

# Or with uvicorn
uvicorn main:app --reload
```

### Production Mode

```bash
# Multiple workers for production
uvicorn main:app --host 0.0.0.0 --port 8000 --workers 4

# Or with Gunicorn (recommended)
gunicorn main:app \
  --workers 4 \
  --worker-class uvicorn.workers.UvicornWorker \
  --bind 0.0.0.0:8000
```

---

## 🔍 Testing

### Run Tests

```bash
# Install test dependencies
pip install pytest pytest-asyncio pytest-cov

# Run all tests
pytest tests/test_api.py -v

# Run with coverage
pytest tests/test_api.py --cov=main --cov-report=html
```

---

## 🛠️ Troubleshooting

### Issue: "ModuleNotFoundError: No module named 'fastapi'"

**Solution:**
```bash
pip install -r api_requirements.txt
```

---

### Issue: "GOOGLE_API_KEY must be set"

**Solution:**
Add to your `.env` file:
```env
GOOGLE_API_KEY=your_actual_google_api_key
```

Then restart the server.

---

### Issue: "RAG system UNAVAILABLE"

**Solution:**
1. Check Pinecone credentials in `.env`:
   ```env
   PINECONE_API_KEY=pcsk_your_key
   PINECONE_ENV=your_environment
   ```

2. Verify network connectivity to Pinecone

3. Check if index exists:
   ```python
   from pinecone import Pinecone
   pc = Pinecone(api_key="your_key", host="your_env")
   print(pc.list_indexes().names())
   ```

---

### Issue: CORS errors from frontend

**Solution:**
The API already allows all origins for development. For production, restrict in `main.py`:

```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://your-frontend.com"],  # Change this
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

---

## 📖 Next Steps

### Explore the Documentation

- **Interactive API Docs:** http://localhost:8000/docs
- **ReDoc:** http://localhost:8000/redoc
- **OpenAPI Spec:** http://localhost:8000/openapi.json

### Read Full Documentation

- **API Documentation:** `docs/API_DOCUMENTATION.md`
- **Implementation Summary:** `docs/API_IMPLEMENTATION_SUMMARY.md`
- **Orchestrator Docs:** `docs/ORCHESTRATOR_README.md`

### Integrate with Frontend

Example JavaScript/TypeScript client:

```typescript
const API_BASE_URL = 'http://localhost:8000';

async function analyzeAlert(alertData: any) {
  const response = await fetch(`${API_BASE_URL}/analyze`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(alertData)
  });
  
  if (!response.ok) {
    throw new Error(`HTTP error! status: ${response.status}`);
  }
  
  return await response.json();
}

// Usage
const result = await analyzeAlert({
  raw_event: { /* ... */ },
  guide_score: 0.92,
  guide_grade: 'TP'
});

console.log('Analysis result:', result);
```

---

## ✅ Checklist

Before moving to production:

- [ ] All environment variables configured
- [ ] Pinecone index populated with data
- [ ] Tests passing (`pytest tests/test_api.py`)
- [ ] CORS restricted to your frontend domain
- [ ] Authentication added (if needed)
- [ ] Rate limiting configured
- [ ] HTTPS/TLS configured
- [ ] Monitoring/logging setup
- [ ] Kubernetes probes configured (if using K8s)

---

## 🎯 Quick Reference

### Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | Welcome message |
| GET | `/health` | Health check |
| GET | `/status` | System status |
| POST | `/analyze` | Analyze alert |
| POST | `/ingest/trigger` | Trigger ingestion |

### Default Port

**8000** - Change in `main.py` if needed

### Log Location

Console output (or configure file handler in `main.py`)

---

## 💡 Pro Tips

1. **Use Swagger UI for Testing**
   - Visit `/docs` and try endpoints interactively
   - No need to write curl commands

2. **Enable Debug Logging**
   ```python
   logging.basicConfig(level=logging.DEBUG)
   ```

3. **Monitor Processing Time**
   - Check `X-Process-Time-Ms` header in responses
   - Useful for performance optimization

4. **Batch Multiple Alerts**
   - Create a loop to send multiple alerts
   - Consider adding a batch endpoint for efficiency

---

## 🆘 Getting Help

### Check Logs

```bash
# Watch logs in real-time
tail -f /path/to/your/logs.log

# Or just watch console output
```

### System Status

```bash
curl http://localhost:8000/status
```

Returns detailed component availability.

### Review Documentation

- `docs/API_DOCUMENTATION.md` - Complete API guide
- `docs/ORCHESTRATOR_README.md` - Orchestrator details

---

**Quick Start Version:** 1.0  
**Last Updated:** 2026-03-06  
**API Version:** 1.0.0

#!/usr/bin/env python3
"""
Sentinel-Core Security Platform - FastAPI Application

This module provides the REST API layer for the Sentinel-Core security orchestration system.
It exposes endpoints for security alert analysis, health checks, and ingestion triggering.
"""

import os
import re
import time
import logging
import asyncio
import threading
import contextlib
import io
import secrets
import datetime
from typing import List, Optional, Dict, Any
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, HTTPException, BackgroundTasks, status, Header, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from fastapi.exceptions import RequestValidationError
from pydantic import BaseModel, Field, field_validator
import uvicorn

from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

# Import orchestrator logic
try:
    from orchestrator import analyze_alert, SentinelState
    ORCHESTRATOR_AVAILABLE = True
except ImportError as e:
    ORCHESTRATOR_AVAILABLE = False
    print(f"Warning: orchestrator module not available: {e}")

# Import ingestion logic
try:
    from ingest import SentinelIngestor
    INGESTOR_AVAILABLE = True
except ImportError as e:
    INGESTOR_AVAILABLE = False
    print(f"Warning: ingest module not available: {e}")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Rate Limiter
limiter = Limiter(key_func=get_remote_address)


# ============================================================================
# API KEY AUTHENTICATION
# ============================================================================

def verify_api_key(x_sentinel_key: Optional[str] = Header(None, alias="X-Sentinel-Key")):
    """Verify the API key if SENTINEL_API_KEY env var is set."""
    expected_key = os.getenv("SENTINEL_API_KEY")
    if not expected_key:
        return True # Dev mode: skip auth

    if not x_sentinel_key or not secrets.compare_digest(x_sentinel_key, expected_key):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key"
        )
    return True


# ============================================================================
# PYDANTIC MODELS (Request/Response Schemas)
# ============================================================================

class RawEvent(BaseModel):
    process_name: str = Field(..., description="Name of the process")
    syscall: str = Field(..., description="System call name")
    file_path: str = Field(..., description="File path accessed")
    pod_name: str = Field(..., description="Kubernetes pod name")
    namespace: str = Field(..., description="Kubernetes namespace")
    user: str = Field(..., description="User who executed the process")
    pid: int = Field(..., description="Process ID")

class AnalyzeRequest(BaseModel):
    raw_event: RawEvent
    guide_score: float = Field(..., ge=0.0, le=1.0, description="Classifier confidence score")
    guide_grade: str = Field(..., description="Classifier grade: TP, BP, or FP")
    
    @field_validator('guide_grade')
    @classmethod
    def validate_guide_grade(cls, v: str) -> str:
        allowed_grades = {"TP", "BP", "FP"}
        if v.upper() not in allowed_grades:
            raise ValueError(f"guide_grade must be one of {allowed_grades}, got '{v}'")
        return v.upper()

class AnalyzeResponse(BaseModel):
    status: str = Field(..., description="Alert status: TP, BP, or FP")
    confidence: float = Field(..., description="Classifier confidence score")
    final_report: str = Field(..., description="Security incident report")
    yaml_fix: str = Field(..., description="Kubernetes YAML remediation patch")
    mitre_techniques: List[str] = Field(default_factory=list, description="MITRE technique IDs")
    processing_time_ms: float = Field(..., description="Processing time in milliseconds")

class HealthResponse(BaseModel):
    status: str = Field(..., description="Health status")
    version: str = Field(..., description="API version")

class IngestionTriggerResponse(BaseModel):
    status: str = Field(..., description="Ingestion status")

# ============================================================================
# ERROR FORMATTER
# ============================================================================

def format_error(code: str, detail: str) -> dict:
    """Format structured error response."""
    return {
        "error": code,
        "detail": detail,
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
    }

# ============================================================================
# LIFESPAN MANAGEMENT (Startup/Shutdown Events)
# ============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("="*80)
    logger.info("SENTINEL-CORE API STARTING UP")
    logger.info("="*80)
    
    app.state.orchestrator_available = ORCHESTRATOR_AVAILABLE
    
    # Check Pinecone connectivity and RAG system status
    try:
        from pinecone import Pinecone
        from config import Config
        pc = Pinecone(api_key=Config.PINECONE_API_KEY, host=Config.PINECONE_ENV)
        index_name = "sentinel-rag"
        if index_name in pc.list_indexes().names():
            app.state.rag_available = True
        else:
            app.state.rag_available = False
    except Exception as e:
        app.state.rag_available = False
    
    yield
    
    # Shutdown
    logger.info("="*80)
    logger.info("SENTINEL-CORE API SHUTTING DOWN")
    logger.info("="*80)

# ============================================================================
# FASTAPI APPLICATION
# ============================================================================

app = FastAPI(
    title="Sentinel-Core Security Platform",
    description="Powerful security orchestration platform for real-time threat analysis and remediation.",
    version="1.0.0",
    lifespan=lifespan
)

app.state.limiter = limiter

# ============================================================================
# MIDDLEWARE
# ============================================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.middleware("http")
async def request_logging_middleware(request: Request, call_next):
    start_time = time.time()
    response = await call_next(request)
    process_time = (time.time() - start_time) * 1000
    
    logger.info(
        f"{request.method} {request.url.path} - "
        f"Status: {response.status_code} - "
        f"Time: {process_time:.2f}ms"
    )
    
    response.headers["X-Process-Time-Ms"] = str(f"{process_time:.2f}")
    return response

# ============================================================================
# EXCEPTION HANDLERS
# ============================================================================

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    code_map = {
        400: "bad_request",
        401: "unauthorized",
        403: "forbidden",
        404: "not_found",
        500: "internal_error",
        503: "service_unavailable"
    }
    short_code = code_map.get(exc.status_code, "error")
    return JSONResponse(
        status_code=exc.status_code,
        content=format_error(short_code, exc.detail)
    )

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content=format_error("bad_request", f"Validation Error: {exc.errors()}")
    )

@app.exception_handler(RateLimitExceeded)
async def custom_rate_limit_exceeded_handler(request: Request, exc: RateLimitExceeded):
    return JSONResponse(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        content=format_error("rate_limit_exceeded", f"Rate limit exceeded: {exc.detail}")
    )

@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content=format_error("internal_error", f"Internal server error: {str(exc)}")
    )

# ============================================================================
# API ENDPOINTS
# ============================================================================

@app.get("/health", response_model=HealthResponse, tags=["Health"])
async def health_check():
    return HealthResponse(status="ok", version="1.0.0")


@app.post("/analyze", response_model=AnalyzeResponse, tags=["Analysis"], dependencies=[Depends(verify_api_key)])
@limiter.limit("30/minute")
async def process_analysis(request: Request, body: AnalyzeRequest):
    """Analyze a security alert and generate incident report + remediation fix."""
    start_time = time.time()
    
    if not app.state.orchestrator_available:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Orchestrator service is currently unavailable"
        )
    
    raw_event_dict = body.raw_event.model_dump()
    raw_event_dict["process"] = raw_event_dict.pop("process_name")
    raw_event_dict["timestamp"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    raw_event_dict["alert_title"] = f"Suspicious {raw_event_dict['syscall']} from {raw_event_dict['process']}"
        
    try:
        # Run synchronous orchestrator logic in a background thread
        result = await asyncio.to_thread(
            analyze_alert,
            raw_event=raw_event_dict,
            guide_score=body.guide_score,
            guide_grade=body.guide_grade,
            stream=False
        )
        
        # Robust MITRE extraction: Tdddd or Tdddd.ddd
        mitre_pattern = r"T\d{4}(?:\.\d{3})?"
        extracted = re.findall(mitre_pattern, result.get("final_report", ""))
        mitre_techniques = list(set(extracted)) if extracted else []
        
        processing_time_ms = (time.time() - start_time) * 1000
        
        return AnalyzeResponse(
            status=result.get("guide_grade", body.guide_grade),
            confidence=result.get("guide_score", body.guide_score),
            final_report=result.get("final_report", "No report generated"),
            yaml_fix=result.get("yaml_fix", ""),
            mitre_techniques=mitre_techniques,
            processing_time_ms=processing_time_ms
        )
    except Exception as e:
        logger.error(f"Analysis failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


class AsyncStdoutQueue(io.StringIO):
    """Intercepts stdout writes and drops them onto an asyncio.Queue."""
    def __init__(self, queue: asyncio.Queue, loop: asyncio.AbstractEventLoop):
        super().__init__()
        self.queue = queue
        self.loop = loop

    def write(self, s: str):
        if not s:
            return 0
        asyncio.run_coroutine_threadsafe(self.queue.put(s), self.loop)
        return len(s)

    def flush(self):
        pass


@app.post("/analyze/stream", tags=["Analysis"], dependencies=[Depends(verify_api_key)])
@limiter.limit("30/minute")
async def process_analysis_stream(request: Request, body: AnalyzeRequest):
    """Streams the analysis report token by token using Server-Sent Events (SSE)."""
    if not app.state.orchestrator_available:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Orchestrator service is currently unavailable"
        )
        
    raw_event_dict = body.raw_event.model_dump()
    raw_event_dict["process"] = raw_event_dict.pop("process_name")
    raw_event_dict["timestamp"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    raw_event_dict["alert_title"] = f"Suspicious {raw_event_dict['syscall']} from {raw_event_dict['process']}"

    queue = asyncio.Queue()
    loop = asyncio.get_running_loop()
    
    def background_analyze():
        stdout_capture = AsyncStdoutQueue(queue, loop)
        with contextlib.redirect_stdout(stdout_capture):
            try:
                analyze_alert(
                    raw_event=raw_event_dict,
                    guide_score=body.guide_score,
                    guide_grade=body.guide_grade,
                    stream=True
                )
            except Exception as e:
                logger.error(f"Stream generation failed: {e}", exc_info=True)
        # Signal completion
        asyncio.run_coroutine_threadsafe(queue.put(None), loop)

    threading.Thread(target=background_analyze, daemon=True).start()
    
    async def sse_generator():
        while True:
            chunk = await queue.get()
            if chunk is None:
                break
            if chunk:
                # Format as Server-Sent Events
                # Clean up newlines if present inside chunks to maintain SSE protocol format
                lines = chunk.split('\n')
                for line in lines:
                    if line or len(lines) == 1:
                        yield f"data: {line}\n\n"

    return StreamingResponse(sse_generator(), media_type="text/event-stream")


@app.post("/ingest/trigger", response_model=IngestionTriggerResponse, dependencies=[Depends(verify_api_key)])
async def trigger_ingestion(background_tasks: BackgroundTasks):
    if not INGESTOR_AVAILABLE:
        raise HTTPException(status_code=503, detail="Ingestion service is not available")
        
    def run_ingestion():
        try:
            logger.info("Starting ingestion pipeline...")
            ingestor = SentinelIngestor(dry_run=False)
            ingestor.ingest_mitre("mitre_attack_v15.json")
            ingestor.ingest_azure("azure_security_benchmark.pdf")
            ingestor.print_summary()
            logger.info("Ingestion pipeline completed successfully")
        except Exception as e:
            logger.error(f"Ingestion failed: {e}", exc_info=True)
            
    background_tasks.add_task(run_ingestion)
    return IngestionTriggerResponse(status="ingestion_started")


@app.get("/status", tags=["Health"])
async def get_system_status():
    status_info = {
        "orchestrator": "available" if app.state.orchestrator_available else "unavailable",
        "rag_system": "available" if getattr(app.state, 'rag_available', False) else "unavailable",
        "ingestor": "available" if INGESTOR_AVAILABLE else "unavailable",
        "version": "1.0.0"
    }
    status_info["healthy"] = status_info["orchestrator"] == "available"
    return status_info

@app.get("/", tags=["Root"])
async def root():
    return {
        "message": "Welcome to Sentinel-Core Security Platform",
        "version": "1.0.0",
        "docs": "/docs",
        "health": "/health"
    }

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True, log_level="info", workers=1)

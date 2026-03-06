"""
Sentinel-Core Event Forwarder — Configuration

All settings are loaded from environment variables with sensible defaults.
"""

import os


class Config:
    """Central configuration loaded from environment variables."""

    # ── Tetragon ──────────────────────────────────────────────────
    TETRAGON_GRPC_ADDRESS: str = os.getenv("TETRAGON_GRPC_ADDRESS", "localhost:54321")
    TETRA_BIN: str = os.getenv("TETRA_BIN", "tetra")

    # ── Redis ─────────────────────────────────────────────────────
    REDIS_HOST: str = os.getenv("REDIS_HOST", "localhost")
    REDIS_PORT: int = int(os.getenv("REDIS_PORT", "6379"))
    REDIS_DB: int = int(os.getenv("REDIS_DB", "0"))
    REDIS_PASSWORD: str | None = os.getenv("REDIS_PASSWORD")
    REDIS_STREAM_KEY: str = os.getenv("REDIS_STREAM_KEY", "sentinel:events")
    REDIS_MAXLEN: int = int(os.getenv("REDIS_MAXLEN", "10000"))

    # ── Forwarder ─────────────────────────────────────────────────
    EVENT_BUFFER_SIZE: int = int(os.getenv("EVENT_BUFFER_SIZE", "100"))
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")

    # ── API Server ────────────────────────────────────────────────
    API_HOST: str = os.getenv("API_HOST", "0.0.0.0")
    API_PORT: int = int(os.getenv("API_PORT", "8081"))

    # ── ML Triage ─────────────────────────────────────────────────
    ML_MODEL_PATH: str = os.getenv("ML_MODEL_PATH", "forwarder/model/xgboost_model.json")
    FEATURE_LIST_PATH: str = os.getenv("FEATURE_LIST_PATH", "forwarder/model/feature_list.json")

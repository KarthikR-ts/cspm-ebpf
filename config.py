"""
config.py

Configuration settings for the Sentinel-Core Security AI Platform
Document Ingestion Script.
"""

import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

class Config:
    """Configuration variables mapped from the environment."""
    
    # Pinecone coordinates
    PINECONE_API_KEY = os.getenv("PINECONE_API_KEY")
    PINECONE_ENV = os.getenv("PINECONE_ENV")

    # Embedding provider selection ("google" or "openai")
    EMBEDDING_MODEL = os.getenv("EMBEDDING_MODEL", "google")
    
    # Provider API Keys
    GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")
    OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

    # Specific embedding models
    GOOGLE_EMBEDDING_MODEL = "models/embedding-004"
    OPENAI_EMBEDDING_MODEL = "text-embedding-3-small"

# Validation checks to ensure script can safely run
if not Config.PINECONE_API_KEY or not Config.PINECONE_ENV:
    raise ValueError("Missing required environment variables: PINECONE_API_KEY and PINECONE_ENV")

if Config.EMBEDDING_MODEL == "google" and not Config.GOOGLE_API_KEY:
    raise ValueError("GOOGLE_API_KEY must be set when EMBEDDING_MODEL is 'google'")
elif Config.EMBEDDING_MODEL == "openai" and not Config.OPENAI_API_KEY:
    raise ValueError("OPENAI_API_KEY must be set when EMBEDDING_MODEL is 'openai'")

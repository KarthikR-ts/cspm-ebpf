#!/usr/bin/env python3
"""
Sentinel-Core Security AI Platform - Document Ingestion Script

This script ingests security knowledge from two sources:
1. MITRE ATT&CK techniques (JSON format)
2. Azure Security Benchmark (PDF format)

It chunks, embeds, and upserts the data into Pinecone for RAG-based retrieval.
"""

import json
import logging
import argparse
import hashlib
import sys
from pathlib import Path
from typing import List, Dict, Any

from pinecone import Pinecone
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain_community.document_loaders import PyPDFLoader
import google.generativeai as genai
from openai import OpenAI

from config import Config

# Configure structured logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class SentinelIngestor:
    """
    Handles the ingestion pipeline for security documents into Pinecone.
    """
    
    def __init__(self, dry_run: bool = False):
        self.dry_run = dry_run
        
        self.pc = Pinecone(
            api_key=Config.PINECONE_API_KEY,
            host=Config.PINECONE_ENV
        )
        
        self.embedding_provider = Config.EMBEDDING_MODEL.lower()
        
        if self.embedding_provider == "google":
            genai.configure(api_key=Config.GOOGLE_API_KEY)
        elif self.embedding_provider == "openai":
            self.openai_client = OpenAI(api_key=Config.OPENAI_API_KEY)
        else:
            raise ValueError(f"Unsupported EMBEDDING_MODEL: {self.embedding_provider}")

        self.stats = {
            "mitre": {"loaded": 0, "embedded": 0, "upserted": 0, "skipped": 0},
            "azure": {"loaded": 0, "embedded": 0, "upserted": 0, "skipped": 0}
        }
    
    def generate_id(self, text: str) -> str:
        """Generate a deterministic ID based on the MD5 hash of the chunk text."""
        return hashlib.md5(text.encode('utf-8')).hexdigest()
    
    def load_mitre_json(self, file_path: str) -> List[Dict[str, Any]]:
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"MITRE ATT&CK file not found: {file_path}")
        
        logger.info(f"Loading MITRE ATT&CK from {file_path}...")
        
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        if isinstance(data, list):
            techniques = data
        elif isinstance(data, dict) and 'techniques' in data:
            techniques = data['techniques']
        else:
            raise ValueError(
                "Invalid MITRE JSON format: expected list or dict with 'techniques' key"
            )
        
        valid_techniques = []
        for tech in techniques:
            if all(k in tech for k in ['technique_id', 'name', 'description', 'tactic']):
                valid_techniques.append(tech)
            else:
                logger.warning(f"Skipping technique missing required fields: {tech.get('technique_id', 'UNKNOWN')}")
        
        self.stats["mitre"]["loaded"] = len(valid_techniques)
        logger.info(f"Loaded {len(valid_techniques)} MITRE techniques")
        
        return valid_techniques
    
    def load_azure_pdf(self, file_path: str) -> List[str]:
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"Azure Security Benchmark PDF not found: {file_path}")
        
        logger.info(f"Loading Azure Security Benchmark from {file_path}...")
        
        loader = PyPDFLoader(str(path))
        documents = loader.load()
        
        text_splitter = RecursiveCharacterTextSplitter(
            chunk_size=800,
            chunk_overlap=100,
            length_function=len,
            separators=["\n\n", "\n", ". ", " ", ""]
        )
        
        chunks = text_splitter.split_documents(documents)
        chunk_texts = [chunk.page_content for chunk in chunks]
        
        self.stats["azure"]["loaded"] = len(chunk_texts)
        logger.info(f"Created {len(chunk_texts)} Azure PDF chunks")
        
        return chunk_texts
    
    def chunk_mitre_techniques(self, techniques: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        logger.info("Formatting MITRE techniques into chunks...")
        
        chunks = []
        for tech in techniques:
            chunk_text = (
                f"Technique {tech['technique_id']} - {tech['name']} | "
                f"Tactic: {tech['tactic']} | {tech['description']}"
            )
            
            chunks.append({
                "text": chunk_text,
                "technique_id": tech['technique_id'],
                "name": tech['name'],
                "tactic": tech['tactic']
            })
        
        self.stats["mitre"]["embedded"] = len(chunks)
        logger.info(f"Formatted {len(chunks)} MITRE chunks")
        
        return chunks
    
    def generate_embeddings(self, texts: List[str]) -> List[List[float]]:
        batch_size = 100
        all_embeddings = []
        
        for i in range(0, len(texts), batch_size):
            batch = texts[i:i + batch_size]
            
            if self.embedding_provider == "google":
                response = genai.embed_content(
                    model=Config.GOOGLE_EMBEDDING_MODEL,
                    content=batch,
                    task_type="retrieval_document"
                )
                batch_embeddings = response['embedding']
            else:
                response = self.openai_client.embeddings.create(
                    input=batch,
                    model=Config.OPENAI_EMBEDDING_MODEL
                )
                batch_embeddings = [item.embedding for item in response.data]
                
            all_embeddings.extend(batch_embeddings)
            
            processed = min(i + batch_size, len(texts))
            logger.info(f"Embedded {processed}/{len(texts)} texts...")
        
        return all_embeddings
    
    def upsert_to_pinecone(
        self, 
        index_name: str, 
        namespace: str, 
        chunks: List[Dict[str, Any]], 
        embeddings: List[List[float]]
    ) -> None:
        logger.info(f"Upserting to Pinecone index '{index_name}', namespace '{namespace}'...")
        
        if self.dry_run:
            logger.info(f"[DRY-RUN] Skipping index creation/check for '{index_name}'")
        else:
            if index_name not in self.pc.list_indexes().names():
                logger.info(f"Creating new index: {index_name}")
                dimension = 768 if self.embedding_provider == "google" else 1536
                self.pc.create_index(
                    name=index_name,
                    dimension=dimension,
                    metric="cosine"
                )
        
        index = None if self.dry_run else self.pc.Index(index_name)
        
        vectors = []
        for chunk, embedding in zip(chunks, embeddings):
            vector_id = self.generate_id(chunk["text"])
            
            metadata = {
                "source": namespace,
                "text": chunk["text"]
            }
            if namespace == "mitre":
                metadata.update({
                    "technique_id": chunk.get("technique_id"),
                    "name": chunk.get("name"),
                    "tactic": chunk.get("tactic")
                })
                
            vectors.append({
                "id": vector_id,
                "values": embedding,
                "metadata": metadata
            })
        
        batch_size = 100
        upserted_count = 0
        skipped_count = 0
        
        for i in range(0, len(vectors), batch_size):
            batch = vectors[i:i + batch_size]
            batch_ids = [v["id"] for v in batch]
            
            if not self.dry_run:
                # Check idempotency
                fetch_response = index.fetch(ids=batch_ids, namespace=namespace)
                existing_ids = set(fetch_response.get('vectors', {}).keys())
                
                vectors_to_upsert = [v for v in batch if v["id"] not in existing_ids]
                
                skipped = len(batch) - len(vectors_to_upsert)
                skipped_count += skipped
                
                if vectors_to_upsert:
                    index.upsert(vectors=vectors_to_upsert, namespace=namespace)
                    upserted_count += len(vectors_to_upsert)
            else:
                logger.info(f"[DRY-RUN] Would fetch and potentially upsert batch of {len(batch)} vectors.")
                vectors_to_upsert = batch
                skipped = 0
                upserted_count += len(batch)
            
            processed = min(i + batch_size, len(vectors))
            logger.info(f"Processed {processed}/{len(vectors)} vectors (Upserted: {len(vectors_to_upsert)}, Skipped: {skipped})...")
        
        self.stats[namespace]["upserted"] += upserted_count
        self.stats[namespace]["skipped"] += skipped_count
    
    def ingest_mitre(self, json_path: str, index_name: str = "sentinel-rag") -> None:
        logger.info("="*60)
        logger.info("MITRE ATT&CK Ingestion Pipeline")
        logger.info("="*60)
        
        techniques = self.load_mitre_json(json_path)
        chunks = self.chunk_mitre_techniques(techniques)
        texts = [chunk["text"] for chunk in chunks]
        
        logger.info("Generating embeddings for MITRE chunks...")
        embeddings = self.generate_embeddings(texts)
        
        self.upsert_to_pinecone(
            index_name=index_name,
            namespace="mitre",
            chunks=chunks,
            embeddings=embeddings
        )
        
        logger.info("MITRE ingestion complete")
    
    def ingest_azure(self, pdf_path: str, index_name: str = "sentinel-rag") -> None:
        logger.info("="*60)
        logger.info("Azure Security Benchmark Ingestion Pipeline")
        logger.info("="*60)
        
        chunk_texts = self.load_azure_pdf(pdf_path)
        chunks = [{"text": text} for text in chunk_texts]
        
        logger.info("Generating embeddings for Azure chunks...")
        embeddings = self.generate_embeddings(chunk_texts)
        
        self.upsert_to_pinecone(
            index_name=index_name,
            namespace="azure",
            chunks=chunks,
            embeddings=embeddings
        )
        
        logger.info("Azure ingestion complete")
    
    def print_summary(self) -> None:
        logger.info("="*60)
        logger.info("INGESTION SUMMARY")
        logger.info("="*60)
        
        for source in ["mitre", "azure"]:
            stats = self.stats[source]
            logger.info(f"{source.upper()}:")
            logger.info(f"  Loaded:    {stats['loaded']}")
            logger.info(f"  Embedded:  {stats['embedded']}")
            logger.info(f"  Upserted:  {stats['upserted']}")
            logger.info(f"  Skipped:   {stats['skipped']}")
        
        total_upserted = sum(s["upserted"] for s in self.stats.values())
        logger.info(f"TOTAL VECTORS IN PINECONE (or processed if dry-run): {total_upserted}")
        logger.info("="*60)


def main():
    parser = argparse.ArgumentParser(description="Sentinel-Core Security AI Platform - Document Ingestion Script")
    parser.add_argument("mitre_path", nargs="?", default="mitre_attack_v15.json", help="Path to MITRE JSON file")
    parser.add_argument("azure_path", nargs="?", default="azure_security_benchmark.pdf", help="Path to Azure PDF file")
    parser.add_argument("--dry-run", action="store_true", help="Process and log but do not upsert to Pinecone")
    args = parser.parse_args()
    
    logger.info("Starting Sentinel-Core Ingestion Pipeline")
    logger.info(f"MITRE file: {args.mitre_path}")
    logger.info(f"Azure file: {args.azure_path}")
    
    if args.dry_run:
        logger.info("DRY-RUN MODE ENABLED - No changes will be made to Pinecone")
    
    try:
        ingestor = SentinelIngestor(dry_run=args.dry_run)
        
        ingestor.ingest_mitre(args.mitre_path)
        ingestor.ingest_azure(args.azure_path)
        
        ingestor.print_summary()
        
        logger.info("Ingestion completed successfully!")
        
    except FileNotFoundError as e:
        logger.error(f"FILE NOT FOUND: {e}")
        logger.error("Make sure your data files exist.")
        sys.exit(1)
        
    except json.JSONDecodeError as e:
        logger.error(f"INVALID JSON: {e}")
        logger.error("Check that your MITRE ATT&CK file is valid JSON.")
        sys.exit(1)
        
    except ValueError as e:
        logger.error(f"CONFIGURATION ERROR: {e}")
        sys.exit(1)
        
    except Exception as e:
        logger.error(f"UNEXPECTED ERROR: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()

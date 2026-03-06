import json
import logging
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
import xgboost as xgb

logger = logging.getLogger("sentinel.ml_triage")

class MLTriage:
    """Handles ML-based triage for Sentinel events."""

    def __init__(self, model_path: Path, feature_list_path: Path):
        self.model_path = model_path
        self.feature_list_path = feature_list_path
        self.model = None
        self.features = []
        self.label_map = {}
        self.reverse_label_map = {}
        
        self._load_resources()

    def _load_resources(self):
        """Load the model and feature/label metadata."""
        if not self.model_path.exists():
            logger.warning("ML model not found at %s. Triage will be disabled.", self.model_path)
            return

        try:
            # Load model
            self.model = xgb.XGBClassifier()
            self.model.load_model(str(self.model_path))
            logger.info("✅ ML model loaded from %s", self.model_path)

            # Load feature list and labels
            if self.feature_list_path.exists():
                with open(self.feature_list_path, "r") as f:
                    data = json.load(f)
                    self.features = data.get("features", [])
                    self.label_map = data.get("labels", {})
                    self.reverse_label_map = {v: k for k, v in self.label_map.items()}
                logger.info("✅ Feature list loaded: %s", self.features)
            else:
                logger.warning("Feature list not found. Using defaults.")
                self.features = ["id", "feature_1", "feature_2", "category"]
                self.label_map = {"FalsePositive": 0, "BenignPositive": 1, "TruePositive": 2}
                self.reverse_label_map = {v: k for k, v in self.label_map.items()}

        except Exception as e:
            logger.error("❌ Failed to load ML resources: %s", e)
            self.model = None

    def triage_event(self, event: dict[str, Any]) -> dict[str, Any]:
        """
        Predict triage status for a Sentinel event.
        Returns a dict with triage results.
        """
        if self.model is None:
            return {
                "triage": None,
                "explanation": "ML Triage disabled (model not loaded).",
            }

        try:
            # Prepare features for inference
            feature_data = self._prepare_features(event)
            
            # Create DataFrame for XGBoost (ensures feature order and types)
            X = pd.DataFrame([feature_data], columns=self.features)
            
            # Ensure categorical columns are handled if model expects them
            # (XGBoost native categorical support)
            for col in X.columns:
                if self.features.index(col) == 3: # Assuming 'category' is the only categorical one based on feature_types in JSON
                    X[col] = X[col].astype("category")

            # Predict
            probs = self.model.predict_proba(X)[0]
            prediction = int(np.argmax(probs))
            confidence = float(np.max(probs))

            grade_map = {
                "FalsePositive": "FP",
                "BenignPositive": "BP",
                "TruePositive": "TP"
            }
            grade = grade_map.get(status, "TP") # Default to TP if unknown
            
            # Formatted explanation (as an object per unified schema)
            # Note: MITRE ID is placeholder until Advisor RAG confirms it
            explanation_obj = {
                "mitre_id": "N/A", 
                "guidance": explanation
            }

            return {
                "triage": {
                    "grade": grade,
                    "confidence": round(confidence, 2)
                },
                "explanation": explanation_obj,
                "deliverable": f"This event is a {confidence*100:.0f}% {status_formatted}."
            }

        except Exception as e:
            logger.error("Triage prediction failed: %s", e)
            return {
                "triage": "Error",
                "explanation": f"ML Triage failed: {str(e)}",
            }

    def _prepare_features(self, event: dict[str, Any]) -> dict[str, Any]:
        """Map Sentinel event fields to ML features."""
        telemetry = event.get("telemetry", {})
        
        # This is a best-effort mapping to the placeholder features in the model
        # id, feature_1, feature_2, category
        
        # We'll use:
        # id: Hash of binary name
        # feature_1: UID
        # feature_2: PID
        # category: Event Type (index-based)
        
        binary_name = telemetry.get("binary", "unknown")
        event_id_val = hash(binary_name) % 1000
        
        # Categorical mapping for 'category'
        # Model JSON showed values 65, 66, 67 (A, B, C)
        # We'll map our event types to these
        cat_map = {
            "process_exec": 65, 
            "process_kprobe": 66,
            "process_exit": 67
        }
        category_val = cat_map.get(event.get("event_type", ""), 65)

        return {
            "id": event_id_val,
            "feature_1": float(telemetry.get("uid", 0)),
            "feature_2": float(telemetry.get("pid", 0)),
            "category": category_val
        }

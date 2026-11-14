"""
SMVITM MorphPot: Machine Learning Threat Detector Module
--------------------------------------------------------
Loads the trained ML model & TF-IDF vectorizer to perform
sub-millisecond real-time payload classification.
"""

import os
import joblib

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODELS_DIR = os.path.join(BASE_DIR, "models")

MODEL_PATH = os.path.join(MODELS_DIR, "best_honeypot_model.joblib")
VEC_PATH = os.path.join(MODELS_DIR, "tfidf_vectorizer.joblib")

class MLThreatDetector:
    def __init__(self):
        self.model = None
        self.vectorizer = None
        self.is_ready = False
        self._load()

    def _load(self):
        try:
            if os.path.exists(MODEL_PATH) and os.path.exists(VEC_PATH):
                self.model = joblib.load(MODEL_PATH)
                self.vectorizer = joblib.load(VEC_PATH)
                self.is_ready = True
                print("[ML Detector] Best trained model (SVM) loaded successfully into memory.")
        except Exception as e:
            print(f"[ML Detector Notice] Could not load ML model: {e}")
            self.is_ready = False

    def predict(self, text):
        """
        Classifies incoming HTTP payload into:
        ['Benign', 'SQL_Injection', 'Path_Traversal', 'Brute_Force', 'XSS_Probe']
        Returns (predicted_class, is_malicious)
        """
        if not self.is_ready or not text:
            return "Benign", False

        try:
            vec = self.vectorizer.transform([text])
            pred = self.model.predict(vec)[0]
            is_malicious = pred != "Benign"
            return pred, is_malicious
        except Exception:
            return "Benign", False

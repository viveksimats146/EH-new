import os
import pickle
from pathlib import Path
from typing import Optional
from backend import config

class MLDetector:
    """
    Local Scikit-Learn ML Classifier using TF-IDF character/word n-grams and Logistic Regression.
    Loads cached model if present; otherwise trains locally on initial load.
    Falls back gracefully if dependencies or models are unavailable.
    """

    def __init__(self):
        self.model = None
        self.vectorizer = None
        self.is_loaded = False
        self._initialize_model()

    def _initialize_model(self):
        """Loads model from disk or trains a new one using local dataset."""
        try:
            if config.MODEL_FILE_PATH.exists() and config.VECTORIZER_FILE_PATH.exists():
                with open(config.MODEL_FILE_PATH, "rb") as mf:
                    self.model = pickle.load(mf)
                with open(config.VECTORIZER_FILE_PATH, "rb") as vf:
                    self.vectorizer = pickle.load(vf)
                self.is_loaded = True
            else:
                self.train_and_save()
        except Exception as e:
            print(f"[MLDetector Warning] Could not initialize ML model: {e}. Falling back to 100% Rule Engine.")
            self.is_loaded = False

    def train_and_save(self) -> bool:
        """Trains model on dataset/ CSV files and saves pkl files locally."""
        try:
            import pandas as pd
            from sklearn.feature_extraction.text import TfidfVectorizer
            from sklearn.linear_model import LogisticRegression

            if not (config.NORMAL_CSV.exists() and config.SQLI_CSV.exists()):
                return False

            df_normal = pd.read_csv(config.NORMAL_CSV)
            df_sqli = pd.read_csv(config.SQLI_CSV)

            df = pd.concat([df_normal, df_sqli], ignore_index=True)
            df['query'] = df['query'].astype(str)

            vectorizer = TfidfVectorizer(analyzer='char', ngram_range=(2, 5))
            X = vectorizer.fit_transform(df['query'])
            y = df['label']

            model = LogisticRegression(C=1.0, max_iter=1000)
            model.fit(X, y)

            config.MODEL_DIR.mkdir(parents=True, exist_ok=True)
            with open(config.MODEL_FILE_PATH, "wb") as mf:
                pickle.dump(model, mf)
            with open(config.VECTORIZER_FILE_PATH, "wb") as vf:
                pickle.dump(vectorizer, vf)

            self.model = model
            self.vectorizer = vectorizer
            self.is_loaded = True
            return True
        except Exception as e:
            print(f"[MLDetector Train Warning] Training failed: {e}")
            self.is_loaded = False
            return False

    def predict_probability(self, text: str) -> Optional[float]:
        """
        Returns probability (0.0 to 1.0) of input being SQL injection.
        Returns None if ML model is unavailable.
        """
        if not self.is_loaded or self.model is None or self.vectorizer is None:
            return None

        try:
            X = self.vectorizer.transform([text])
            probs = self.model.predict_proba(X)[0]
            # Class 1 is SQL injection
            return float(probs[1])
        except Exception:
            return None

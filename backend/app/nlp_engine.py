import joblib
import os

class NLPEngine:
    def __init__(self):
        vec_path = "app/vectorizer.pkl"
        model_path = "app/model.pkl"
        
        if os.path.exists(vec_path) and os.path.exists(model_path):
            self.vectorizer = joblib.load(vec_path)
            self.model = joblib.load(model_path)
            self.ready = True
            print("[+] Tier-2 NLP Inference Engine Loaded.")
        else:
            self.ready = False

    def predict(self, url: str):
        if not self.ready:
            return "UNKNOWN", 0.0

        features = self.vectorizer.transform([url])
        prob = self.model.predict_proba(features)[0][1]
        verdict = "MALICIOUS" if prob > 0.5 else "SAFE"
        return verdict, round(float(prob), 4)

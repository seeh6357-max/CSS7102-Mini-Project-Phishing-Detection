import joblib
import os
import math
import numpy as np
from Levenshtein import distance as lev_distance

class AdvancedNLPEngine:
    def __init__(self):
        vec_path = "app/vectorizer.pkl"
        scaler_path = "app/scaler.pkl"
        model_path = "app/model.pkl"
        self.target_brands = ["paypal", "google", "microsoft", "apple", "amazon", "bankofamerica", "netflix", "presidencyuniversity"]
        
        if os.path.exists(vec_path) and os.path.exists(scaler_path) and os.path.exists(model_path):
            self.vectorizer = joblib.load(vec_path)
            self.scaler = joblib.load(scaler_path)
            self.model = joblib.load(model_path)
            self.ready = True
            print("[+] Tier-2 Advanced NLP Engine Online.")
        else:
            self.ready = False
            print("[-] NLP Engine Error: Missing Model Artifacts.")

    def _calculate_entropy(self, text: str) -> float:
        if not text:
            return 0.0
        prob = [float(text.count(c)) / len(text) for c in set(text)]
        return -sum([p * math.log(p, 2) for p in prob])

    def _extract_lexical_features(self, url: str):
        url_str = url.lower()
        url_length = len(url_str)
        num_digits = sum(c.isdigit() for c in url_str)
        digit_ratio = num_digits / url_length if url_length > 0 else 0
        
        num_special = sum(not c.isalnum() for c in url_str)
        special_ratio = num_special / url_length if url_length > 0 else 0
        
        num_subdomains = url_str.count(".") - 1
        has_ip = 1 if any(char.isdigit() for char in url_str.split("/")[0]) and url_str.count(".") == 3 else 0
        
        entropy = self._calculate_entropy(url_str)
        domain = url_str.split("://")[-1].split("/")[0]
        distances = [lev_distance(domain, brand) for brand in self.target_brands]
        brand_dist = min(distances) if distances else 999

        return np.array([[
            url_length, digit_ratio, special_ratio, num_subdomains, has_ip, entropy, brand_dist
        ]])

    def predict(self, url: str):
        if not self.ready:
            return "UNKNOWN", 0.0

        tfidf_feat = self.vectorizer.transform([url]).toarray()
        lex_feat = self._extract_lexical_features(url)
        lex_scaled = self.scaler.transform(lex_feat)

        combined_features = np.hstack((tfidf_feat, lex_scaled))
        prob = self.model.predict_proba(combined_features)[0][1]
        
        if prob >= 0.80:
            verdict = "MALICIOUS"
        elif prob >= 0.50:
            verdict = "SUSPICIOUS"
        else:
            verdict = "SAFE"

        return verdict, round(float(prob), 4)

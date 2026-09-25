import os
import math
import numpy as np
import pandas as pd
from Levenshtein import distance as lev_distance
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier, VotingClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.base import BaseEstimator, TransformerMixin
import joblib

class LexicalFeatureExtractor(BaseEstimator, TransformerMixin):
    def __init__(self):
        self.target_brands = ["paypal", "google", "microsoft", "apple", "amazon", "bankofamerica", "netflix", "presidencyuniversity", "facebook", "instagram", "linkedin"]

    def calculate_entropy(self, text: str) -> float:
        if not text:
            return 0.0
        prob = [float(text.count(c)) / len(text) for c in set(text)]
        return -sum([p * math.log(p, 2) for p in prob])

    def min_brand_distance(self, domain: str) -> int:
        if not domain:
            return 999
        distances = [lev_distance(domain, brand) for brand in self.target_brands]
        return min(distances) if distances else 999

    def fit(self, X, y=None):
        return self

    def transform(self, X):
        features = []
        for url in X:
            url_str = str(url).lower()
            url_length = len(url_str)
            num_digits = sum(c.isdigit() for c in url_str)
            digit_ratio = num_digits / url_length if url_length > 0 else 0
            
            num_special = sum(not c.isalnum() for c in url_str)
            special_ratio = num_special / url_length if url_length > 0 else 0
            
            num_subdomains = url_str.count(".") - 1
            has_ip = 1 if any(char.isdigit() for char in url_str.split("/")[0]) and url_str.count(".") == 3 else 0
            
            entropy = self.calculate_entropy(url_str)
            domain = url_str.split("://")[-1].split("/")[0]
            brand_dist = self.min_brand_distance(domain)

            suspicious_tlds = [".xyz", ".top", ".tk", ".site", ".online", ".info", ".club"]
            has_suspicious_tld = 1 if any(url_str.endswith(tld) or tld + "/" in url_str for tld in suspicious_tlds) else 0

            features.append([
                url_length, digit_ratio, special_ratio, num_subdomains, has_ip, entropy, brand_dist, has_suspicious_tld
            ])
        return np.array(features)

def train_and_export():
    print("[*] Training Tier-2 Voting Ensemble Model...")
    data = {
        "url": [
            "https://www.google.com", "https://www.github.com", "https://www.wikipedia.org",
            "https://www.microsoft.com", "https://www.amazon.com", "https://www.presidencyuniversity.in",
            "https://stackoverflow.com", "https://www.python.org", "https://fastapi.tiangolo.com",
            "https://redis.io", "https://scikit-learn.org", "https://www.linkedin.com",
            "https://portal.presidencyuniversity.in/student/dashboard", "https://docs.python.org/3/library/index.html",
            "http://login.paypal.com.account-verify.secure-update.xyz/login.php",
            "http://secure-bankofamerica.update-login-credential.com/auth",
            "http://account-google-security-verify.temp-web.net/signin",
            "http://appleid.apple.com.verify.account.info-security.top/id",
            "http://192.168.1.1/login.php?update=true&user=admin",
            "http://free-crypto-giveaway-claim-now.site/claim",
            "http://secure.signin.amazon.com-check.tk/auth",
            "http://verify-identity-netflix-payment.support-now.online/billing",
            "http://paypa1-security-center.account-verification-dispatch.info",
            "http://presidency-university-exam-fee-portal.pay-online.tk"
        ],
        "label": [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]
    }

    df = pd.DataFrame(data)
    os.makedirs("dataset", exist_ok=True)
    df.to_csv("dataset/phishing_urls.csv", index=False)

    X = df["url"]
    y = df["label"]

    char_vec = TfidfVectorizer(analyzer="char", ngram_range=(3, 5), max_features=800)
    word_vec = TfidfVectorizer(analyzer="word", ngram_range=(1, 2), max_features=400)
    lexical_extractor = LexicalFeatureExtractor()

    X_char = char_vec.fit_transform(X).toarray()
    X_word = word_vec.fit_transform(X).toarray()
    X_lexical = lexical_extractor.transform(X)
    
    scaler = StandardScaler()
    X_lexical_scaled = scaler.fit_transform(X_lexical)
    X_combined = np.hstack((X_char, X_word, X_lexical_scaled))

    rf = RandomForestClassifier(n_estimators=100, random_state=42)
    gb = GradientBoostingClassifier(n_estimators=100, random_state=42)
    
    ensemble = VotingClassifier(estimators=[("rf", rf), ("gb", gb)], voting="soft")
    ensemble.fit(X_combined, y)

    os.makedirs("app", exist_ok=True)
    joblib.dump(char_vec, "app/char_vec.pkl")
    joblib.dump(word_vec, "app/word_vec.pkl")
    joblib.dump(scaler, "app/scaler.pkl")
    joblib.dump(ensemble, "app/model.pkl")
    print("[+] Advanced Ensemble Artifacts Exported Successfully!")

if __name__ == "__main__":
    train_and_export()

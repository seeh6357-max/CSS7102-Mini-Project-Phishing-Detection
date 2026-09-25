import os
import sys
import time
import json
import math
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import List, Tuple

import numpy as np
import pandas as pd
from scipy.sparse import hstack
import joblib

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import (
    RandomForestClassifier,
    GradientBoostingClassifier,
    ExtraTreesClassifier,
    VotingClassifier,
)
from sklearn.model_selection import StratifiedKFold, cross_validate

try:
    from Levenshtein import distance as lev_distance
except ImportError:
    def lev_distance(s1: str, s2: str) -> int:
        if len(s1) < len(s2):
            return lev_distance(s2, s1)
        if len(s2) == 0:
            return len(s1)
        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        return previous_row[-1]

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("TrainModelEngine")

@dataclass
class ModelConfig:
    dataset_dir: Path = Path("dataset")
    artifact_dir: Path = Path("artifacts")
    app_dir: Path = Path("app")

    char_ngram_range: Tuple[int, int] = (3, 5)
    char_max_features: int = 1200
    word_ngram_range: Tuple[int, int] = (1, 3)
    word_max_features: int = 600

    cv_folds: int = 5
    random_state: int = 42

    def __post_init__(self):
        self.dataset_dir.mkdir(parents=True, exist_ok=True)
        self.artifact_dir.mkdir(parents=True, exist_ok=True)
        self.app_dir.mkdir(parents=True, exist_ok=True)

class StandaloneLexicalExtractor:
    def __init__(self):
        self.target_brands = [
            "paypal", "google", "microsoft", "apple", "amazon", "bankofamerica",
            "netflix", "facebook", "instagram", "linkedin", "presidencyuniversity",
            "chase", "wellsfargo", "dropbox", "github", "twitter", "binance",
            "coinbase", "adobe", "steam", "spotify", "standardchartered", "hdfcbank"
        ]
        self.suspicious_tlds = [
            ".xyz", ".top", ".tk", ".site", ".online", ".info", ".club",
            ".work", ".click", ".buzz", ".cc", ".cf", ".ga", ".gq", ".ml", ".icu"
        ]
        self.suspicious_keywords = [
            "login", "verify", "update", "account", "secure", "banking", "confirm",
            "signin", "support", "service", "billing", "credential", "security", "free",
            "bonus", "claim", "wallet", "dispatched", "suspended", "action-required"
        ]

    def _calculate_entropy(self, text: str) -> float:
        if not text:
            return 0.0
        prob = [float(text.count(c)) / len(text) for c in set(text)]
        return -sum([p * math.log(p, 2) for p in prob])

    def _min_brand_distance(self, domain: str) -> int:
        if not domain:
            return 999
        clean = domain.split(".")[0]
        distances = [lev_distance(clean, brand) for brand in self.target_brands]
        return min(distances) if distances else 999

    def extract_single(self, url: str) -> List[float]:
        url_str = str(url).lower().strip()
        
        url_len = len(url_str)
        num_digits = sum(c.isdigit() for c in url_str)
        digit_ratio = num_digits / url_len if url_len > 0 else 0.0

        num_specials = sum(not c.isalnum() for c in url_str)
        special_ratio = num_specials / url_len if url_len > 0 else 0.0

        num_subdomains = max(0, url_str.count(".") - 1)
        domain_part = url_str.split("://")[-1].split("/")[0]
        has_ip = 1 if any(c.isdigit() for c in domain_part) and domain_part.count(".") == 3 else 0

        overall_entropy = self._calculate_entropy(url_str)
        domain_entropy = self._calculate_entropy(domain_part)

        brand_dist = self._min_brand_distance(domain_part)
        has_suspicious_tld = 1 if any(url_str.endswith(tld) or tld + "/" in url_str for tld in self.suspicious_tlds) else 0
        keyword_matches = sum(1 for kw in self.suspicious_keywords if kw in url_str)

        return [
            float(url_len), float(digit_ratio), float(special_ratio),
            float(num_subdomains), float(has_ip), float(overall_entropy),
            float(domain_entropy), float(brand_dist), float(has_suspicious_tld),
            float(keyword_matches)
        ]

    def transform(self, urls: List[str]) -> np.ndarray:
        return np.array([self.extract_single(u) for u in urls])

def load_or_generate_dataset(config: ModelConfig) -> pd.DataFrame:
    csv_path = config.dataset_dir / "phishing_urls.csv"

    if csv_path.exists():
        logger.info(f"Loading existing dataset from {csv_path}...")
        return pd.read_csv(csv_path)

    logger.info("Constructing benchmark training dataset...")
    benign_urls = [
        "https://www.google.com", "https://www.github.com", "https://www.wikipedia.org",
        "https://www.microsoft.com", "https://www.amazon.com", "https://www.presidencyuniversity.in",
        "https://stackoverflow.com", "https://www.python.org", "https://fastapi.tiangolo.com",
        "https://redis.io", "https://scikit-learn.org", "https://www.linkedin.com",
        "https://portal.presidencyuniversity.in/student/dashboard", "https://docs.python.org/3/library/index.html",
        "https://aws.amazon.com/console/", "https://drive.google.com/drive/my-drive",
        "https://developer.mozilla.org/en-US/docs/Web", "https://pypi.org/project/joblib/",
        "https://www.cloudflare.com/network/", "https://www.sciencedirect.com/journal/cybersecurity",
        "https://arxiv.org/abs/2301.00001", "https://www.nytimes.com/section/technology",
        "https://medium.com/topic/cybersecurity", "https://chat.openai.com/",
        "https://hub.docker.com/_/redis", "https://www.postman.com/product/api-platform/",
        "https://git-scm.com/doc", "https://news.ycombinator.com/", "https://www.reddit.com/r/netsec/"
    ]

    phishing_urls = [
        "http://login.paypal.com.account-verify.secure-update.xyz/login.php",
        "http://secure-bankofamerica.update-login-credential.com/auth",
        "http://account-google-security-verify.temp-web.net/signin",
        "http://appleid.apple.com.verify.account.info-security.top/id",
        "http://192.168.1.1/login.php?update=true&user=admin",
        "http://free-crypto-giveaway-claim-now.site/claim",
        "http://secure.signin.amazon.com-check.tk/auth",
        "http://verify-identity-netflix-payment.support-now.online/billing",
        "http://paypa1-security-center.account-verification-dispatch.info",
        "http://presidency-university-exam-fee-portal.pay-online.tk",
        "http://xn--gogl-0ra.com/login-verification-security",
        "http://microsoft-office365-password-reset.action-required.club",
        "http://chase-online-banking-alert.suspended-account.work",
        "http://wellsfargo-verify-identity-billing-update.buzz/login",
        "http://facebook-security-appeal-center.account-support.cc",
        "http://instagram-copyright-infringement-claim.site/verify",
        "http://binance-wallet-recovery-passphrase.claim-airdrop.top",
        "http://coinbase-auth-mfa-token-sync.info-verification.online",
        "http://adobe-account-renewal-payment.discount-offer.click",
        "http://hdfc-netbanking-otp-auth.secure-update.gq/login",
        "http://10.0.0.1/admin/config.php?session=stolen",
        "http://spotify-premium-annual-free-pass.buzz/claim",
        "http://dropbox-shared-confidential-document.xyz/download"
    ]

    urls = benign_urls + phishing_urls
    labels = [0] * len(benign_urls) + [1] * len(phishing_urls)

    df = pd.DataFrame({"url": urls, "label": labels})
    df.to_csv(csv_path, index=False)
    logger.info(f"Generated dataset saved to {csv_path} ({len(df)} total samples).")
    return df

class ModelTrainer:
    def __init__(self, config: ModelConfig):
        self.config = config
        self.lexical_extractor = StandaloneLexicalExtractor()

    def train(self):
        logger.info("Initializing train_model.py Training Pipeline...")

        df = load_or_generate_dataset(self.config)
        X_raw = df["url"].values
        y = df["label"].values

        logger.info("Extracting Character-Level TF-IDF vectors...")
        char_vec = TfidfVectorizer(
            analyzer="char",
            ngram_range=self.config.char_ngram_range,
            max_features=self.config.char_max_features
        )
        X_char = char_vec.fit_transform(X_raw)

        logger.info("Extracting Word-Level TF-IDF vectors...")
        word_vec = TfidfVectorizer(
            analyzer="word",
            ngram_range=self.config.word_ngram_range,
            max_features=self.config.word_max_features
        )
        X_word = word_vec.fit_transform(X_raw)

        logger.info("Extracting Lexical Features...")
        X_lex = self.lexical_extractor.transform(X_raw)

        logger.info("Scaling Lexical Features...")
        scaler = StandardScaler()
        X_lex_scaled = scaler.fit_transform(X_lex)

        X_combined = hstack([X_char, X_word, X_lex_scaled]).tocsr()
        logger.info(f"Combined Feature Matrix Shape: {X_combined.shape}")

        rf = RandomForestClassifier(n_estimators=150, max_depth=12, random_state=self.config.random_state, n_jobs=-1)
        gb = GradientBoostingClassifier(n_estimators=150, learning_rate=0.1, max_depth=5, random_state=self.config.random_state)
        et = ExtraTreesClassifier(n_estimators=100, max_depth=12, random_state=self.config.random_state, n_jobs=-1)

        ensemble = VotingClassifier(estimators=[("rf", rf), ("gb", gb), ("et", et)], voting="soft")

        logger.info(f"Evaluating Ensemble model using {self.config.cv_folds}-Fold Stratified Cross-Validation...")
        cv = StratifiedKFold(n_splits=self.config.cv_folds, shuffle=True, random_state=self.config.random_state)
        
        cv_results = cross_validate(
            ensemble, X_combined, y, cv=cv,
            scoring=["accuracy", "precision", "recall", "f1", "roc_auc"],
            return_train_score=False
        )

        acc_mean = float(np.mean(cv_results["test_accuracy"]))
        logger.info(f"CV Accuracy: {acc_mean * 100:.2f}%")

        logger.info("Fitting Soft-Voting Ensemble on full dataset...")
        ensemble.fit(X_combined, y)

        logger.info("Serializing model artifacts to 'artifacts/' and 'app/' directories...")
        def export_artifact(obj, filename: str):
            joblib.dump(obj, self.config.artifact_dir / filename)
            joblib.dump(obj, self.config.app_dir / filename)

        export_artifact(char_vec, "char_vec.pkl")
        export_artifact(word_vec, "word_vec.pkl")
        export_artifact(scaler, "scaler.pkl")
        export_artifact(ensemble, "model.pkl")

        manifest = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S IST"),
            "dataset_samples": int(len(df)),
            "accuracy": round(acc_mean, 4),
            "artifacts_saved": ["char_vec.pkl", "word_vec.pkl", "scaler.pkl", "model.pkl"]
        }

        manifest_path = self.config.artifact_dir / "training_manifest.json"
        with open(manifest_path, "w") as f:
            json.dump(manifest, f, indent=4)

        logger.info(f"[✔] Model Training & Export Complete. Saved to {manifest_path}")

if __name__ == "__main__":
    config = ModelConfig()
    trainer = ModelTrainer(config)
    trainer.train()
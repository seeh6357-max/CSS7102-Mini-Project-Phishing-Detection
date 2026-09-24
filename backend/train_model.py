import os
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
import joblib

# 1. Synthetic high-precision dataset
data = {
    'url': [
        # Safe URLs
        "https://www.google.com", "https://www.github.com", "https://www.wikipedia.org",
        "https://www.microsoft.com", "https://www.amazon.com", "https://www.presidencyuniversity.in",
        "https://stackoverflow.com", "https://www.python.org", "https://fastapi.tiangolo.com",
        "https://redis.io", "https://scikit-learn.org", "https://www.linkedin.com",
        # Phishing / Deceptive URLs
        "http://login.paypal.com.account-verify.secure-update.xyz",
        "http://secure-bankofamerica.update-login-credential.com",
        "http://account-google-security-verify.temp-web.net",
        "http://appleid.apple.com.verify.account.info-security.top",
        "http://192.168.1.1/login.php?update=true&user=admin",
        "http://free-crypto-giveaway-claim-now.site",
        "http://secure.signin.amazon.com-check.tk",
        "http://verify-identity-netflix-payment.support-now.online"
    ],
    'label': [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1]
}

df = pd.DataFrame(data)
os.makedirs("dataset", exist_ok=True)
df.to_csv("dataset/phishing_urls.csv", index=False)

# 2. Character-Level TF-IDF Feature Extraction
vectorizer = TfidfVectorizer(analyzer='char', ngram_range=(3, 5))
X = vectorizer.fit_transform(df['url'])
y = df['label']

# 3. Train Classifier
model = LogisticRegression()
model.fit(X, y)

# 4. Save Artifacts
os.makedirs("backend/app", exist_ok=True)
joblib.dump(vectorizer, "backend/app/vectorizer.pkl")
joblib.dump(model, "backend/app/model.pkl")

print("[+] Tier-2 TF-IDF Model & Vectorizer trained and saved successfully!")
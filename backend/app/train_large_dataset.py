# Save as train_large_dataset.py for Cloud Colab / Kaggle Execution
import pandas as pd
import joblib
from sklearn.feature_extraction.text import HashingVectorizer
from sklearn.linear_model import SGDClassifier

print("[+] Loading 1,000,000 URL Dataset...")
df = pd.read_csv("large_phishing_1m.csv") # Replace with dataset path

# Memory-efficient feature extraction for 1M+ strings
vectorizer = HashingVectorizer(analyzer="char_wb", ngram_range=(3, 5), n_features=2**18)
X = vectorizer.transform(df["url"])
y = df["label"]

# Train incremental online classifier
model = SGDClassifier(loss="log_loss", max_iter=20)
model.fit(X, y)

print("[✔] Training complete! Exporting lightweight artifacts...")
joblib.dump(model, "model.pkl")
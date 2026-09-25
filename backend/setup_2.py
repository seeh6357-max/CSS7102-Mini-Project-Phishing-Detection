import abc
import hashlib
import json
import logging
import math
import os
import sys
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

import joblib
import numpy as np
import pandas as pd
from scipy.stats import entropy
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.ensemble import IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import PowerTransformer, RobustScaler, StandardScaler

# Try importing imblearn for advanced resampling; provide fallback if missing
try:
    from imblearn.combine import SMOTETomek
    from imblearn.over_sampling import ADASYN, SMOTE

    HAS_IMBLEARN = True
except ImportError:
    HAS_IMBLEARN = False

# ==========================================
# 1. TELEMETRY & LOGGING SETUP
# ==========================================
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("DataPipelineEngine")


# ==========================================
# 2. PIPELINE CONFIGURATION SCHEMA
# ==========================================
@dataclass
class PipelineConfig:
    """Centralized configuration for dataset processing & artifact generation."""

    raw_data_path: Path = Path("data/raw/dataset.csv")
    output_dir: Path = Path("data/processed")
    artifact_dir: Path = Path("artifacts/v1")

    # Processing Parameters
    test_size: float = 0.20
    val_size: float = 0.10
    random_state: int = 42
    n_workers: int = field(default_factory=lambda: max(1, os.cpu_count() - 1))

    # Feature Engineering Config
    enable_entropy_features: bool = True
    enable_outlier_rejection: bool = True
    outlier_contamination: float = 0.02

    # Imbalance Strategy: 'smote', 'smote_tomek', 'adasyn', or 'none'
    resampling_strategy: str = "smote_tomek"

    def __post_init__(self):
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.artifact_dir.mkdir(parents=True, exist_ok=True)


# ==========================================
# 3. ADVANCED MATHEMATICAL FEATURE EXTRACTORS
# ==========================================
class BaseFeatureExtractor(abc.ABC):
    """Abstract base class for high-performance custom feature extractors."""

    @abc.abstractmethod
    def extract_row(self, item: Any) -> Dict[str, Union[int, float]]:
        pass


class InformationEntropyExtractor(BaseFeatureExtractor):
    """Calculates Shannon Entropy and Lexical Ratios for structural data streams."""

    def extract_row(self, item: str) -> Dict[str, Union[int, float]]:
        if not isinstance(item, str) or not item:
            return {
                "shannon_entropy": 0.0,
                "char_length": 0,
                "digit_ratio": 0.0,
                "special_char_ratio": 0.0,
                "uppercase_ratio": 0.0,
            }

        length = len(item)
        # Calculate character frequency probabilities
        prob_dist = [
            float(item.count(c)) / length for c in set(item)
        ]
        shannon_ent = float(entropy(prob_dist, base=2)) if prob_dist else 0.0

        digits = sum(c.isdigit() for c in item)
        uppercase = sum(c.isupper() for c in item)
        specials = sum(not c.isalnum() for c in item)

        return {
            "shannon_entropy": round(shannon_ent, 5),
            "char_length": length,
            "digit_ratio": round(digits / length, 5),
            "special_char_ratio": round(specials / length, 5),
            "uppercase_ratio": round(uppercase / length, 5),
        }


# Dynamic chunk processing for multi-core scaling
def _process_chunk(
    chunk: List[Any], extractor_cls: type
) -> List[Dict[str, Union[int, float]]]:
    extractor = extractor_cls()
    return [extractor.extract_row(item) for item in chunk]


# ==========================================
# 4. PREPROCESSING & SCALING TRANSFORMERS
# ==========================================
class AdvancedFeaturePipeline(BaseEstimator, TransformerMixin):
    """
    Combined transformer handling Power Transformations, Robust Scaling,
    and Outlier Suppression.
    """

    def __init__(self, contamination: float = 0.02):
        self.contamination = contamination
        self.scaler = RobustScaler()
        self.power_transformer = PowerTransformer(method="yeo-johnson")
        self.outlier_detector = IsolationForest(
            contamination=self.contamination, random_state=42, n_jobs=-1
        )
        self.is_fitted = False

    def fit(self, X: np.ndarray, y: Optional[np.ndarray] = None):
        logger.info("Fitting PowerTransformer (Yeo-Johnson) and RobustScaler...")
        X_scaled = self.scaler.fit_transform(X)
        self.power_transformer.fit(X_scaled)

        logger.info("Fitting Isolation Forest Outlier Detector...")
        self.outlier_detector.fit(X_scaled)

        self.is_fitted = True
        return self

    def transform(self, X: np.ndarray) -> np.ndarray:
        if not self.is_fitted:
            raise RuntimeError("Pipeline must be fitted before calling transform.")
        X_scaled = self.scaler.transform(X)
        X_trans = self.power_transformer.transform(X_scaled)
        return X_trans

    def detect_outliers(self, X: np.ndarray) -> np.ndarray:
        """Returns boolean mask where True indicates an inlier (non-outlier)."""
        X_scaled = self.scaler.transform(X)
        preds = self.outlier_detector.predict(X_scaled)
        return preds == 1


# ==========================================
# 5. DATASET ENGINE & ORCHESTRATOR
# ==========================================
class SetupEngine:
    """Main Orchestrator for setup2.py processing pipeline."""

    def __init__(self, config: PipelineConfig):
        self.config = config
        self.entropy_extractor = InformationEntropyExtractor()

    def generate_synthetic_base_if_missing(self) -> pd.DataFrame:
        """Ensures execution readiness by constructing a robust dummy dataset if raw source is missing."""
        if self.config.raw_data_path.exists():
            logger.info(f"Loading dataset from {self.config.raw_data_path}")
            return pd.read_csv(self.config.raw_data_path)

        logger.warning(
            f"Raw dataset not found at {self.config.raw_data_path}. Generating benchmark mock data..."
        )
        np.random.seed(self.config.random_state)
        n_samples = 5000

        payloads = [
            "https://secure.auth-portal.com/login?token="
            + "".join(np.random.choice(list("abcdef0123456789"), 24)),
            "http://192.168.1.1/admin/config.php",
            "SELECT * FROM users WHERE id = '1' OR '1'='1'",
            "GET /api/v1/resource/status?query=normal",
            "https://malicious-phishing-domain.xyz/verify-account/session-reset",
        ]

        data = {
            "raw_payload": [
                np.random.choice(payloads) + f"&id={i}" for i in range(n_samples)
            ],
            "feature_val_1": np.random.exponential(scale=2.0, size=n_samples),
            "feature_val_2": np.random.normal(loc=50.0, scale=15.0, size=n_samples),
            "feature_val_3": np.random.uniform(low=0.0, high=1.0, size=n_samples),
            "target": np.random.choice(
                [0, 1], size=n_samples, p=[0.85, 0.15]
            ),  # Imbalanced
        }
        df = pd.DataFrame(data)

        # Save synthetic base
        self.config.raw_data_path.parent.mkdir(parents=True, exist_ok=True)
        df.to_csv(self.config.raw_data_path, index=False)
        logger.info(
            f"Benchmark raw data generated and stored at {self.config.raw_data_path}"
        )
        return df

    def run_parallel_feature_extraction(self, text_series: pd.Series) -> pd.DataFrame:
        """Splits raw text streams across CPU worker cores for fast parallel extraction."""
        logger.info(
            f"Executing parallel extraction using {self.config.n_workers} worker processes..."
        )
        items = text_series.tolist()
        chunk_size = math.ceil(len(items) / self.config.n_workers)
        chunks = [
            items[i : i + chunk_size] for i in range(0, len(items), chunk_size)
        ]

        extracted_records = []
        start_time = time.time()

        with ProcessPoolExecutor(max_workers=self.config.n_workers) as executor:
            futures = [
                executor.submit(
                    _process_chunk, chunk, InformationEntropyExtractor
                )
                for chunk in chunks
            ]
            for future in as_completed(futures):
                extracted_records.extend(future.result())

        elapsed = time.time() - start_time
        logger.info(
            f"Parallel extraction finished in {elapsed:.3f}s ({len(items)} samples processed)."
        )
        return pd.DataFrame(extracted_records)

    def balance_dataset(
        self, X: np.ndarray, y: np.ndarray
    ) -> Tuple[np.ndarray, np.ndarray]:
        """Applies advanced resampling strategy to address severe class imbalance."""
        if not HAS_IMBLEARN or self.config.resampling_strategy == "none":
            logger.info("Skipping class balancing (imblearn disabled or bypassed).")
            return X, y

        logger.info(
            f"Applying resampling strategy: '{self.config.resampling_strategy}'..."
        )
        orig_counts = dict(zip(*np.unique(y, return_counts=True)))
        logger.info(f"Class distribution before resampling: {orig_counts}")

        if self.config.resampling_strategy == "smote_tomek":
            resampler = SMOTETomek(random_state=self.config.random_state)
        elif self.config.resampling_strategy == "adasyn":
            resampler = ADASYN(random_state=self.config.random_state)
        else:
            resampler = SMOTE(random_state=self.config.random_state)

        X_res, y_res = resampler.fit_resample(X, y)
        new_counts = dict(zip(*np.unique(y_res, return_counts=True)))
        logger.info(f"Class distribution after resampling: {new_counts}")

        return X_res, y_res

    def execute_pipeline(self):
        """Main execution sequence."""
        logger.info("Starting setup2.py execution pipeline...")

        # Step 1: Ingest Raw Data
        df = self.generate_synthetic_base_if_missing()

        # Step 2: Feature Extraction
        if (
            self.config.enable_entropy_features
            and "raw_payload" in df.columns
        ):
            features_df = self.run_parallel_feature_extraction(df["raw_payload"])
            df = pd.concat([df.drop(columns=["raw_payload"]), features_df], axis=1)

        X = df.drop(columns=["target"]).values
        y = df["target"].values
        feature_names = [col for col in df.columns if col != "target"]

        # Step 3: Train/Val/Test Split
        logger.info(
            f"Splitting data (Test: {self.config.test_size}, Val: {self.config.val_size})..."
        )
        X_train_val, X_test, y_train_val, y_test = train_test_split(
            X,
            y,
            test_size=self.config.test_size,
            random_state=self.config.random_state,
            stratify=y,
        )

        val_ratio_adjusted = self.config.val_size / (1.0 - self.config.test_size)
        X_train, X_val, y_train, y_val = train_test_split(
            X_train_val,
            y_train_val,
            test_size=val_ratio_adjusted,
            random_state=self.config.random_state,
            stratify=y_train_val,
        )

        # Step 4: Fit Advanced Pipeline & Remove Outliers
        transformer_pipeline = AdvancedFeaturePipeline(
            contamination=self.config.outlier_contamination
        )
        transformer_pipeline.fit(X_train)

        if self.config.enable_outlier_rejection:
            inlier_mask = transformer_pipeline.detect_outliers(X_train)
            logger.info(
                f"Outlier suppression: Dropping {np.sum(~inlier_mask)} samples from training set."
            )
            X_train = X_train[inlier_mask]
            y_train = y_train[inlier_mask]

        # Step 5: Transform Arrays
        X_train_transformed = transformer_pipeline.transform(X_train)
        X_val_transformed = transformer_pipeline.transform(X_val)
        X_test_transformed = transformer_pipeline.transform(X_test)

        # Step 6: Class Resampling (Train set only)
        X_train_balanced, y_train_balanced = self.balance_dataset(
            X_train_transformed, y_train
        )

        # Step 7: Serialize Datasets to Compressed Parquet
        logger.info("Persisting processed splits into Parquet datasets...")

        def export_parquet(
            X_arr: np.ndarray, y_arr: np.ndarray, filename: str
        ) -> Path:
            out_df = pd.DataFrame(X_arr, columns=feature_names)
            out_df["target"] = y_arr
            target_path = self.config.output_dir / filename
            out_df.to_parquet(target_path, compression="zstd", index=False)
            return target_path

        train_path = export_parquet(
            X_train_balanced, y_train_balanced, "train.parquet"
        )
        val_path = export_parquet(X_val_transformed, y_val, "val.parquet")
        test_path = export_parquet(X_test_transformed, y_test, "test.parquet")

        # Step 8: Save Pipeline Artifacts & Meta Hashes
        pipeline_artifact_path = (
            self.config.artifact_dir / "preprocessing_pipeline.joblib"
        )
        joblib.dump(transformer_pipeline, pipeline_artifact_path)
        logger.info(f"Transformer pipeline saved to {pipeline_artifact_path}")

        # Compute hash of final train dataset for provenance tracking
        with open(train_path, "rb") as f:
            dataset_hash = hashlib.sha256(f.read()).hexdigest()

        metadata = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S IST"),
            "dataset_sha256": dataset_hash,
            "feature_names": feature_names,
            "num_features": len(feature_names),
            "train_samples": len(X_train_balanced),
            "val_samples": len(X_val_transformed),
            "test_samples": len(X_test_transformed),
            "resampling_applied": self.config.resampling_strategy,
            "artifacts": {
                "pipeline": str(pipeline_artifact_path),
                "train_data": str(train_path),
                "val_data": str(val_path),
                "test_data": str(test_path),
            },
        }

        meta_path = self.config.artifact_dir / "pipeline_metadata.json"
        with open(meta_path, "w") as f:
            json.dump(metadata, f, indent=4)

        logger.info(f"Execution complete. Meta manifest saved to {meta_path}")


# ==========================================
# 6. ENTRYPOINT
# ==========================================
if __name__ == "__main__":
    config = PipelineConfig()
    engine = SetupEngine(config)
    engine.execute_pipeline()
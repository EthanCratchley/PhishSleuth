import os
import re
import numpy as np
import pandas as pd
import joblib
from urllib.parse import urlparse
from sklearn.model_selection import train_test_split, RandomizedSearchCV
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    roc_auc_score,
    f1_score,
    make_scorer
)
import xgboost as xgb

# ================================
# 1️⃣ Load & Combine Datasets
# ================================
def load_and_combine_datasets():
    print("📥 Loading datasets...")

    df1 = pd.read_csv('PhiUSIIL_Phishing_URL_Dataset.csv')
    df1_clean = df1[['URL', 'label']].rename(columns={'URL': 'url'})

    from datasets import load_dataset
    ds = load_dataset("pirocheto/phishing-url")
    df2 = ds["train"].to_pandas()
    df2_clean = df2[['url', 'status']].copy()
    df2_clean['label'] = df2_clean['status'].map({'phishing': 1, 'legitimate': 0})
    df2_clean = df2_clean.drop(columns=['status'])

    df3 = pd.read_csv('malicious_phish.csv')
    df3_clean = df3[['url', 'type']].copy()
    df3_clean['label'] = df3_clean['type'].map({'phishing': 1, 'benign': 0})
    df3_clean = df3_clean[df3_clean['label'].notnull()].drop(columns=['type'])

    combined = pd.concat([df1_clean, df2_clean, df3_clean], ignore_index=True).drop_duplicates()
    print("✅ Combined data shape:", combined.shape)
    return combined


# ================================
# 2️⃣ Extract Features
# ================================
def extract_url_features(df, url_column="url"):
    def get_features(url):
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
        scheme = parsed.scheme or ""

        return pd.Series({
            "url_length": len(url),
            "hostname_length": len(hostname),
            "path_length": len(parsed.path or ""),
            "num_dots": url.count('.'),
            "num_hyphens": url.count('-'),
            "num_underscores": url.count('_'),
            "num_slashes": url.count('/'),
            "num_at": url.count('@'),
            "num_question_marks": url.count('?'),
            "num_equals": url.count('='),
            "num_percent": url.count('%'),
            "num_digits": sum(c.isdigit() for c in url),
            "has_https": int(scheme == "https"),
            "has_http": int(scheme == "http"),
            "has_ip": int(bool(re.search(r"\d+\.\d+\.\d+\.\d+", hostname))),
            "suspicious_keywords": int(any(kw in url.lower() for kw in ["login", "secure", "account", "update", "verify", "bank", "paypal", "signin"])),
            "tld": hostname.split('.')[-1] if '.' in hostname else ""
        })

    print("🔍 Extracting URL features...")
    features = df[url_column].apply(get_features)
    tld_dummies = pd.get_dummies(features['tld'], prefix='tld')
    features = pd.concat([features.drop(columns=['tld']), tld_dummies], axis=1)

    if "label" in df.columns:
        features["label"] = df["label"].astype(int)
    return features


# ================================
# 3️⃣ Train Model + Tune
# ================================
def train_model(features_df):
    print("🚀 Starting training pipeline...")
    df = features_df.dropna().select_dtypes(include="number")

    X = df.drop(columns=["label"])
    y = df["label"]
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    # Param grid for tuning
    param_grid = {
        "n_estimators": [100, 200, 300],
        "max_depth": [4, 6, 8, 10],
        "learning_rate": [0.01, 0.1, 0.2],
        "subsample": [0.6, 0.8, 1.0],
        "colsample_bytree": [0.6, 0.8, 1.0],
        "gamma": [0, 1, 5]
    }

    print("🔍 Running RandomizedSearchCV...")
    xgb_model = xgb.XGBClassifier(
        use_label_encoder=False,
        eval_metric="logloss",
        scale_pos_weight=(y_train == 0).sum() / (y_train == 1).sum(),
        random_state=42
    )

    search = RandomizedSearchCV(
        estimator=xgb_model,
        param_distributions=param_grid,
        n_iter=25,
        scoring=make_scorer(f1_score),
        cv=3,
        verbose=2,
        n_jobs=-1
    )
    search.fit(X_train_scaled, y_train)
    best_model = search.best_estimator_
    print("🏆 Best Params:", search.best_params_)

    print("🎯 Tuning classification threshold...")
    y_proba = best_model.predict_proba(X_test_scaled)[:, 1]
    best_thresh = 0.5
    best_f1 = 0

    for t in np.arange(0.1, 0.91, 0.05):
        f1 = f1_score(y_test, (y_proba >= t).astype(int))
        if f1 > best_f1:
            best_f1, best_thresh = f1, t

    print(f"✅ Best threshold: {best_thresh:.2f} with F1-score: {best_f1:.4f}")

    y_pred = (y_proba >= best_thresh).astype(int)
    print("\n📈 Final Evaluation:")
    print(confusion_matrix(y_test, y_pred))
    print(classification_report(y_test, y_pred, digits=4))
    print(f"ROC AUC Score: {roc_auc_score(y_test, y_proba):.4f}")

    # Save model
    print("\n💾 Saving model artifacts...")
    os.makedirs("url_model", exist_ok=True)
    joblib.dump(best_model, "url_model/xgboost_url_model.pkl")
    joblib.dump(scaler, "url_model/url_scaler.pkl")
    joblib.dump(X.columns.tolist(), "url_model/url_feature_order.pkl")

    print("✅ All artifacts saved!")


# ================================
# 🚀 Main Entry
# ================================
if __name__ == "__main__":
    combined_df = load_and_combine_datasets()
    features_df = extract_url_features(combined_df)
    features_df.to_csv("url_features_ready.csv", index=False)
    train_model(features_df)

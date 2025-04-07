import numpy as np
import pandas as pd
import joblib
from sklearn.ensemble import StackingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score, f1_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

# === Config ===
TEST_SIZE = 0.2
RANDOM_STATE = 42
THRESHOLD = 0.5 

# === Load Data ===
print("📦 Loading base model feature data...")
url_df = pd.read_csv("url_model/url_features_ready.csv")
attachment_df = pd.read_csv("attachment_model/ember_features_flat.csv")
phishing_df = pd.read_csv("phishing_model/phishing_training_data.csv")

# Keep only numeric + label columns
url_df = url_df.select_dtypes(include=["number"]).dropna()
attachment_df = attachment_df.select_dtypes(include=["number"]).dropna()
phishing_df = phishing_df.select_dtypes(include=["number"]).dropna()

# --- Stackable Base: Use the shared label column for supervised training
y = url_df["label"]
X_url = url_df.drop(columns=["label"])
X_attachment = attachment_df.drop(columns=["label"])
X_phishing = phishing_df.drop(columns=["label"])

# === Load Base Models ===
print("📦 Loading pre-trained base models...")
url_model = joblib.load("url_model/url_model/xgboost_url_model.pkl")
url_scaler = joblib.load("url_model/url_model/url_scaler.pkl")

attachment_model = joblib.load("attachment_model/attachment_model/xgboost_attachment_model.pkl")
attachment_scaler = joblib.load("attachment_model/attachment_model/attachment_scaler.pkl")

phishing_model = joblib.load("phishing_model/phishing_model/xgboost_model.pkl")
phishing_scaler = joblib.load("phishing_model/phishing_model/xgboost_scaler.pkl")

# === Scale and Predict Base Model Outputs ===
print("🔮 Generating meta-features...")

def get_model_output(model, scaler, X):
    X_scaled = scaler.transform(X)
    return model.predict_proba(X_scaled)[:, 1]

url_meta = get_model_output(url_model, url_scaler, X_url)
attachment_meta = get_model_output(attachment_model, attachment_scaler, X_attachment)
phishing_meta = get_model_output(phishing_model, phishing_scaler, X_phishing)

# === Align lengths and build meta-feature DataFrame ===
min_len = min(len(url_meta), len(attachment_meta), len(phishing_meta), len(y))
meta_X = pd.DataFrame({
    "url_score": url_meta[:min_len],
    "attachment_score": attachment_meta[:min_len],
    "phishing_score": phishing_meta[:min_len]
})
meta_y = y[:min_len].reset_index(drop=True)

# === Split Meta Data ===
X_train, X_test, y_train, y_test = train_test_split(meta_X, meta_y, test_size=TEST_SIZE, random_state=RANDOM_STATE, stratify=meta_y)

# === Train Meta Model ===
print("🧠 Training Meta (Stacking) Model...")
meta_model = LogisticRegression(random_state=RANDOM_STATE)
meta_model.fit(X_train, y_train)

# === Predict and Evaluate ===
y_proba = meta_model.predict_proba(X_test)[:, 1]
y_pred = (y_proba >= THRESHOLD).astype(int)

print("\n📈 Meta Model Evaluation:")
print(confusion_matrix(y_test, y_pred))
print(classification_report(y_test, y_pred, digits=4))
print(f"ROC AUC Score: {roc_auc_score(y_test, y_proba):.4f}")
print(f"F1 Score: {f1_score(y_test, y_pred):.4f}")

# === Save Meta Model ===
joblib.dump(meta_model, "meta_model.pkl")
joblib.dump(meta_X.columns.tolist(), "meta_feature_order.pkl")
print("✅ Meta model saved to: meta_model.pkl")

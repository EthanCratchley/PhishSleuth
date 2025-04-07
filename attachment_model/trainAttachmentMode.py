import os
import json
import ast
import joblib
import numpy as np
import pandas as pd
from xgboost import XGBClassifier
from sklearn.model_selection import train_test_split, RandomizedSearchCV
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    classification_report, confusion_matrix, f1_score,
    roc_auc_score, make_scorer
)

# ============================
# 1️⃣ Load JSONL -> CSV
# ============================
def load_ember_json_to_csv(ember_path, output_csv):
    first = True
    for i in range(6):
        path = f"{ember_path}/train_features_{i}.jsonl"
        print(f"🔄 Processing {path}")
        rows = []
        with open(path, "r") as f:
            for line in f:
                obj = json.loads(line)
                if obj["label"] is not None:
                    rows.append(obj)
        df = pd.DataFrame(rows)
        df.drop(columns=["sha256", "appeared"], inplace=True, errors="ignore")
        df.to_csv(output_csv, mode='a', header=first, index=False)
        first = False
        print(f"✅ Appended {len(df)} rows.")
    return pd.read_csv(output_csv)


# ============================
# 2️⃣ Flatten Complex Columns
# ============================
def flatten_features(df):
    def extract_flat_features(row):
        result = {}
        # --- Strings ---
        strings = ast.literal_eval(row['strings']) if isinstance(row['strings'], str) else {}
        result['numstrings'] = strings.get('numstrings', 0)
        result['avlength'] = strings.get('avlength', 0)
        result['printabledist_entropy'] = (
            strings.get('printabledist', {}).get('entropy', 0)
            if isinstance(strings.get('printabledist', {}), dict)
            else 0
        )

        # --- General ---
        general = ast.literal_eval(row['general']) if isinstance(row['general'], str) else {}
        result['size'] = general.get('size', 0)
        result['vsize'] = general.get('vsize', 0)
        result['has_debug'] = int(general.get('has_debug', False))
        result['has_relocations'] = int(general.get('has_relocations', False))
        result['has_resources'] = int(general.get('has_resources', False))

        # --- Header ---
        header = ast.literal_eval(row['header']) if isinstance(row['header'], str) else {}
        coff = header.get('coff', {}) if isinstance(header, dict) else {}
        result['timestamp'] = coff.get('timestamp', 0)
        optional = header.get('optional', {}) if isinstance(header, dict) else {}
        result['major_image_version'] = optional.get('major_image_version', 0)
        result['major_os_version'] = optional.get('major_os_version', 0)
        result['major_subsystem_version'] = optional.get('major_subsystem_version', 0)
        return pd.Series(result)

    print("⚙️ Extracting flat features...")
    flat_df = df.apply(extract_flat_features, axis=1)
    flat_df['label'] = df['label']
    flat_df = flat_df[flat_df['label'].isin([0, 1])].reset_index(drop=True)
    flat_df.to_csv("ember_features_flat.csv", index=False)
    print(f"✅ Cleaned Data Saved! Shape: {flat_df.shape}")
    return flat_df


# ============================
# 3️⃣ Train & Tune XGBoost
# ============================
def train_attachment_model(df):
    print("🚀 Training XGBoost on Attachment Features...")

    X = df.drop(columns=["label"])
    y = df["label"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=42
    )

    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    param_grid = {
        'n_estimators': [100, 200, 300],
        'max_depth': [6, 8, 10],
        'learning_rate': [0.05, 0.1, 0.2],
        'subsample': [0.6, 0.8, 1.0],
        'colsample_bytree': [0.6, 0.8, 1.0],
        'gamma': [0, 1, 5]
    }

    scorer = make_scorer(f1_score)
    search = RandomizedSearchCV(
        estimator=XGBClassifier(use_label_encoder=False, eval_metric="logloss"),
        param_distributions=param_grid,
        n_iter=25,
        scoring=scorer,
        cv=3,
        verbose=2,
        n_jobs=-1,
        random_state=42
    )

    print("🔍 Running RandomizedSearchCV...")
    search.fit(X_train_scaled, y_train)
    model = search.best_estimator_

    y_proba = model.predict_proba(X_test_scaled)[:, 1]

    print("🎯 Tuning classification threshold...")
    best_thresh, best_f1 = 0.5, 0
    for thresh in np.arange(0.3, 0.91, 0.05):
        preds = (y_proba >= thresh).astype(int)
        f1 = f1_score(y_test, preds)
        if f1 > best_f1:
            best_f1, best_thresh = f1, thresh

    final_preds = (y_proba >= best_thresh).astype(int)
    print("\n📈 Final Evaluation:")
    print(confusion_matrix(y_test, final_preds))
    print(classification_report(y_test, final_preds))
    print("ROC AUC Score:", roc_auc_score(y_test, y_proba))
    print("F1 Score:", best_f1)

    print("\n💾 Saving model artifacts...")
    os.makedirs("attachment_model", exist_ok=True)
    joblib.dump(model, "attachment_model/xgboost_attachment_model.pkl")
    joblib.dump(scaler, "attachment_model/attachment_scaler.pkl")
    joblib.dump(X.columns.tolist(), "attachment_model/attachment_feature_order.pkl")
    print("✅ Model, scaler, and feature order saved!")


# ============================
# 🚀 Main Entry Point
# ============================
if __name__ == "__main__":
    EMBER_PATH = "ember2018"
    combined_csv = "train_features_combined.csv"

    if not os.path.exists(combined_csv):
        df_raw = load_ember_json_to_csv(EMBER_PATH, combined_csv)
    else:
        df_raw = pd.read_csv(combined_csv)

    df_flat = flatten_features(df_raw)
    train_attachment_model(df_flat)

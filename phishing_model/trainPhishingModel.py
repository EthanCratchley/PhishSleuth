import os
import json
import joblib
import numpy as np
import pandas as pd
from xgboost import XGBClassifier
from sklearn.model_selection import train_test_split, RandomizedSearchCV
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    make_scorer, f1_score, confusion_matrix,
    classification_report, roc_auc_score
)

# === Config ===
DATA_PATH = "phishing_training_data.csv"
TUNED_MODEL_PATH = "phishing_model/xgboost_model.pkl"
SCALER_PATH = "phishing_model/xgboost_scaler.pkl"
FEATURE_ORDER_PATH = "phishing_model/xgboost_feature_order.pkl"
RESULTS_PATH = "phishing_model/xgboost_tuning_results.json"
THRESHOLD = 0.6
TEST_SIZE = 0.20
RANDOM_STATE = 42

def load_and_preprocess_data(path):
    print("📊 Loading and preprocessing data...")
    df = pd.read_csv(path)
    df.drop(columns=[col for col in ["spelling_errors", "urgent_keywords", "domains"] if col in df.columns], inplace=True, errors="ignore")
    df = df.drop_duplicates().select_dtypes(include=["number"])
    return df

def train_and_tune_model(X_train, y_train):
    scale_pos_weight = (y_train == 0).sum() / (y_train == 1).sum()

    param_grid = {
        "n_estimators": [100, 200, 300],
        "max_depth": [4, 6, 8, 10],
        "learning_rate": [0.01, 0.05, 0.1, 0.2],
        "subsample": [0.6, 0.8, 1.0],
        "colsample_bytree": [0.6, 0.8, 1.0],
        "gamma": [0, 1, 5]
    }

    xgb_model = XGBClassifier(
        objective='binary:logistic',
        use_label_encoder=False,
        scale_pos_weight=scale_pos_weight,
        random_state=RANDOM_STATE
    )

    scorer = make_scorer(f1_score)

    print("🔍 Running RandomizedSearchCV...")
    search = RandomizedSearchCV(
        estimator=xgb_model,
        param_distributions=param_grid,
        n_iter=25,
        scoring=scorer,
        cv=3,
        verbose=2,
        n_jobs=-1
    )
    search.fit(X_train, y_train)
    print("🏆 Best Parameters Found:")
    print(search.best_params_)
    return search

def evaluate_and_save(search, X_test, y_test, scaler, feature_order):
    best_model = search.best_estimator_
    y_proba = best_model.predict_proba(X_test)[:, 1]
    y_pred = (y_proba >= THRESHOLD).astype(int)

    print("\n📈 Evaluation:")
    print(confusion_matrix(y_test, y_pred))
    print(classification_report(y_test, y_pred, digits=4))
    print(f"ROC AUC Score: {roc_auc_score(y_test, y_proba):.4f}")

    print("\n💾 Saving model artifacts...")
    os.makedirs("phishing_model", exist_ok=True)
    joblib.dump(best_model, TUNED_MODEL_PATH)
    joblib.dump(scaler, SCALER_PATH)
    joblib.dump(feature_order, FEATURE_ORDER_PATH)

    with open(RESULTS_PATH, "w") as f:
        json.dump(search.best_params_, f, indent=4)

    print(f"✅ Tuned model saved to: {TUNED_MODEL_PATH}")
    print(f"✅ Scaler saved to: {SCALER_PATH}")
    print(f"✅ Feature order saved to: {FEATURE_ORDER_PATH}")
    print(f"✅ Best hyperparameters saved to: {RESULTS_PATH}")

# === Main ===
if __name__ == "__main__":
    df = load_and_preprocess_data(DATA_PATH)

    X = df.drop(columns=["label"])
    y = df["label"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=TEST_SIZE, random_state=RANDOM_STATE, stratify=y
    )

    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    search = train_and_tune_model(X_train_scaled, y_train)
    evaluate_and_save(search, X_test_scaled, y_test, scaler, X.columns.tolist())

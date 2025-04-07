import joblib
import numpy as np

# Load meta model
meta_model = joblib.load("metaModel/meta_model.pkl")

def predict_meta(url_feats, attach_feats, phish_feats):
    # Load base models
    url_model = joblib.load("url_model/url_model/xgboost_url_model.pkl")
    url_scaler = joblib.load("url_model/url_model/url_scaler.pkl")
    url_order = joblib.load("url_model/url_model/url_feature_order.pkl")
    
    attach_model = joblib.load("attachment_model/attachment_model/xgboost_attachment_model.pkl")
    attach_scaler = joblib.load("attachment_model/attachment_model/attachment_scaler.pkl")
    attach_order = joblib.load("attachment_model/attachment_model/attachment_feature_order.pkl")
    
    phish_model = joblib.load("phishing_model/phishing_model/xgboost_model.pkl")
    phish_scaler = joblib.load("phishing_model/phishing_model/xgboost_scaler.pkl")
    phish_order = joblib.load("phishing_model/phishing_model/xgboost_feature_order.pkl")

    # Preprocess
    url_input = url_feats.reindex(columns=url_order, fill_value=0)
    url_input = url_scaler.transform(url_input)
    url_prob = url_model.predict_proba(url_input)[0][1]

    attach_input = attach_feats.reindex(columns=attach_order, fill_value=0)
    attach_input = attach_scaler.transform(attach_input)
    attach_prob = attach_model.predict_proba(attach_input)[0][1]

    phish_input = phish_feats.reindex(columns=phish_order, fill_value=0)
    phish_input = phish_scaler.transform(phish_input)
    phish_prob = phish_model.predict_proba(phish_input)[0][1]

    # Stack for meta
    stacked_input = np.array([[url_prob, attach_prob, phish_prob]])
    risk_score = meta_model.predict_proba(stacked_input)[0][1]
    verdict = "Phishing" if risk_score >= 0.6 else "Benign"

    return {
        "risk_score": risk_score,
        "verdict": verdict,
        "base_probs": {
            "url": url_prob,
            "attachment": attach_prob,
            "phishing": phish_prob
        }
    }

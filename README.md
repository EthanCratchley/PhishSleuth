# PhishSleuth: AI-Powered Email Phishing Detection CLI

![PhishSleuth](phish.png)

## Overview
PhishSleuth is a robust command-line tool for analyzing `.eml` email files to detect phishing threats using multiple AI models. It combines text-based analysis, URL inspection, and attachment examination into a stacked ensemble model for high-accuracy phishing classification.

## Tech Stack
- Python 3.11
- XGBoost for all primary base classifiers
- Scikit-learn for preprocessing and meta model (Logistic Regression)
- pandas / numpy for data manipulation
- colorama for colorful CLI UI
- oletools, pdfid.py, pefile, and python-magic for attachment inspection

## Features:
- Email Body Analysis: Detects phishing intent based on NLP and heuristic text features.
- URL Inspection: Analyzes links in the email using domain features, TLDs, and ML models.
- Attachment Analysis: Examines attachments (PDF, Office, EXE) for malicious characteristics.
- Stacking Meta Model: Combines predictions from base models to improve final accuracy.
- User-Friendly CLI: Just provide a path to your email and get a full risk report.

## Folder Structure 
```
phish-detection/
├── attachment_model/       # Attachment model files and raw data
├── phishing_model/         # Text-based phishing detection model
├── url_model/              # URL classifier model
├── metaModel/              # Final stacking model and metadata
├── utils/                  # All utility modules
├── main.py                 # CLI interface
├── metaModel.py            # Training the stacking model
├── requirements.txt        # Python dependencies
└── README.md               # This documentation
```

## Installation:
1. Clone the repository
```sh
git clone https://github.com/yourusername/phish-detection.git
cd phish-detection
```
2. Install Dependencies
```sh
pip install -r requirements.txt
```

## Usage: 
**CLI Mode: Run the File**
```sh
python main.py
```

You will be prompted:
```sh
Enter the path to your .eml file (or type 'quit' to exit):
```

Enter email path:
```sh
Email file path: email.eml
```

**Sample Output:**
```sh
📧 Email Analysis Report:
--------------------------------------------------
Sender: Ethan <hello@ethan.com>
Subject: Try PhishSleuth ✅✅✅

🛑 Phishing Risk Score: 0.00
Flags:
  - HTML content present

No attachments found.
✅ Verdict: Benign Email
--------------------------------------------------
```

## Models Used
**Base Models**
- Email Phishing Model: XGBoost trained on NLP/text features.
- URL Classifier: XGBoost trained on domain, TLD, link structure.
- Attachment Classifier: XGBoost trained on file entropy, type, macros, etc.

**Meta Model**
- Logistic Regression: Takes probability outputs of base models and predicts final risk.

## Performance
Final Stacking Model Metrics:

- Accuracy: 99.26%
- F1 Score: 0.9936
- ROC AUC: 0.9978

## Future Plans
- Browser extension integration
- Add support for multilingual phishing detection
- Web UI dashboard to visualize results
- Integrate virus scanning and advanced sandbox behavior detection
- Real-time email server integration and threat response API

## License
MIT License. Feel free to use, modify, and contribute.

## Contributions
Pull requests welcome! Please open an issue first to discuss major changes.
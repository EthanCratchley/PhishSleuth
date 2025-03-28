# AI Phishing Email and Attachment Detection

## Overview
Goal: Build a CLI tool that scans an email file (or raw email input), analyzes:

- The email content (subject, body, sender) for phishing indicators
- The URLs for suspicious domains or typosquatting
- The attachments for static risk features
- Then outputs a detailed report with phishing scores, flagged issues, and optional suggestions.

## Tech Stack
- Language: Python
- ML Models: scikit-learn, xgboost, joblib
- NLP/Text Processing: nltk, re, spacy, tldextract, email
- Static Analysis: oletools, pdfid, python-magic, pefile
- CLI: argparse, colorama
- Optional: VirusTotal API (for validation)


## Folder Structure 
phishsleuth/
├── phishing_model/
│   ├── train_phishing_model.py
│   ├── phishing_model.pkl
├── attachment_model/
│   ├── train_attachment_model.py
│   ├── attachment_model.pkl
├── utils/
│   ├── feature_extraction.py
│   ├── email_parser.py
│   ├── attachment_analyzer.py
├── main.py  # CLI entry point
├── requirements.txt
├── README.md
└── sample_emails/

## Plan
1. Accept .eml files or raw string input.
Use Python’s built-in email module to extract:
- Subject
- Body (plain text or HTML)
- Sender
- Attachments
Output: Dict or object representing email structure.

2. Extract Static Features for Attachments
If PDF, DOCX, or EXE, use:
- python-magic for MIME/type
- oletools for VBA/macros in Office
- pdfid for JavaScript, embedded files
- pefile for EXE metadata
File size, entropy, # of embedded objects

3. Extract Features for Phishing Detection
Tokenize body text, extract basic NLP features:
- Links
- Words
- Spelling Errors
- Email Address
Extract URL domain info using tldextract, re, or urlparse.

4. Train ML Models 
- Phishing Classifier:
  - TF-IDF of body + engineered metadata
  - Model: Logistic Regression / XGBoost
- Attachment Classifier:
  - Static features → Random Forest or XGBoost

5. Evaluate and Test Tool

6. Iterate
- Export results to JSON or CSV
- Add logging
- Add config file for thresholds
- Optional: Build a web UI later (Streamlit) or Extension


**Example Output:**
```
📧 Email Analysis Report:
----------------------------------
Sender: support@paypal-update.com
Subject: URGENT: Your Account Will Be Suspended

🛑 Phishing Risk Score: 0.87
Flags:
- Unusual domain (paypal-update.com)
- Urgent language
- Spelling errors
- 3 suspicious links

📎 Attachment: invoice.docm
⚠️ Attachment Risk Score: 0.92
Flags:
- Contains macros
- High entropy
- Uncommon extension

✅ Verdict: High Risk Email
```
Output Report: 
- Phishing score (0–1)
- Phishing indicators
- URL flags
- Attachment file risk score (0–1)
- Flags (e.g., macro present, high entropy)

## Final Notes
What the Tool Will Do:
1. Takes an email file (.eml) as input
2. Scans the email for signs of phishing:
   1. Suspicious Sender
   2. Urget or Manipulative Language
   3. Suspicious Links
3. Analyzes any attachments in the email for signs that they might be malicious
   1. Hiiden macros
   2. Secret code
   3. Unusual file types
4. Gives user a risk score/report

ML Use Case:
1. Phishing Email Detection
- Decide whether the email content looks like a phishing attempt
- You train a machine learning model (e.g., Logistic Regression or XGBoost) on real phishing and non-phishing emails.
- The model learns patterns based on features like:
  - Words in the subject/body (from TF-IDF or NLP)
  - Presence of suspicious links or sender domains
  - Spelling errors, urgent language, etc.

2. Email Attachment Risk Classifier
- Predict if an email attachment is likely to be malicious.
- You extract features from the attachment without opening it:
  - File size, entropy (how random the contents look)
  - Whether it has macros (in Word files)
  - Whether it's an uncommon file type (like .scr or .exe)
- You train another ML model (e.g., Random Forest or XGBoost) on known clean and malicious attachments.

## Research Paper: 

**Topic:**“PhishSleuth: Lightweight Static Analysis and AI for Phishing and Attachment Detection in Email”

**Sections:**
- Intro – Email-based threats, problem statement
- Background – Phishing, attachment-based malware, prior solutions
- Methodology – Feature engineering, ML model choice, CLI architecture
- Experiments – Dataset used, metrics, model performance
- Discussion – Strengths, limitations (e.g., can't catch 0-day), future work
- Conclusion

# To Do:
- How does .eml hand emails with multiple replies, forward emails etc?
- Improve terminal design
- Clean Outputs
- Give scores
- Build to look like example output
- Make extension 

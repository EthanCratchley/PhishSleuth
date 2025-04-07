import re
from urllib.parse import urlparse
from email import policy
from email.parser import BytesParser

def extract_email_body(msg):
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = part.get("Content-Disposition", "")
            if content_type == "text/plain" and "attachment" not in content_disposition.lower():
                try:
                    return part.get_content()
                except Exception as e:
                    print(f"Error extracting text content: {e}")
    else:
        return msg.get_content()
    return ""

def extract_html_body(msg):
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/html":
                try:
                    return part.get_content()
                except Exception:
                    return ""
    elif msg.get_content_type() == "text/html":
        return msg.get_content()
    return ""

def extract_urls_from_text(text):
    # Simple regex for URL detection
    return re.findall(r'https?://[^\s]+', text)

def extract_phishing_features(text, html):
    """
    Basic feature extraction for phishing cues.
    """
    text = text.lower()
    html = html.lower()

    phishing_keywords = ['verify', 'login', 'account', 'update', 'bank', 'urgent', 'click here', 'password']
    flags = []

    # Feature vector
    features = {
        "num_urls": len(extract_urls_from_text(text + " " + html)),
        "num_phishing_keywords": sum(kw in text for kw in phishing_keywords),
        "has_html": int(bool(html)),
        "has_urgent_language": int(any(kw in text for kw in ['urgent', 'immediately', 'asap'])),
        "has_login_prompt": int('login' in text),
        "has_verify_request": int('verify' in text)
    }

    if features["has_urgent_language"]:
        flags.append("Urgent language detected")
    if features["has_login_prompt"]:
        flags.append("Login prompt present")
    if features["has_verify_request"]:
        flags.append("Verification request detected")
    if features["num_phishing_keywords"] > 1:
        flags.append("Multiple phishing-related keywords")
    if features["has_html"]:
        flags.append("HTML content present")

    return features, flags

def parse_email(file_path):
    with open(file_path, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)

    body = extract_email_body(msg)
    body_html = extract_html_body(msg)
    urls = extract_urls_from_text(body + " " + body_html)
    phish_features, heuristic_flags = extract_phishing_features(body, body_html)

    email_data = {
        "From": msg.get("From", ""), 
        "To": msg.get("To", ""),
        "Reply-To": msg.get("Reply-To", ""),
        "Return-Path": msg.get("Return-Path", ""),
        "Subject": msg.get("Subject", ""),
        "Date": msg.get("Date", ""),
        "Received": msg.get_all("Received", []),
        "Message-ID": msg.get("Message-ID", ""),
        "X-Mailer": msg.get("X-Mailer", ""),
        "Body": body,
        "Body_HTML": body_html,
        "urls": urls,
        "phish_features": phish_features,
        "flags": heuristic_flags
    }

    return email_data

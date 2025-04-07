import re
from urlextract import URLExtract
import tldextract
from spellchecker import SpellChecker

# Common English stopwords
STOPWORDS = {
    "the", "and", "is", "in", "it", "of", "to", "a", "an", "that", "this",
    "for", "on", "with", "as", "at", "by", "from", "or", "not", "be", "are",
    "was", "were", "but", "if", "so", "out", "up", "down", "about", "can",
    "will", "just", "your", "my", "their", "i", "you", "he", "she", "we",
    "they", "them", "his", "her", "its"
}

spell = SpellChecker()
spell_cache = {}

def extract_word_features(text):
    tokens = re.findall(r'\b[a-zA-Z]+\b', text.lower())
    return {
        "num_words": len(tokens),
        "num_unique_words": len(set(tokens)),
        "num_stopwords": sum(1 for t in tokens if t in STOPWORDS)
    }

def extract_links(text):
    extractor = URLExtract()
    urls = extractor.find_urls(text)
    return {
        "num_links": len(urls),
        "urls": urls
    }

def extract_email_addresses(text):
    emails = re.findall(r'\b[\w\.-]+@[\w\.-]+\.\w+\b', text)
    return {
        "num_email_addresses": len(emails),
        "emails": emails
    }

def extract_spelling_errors(text):
    words = re.findall(r'\b[a-zA-Z]+\b', text.lower())
    filtered_words = [w for w in words if w not in {"http", "https", "www", "org"}]
    
    misspelled = []
    for word in filtered_words:
        if word not in spell_cache:
            spell_cache[word] = word in spell.unknown([word])
        if spell_cache[word]:
            misspelled.append(word)

    return {
        "num_spelling_errors": len(misspelled),
        "spelling_errors": misspelled
    }

def extract_domain_features(urls):
    domains = [tldextract.extract(url).registered_domain for url in urls if url]
    unique_domains = list(set(domains))
    return {
        "domains": unique_domains,
        "num_unique_domains": len(unique_domains)
    }

def extract_urgent_keywords(text):
    keywords = ['urgent', 'verify', 'immediately', 'update', 'suspend', 'account', 'limited']
    found = [kw for kw in keywords if kw in text.lower()]
    return {
        "num_urgent_keywords": len(found),
        "urgent_keywords": found
    }

def extract_phishing_features(text):
    """
    Master function for phishing feature extraction.
    Combines linguistic, lexical, and behavioral cues into one feature set.
    """
    features = {}

    # Word stats
    features.update(extract_word_features(text))

    # Link & domain features
    link_info = extract_links(text)
    features["num_links"] = link_info["num_links"]
    features.update(extract_domain_features(link_info["urls"]))

    # Email address mentions
    email_info = extract_email_addresses(text)
    features["num_email_addresses"] = email_info["num_email_addresses"]

    # Spelling analysis
    features.update(extract_spelling_errors(text))

    # Urgency cues
    features.update(extract_urgent_keywords(text))

    return features

def extract_url_features(df, url_column="url"):
    from urllib.parse import urlparse
    import pandas as pd
    import re

    def get_features(url):
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
        path = parsed.path or ""
        query = parsed.query or ""
        scheme = parsed.scheme

        features = {
            "url_length": len(url),
            "hostname_length": len(hostname),
            "path_length": len(path),
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
            "suspicious_keywords": int(any(kw in url.lower() for kw in [
                "login", "secure", "account", "update", "verify", "bank", "paypal", "signin"
            ])),
            "tld": hostname.split('.')[-1] if '.' in hostname else ""
        }
        return pd.Series(features)

    print("🔍 Extracting URL features...")
    features_df = df[url_column].apply(get_features)

    # Encode TLD as dummy variables
    tld_dummies = pd.get_dummies(features_df["tld"], prefix="tld")
    features_df = pd.concat([features_df.drop(columns=["tld"]), tld_dummies], axis=1)

    # Add label if present
    if "label" in df.columns:
        features_df["label"] = df["label"].astype(int)

    return features_df

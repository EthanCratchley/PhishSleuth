import re
import string
from urlextract import URLExtract
import tldextract
from spellchecker import SpellChecker

# A simple set of English stopwords (can be extended as needed)
STOPWORDS = {
    "the", "and", "is", "in", "it", "of", "to", "a", "an", "that", "this",
    "for", "on", "with", "as", "at", "by", "from", "or", "not", "be", "are",
    "was", "were", "but", "if", "so", "out", "up", "down", "about", "can",
    "will", "just", "your", "my", "their", "i", "you", "he", "she", "we",
    "they", "them", "his", "her", "its"
}

'''
Stop words are a set of commonly used words in any language, in NLP and text mining applications, 
they are used to eliminate unimportant words, allowing applications to focus on the important words instead.
'''

def extract_word_features(text):
    """
    Tokenizes the text and extract word-based features.

    Dictionary with:
    - num of words
    - num of unique words
    - num of stopwords
    """
    # Tokenize by finding all sequences of alphabetical characters
    tokens = re.findall(r'\b[a-zA-Z]+\b', text.lower())
    num_words = len(tokens)
    num_unqiue_words = len(set(tokens))
    num_stopwords = sum(1 for t in tokens if t in STOPWORDS)

    return {
        "num_words": num_words,
        "num_unique_words": num_unqiue_words,
        "num_stopwords": num_stopwords
    }

def extract_links(text):
    """
    Extract URLS from text using urlextract.

    Dictionary with:
    - number of URLs found
    - List of URLs
    """
    extractor = URLExtract()
    urls = extractor.find_urls(text)
    
    return {
        "num_links": len(urls),
        "urls": urls
    }

def extract_email_addresses(text):
    """
    Uses a regular expression to extract email addresses from text.

    Dictionary with:
    - num of emails
    - list of emails
    """
    emails = re.findall(r'\b[\w\.-]+@[\w\.-]+\.\w+\b', text)

    return {
        "num_emails": len(emails),
        "emails": emails
    }

def extract_spelling_errors(text):
    """
    Identifies mispelled words.

    Dictionary with:
    - num of spelling errors
    - list of spelling errors
    """
    spell = SpellChecker()
    # Use the same simple tokenization, only alphabetical words
    words = re.findall(r'\b[a-zA-Z]+\b', text.lower())
    filtered_words = [w for w in words if w not in {"http", "https", "www", "org"}]
    misspelled = spell.unknown(filtered_words)
    
    return {
        "num_spelling_errors": len(misspelled),
        "spelling_errors": list(misspelled)
    }

def extract_domain_features(urls):
    """
    Extracts domain information from a list of URLs.
    
    Dictionary with:
      - List of unique registered domains.
      - Count of unique domains.
    """
    domains = [tldextract.extract(url).registered_domain for url in urls if url]
    unique_domains = list(set(domains))

    return {
        "domains": unique_domains,
        "num_unique_domains": len(unique_domains)
    }

def extract_phishing_features(text):
    """
    Combines all phishing-related feature extractions into a single function.
    
    Dictionary containing:
      - Word features.
      - Link features and domain info.
      - Email address count.
      - Spelling error count.
    """
    features = {}
    
    # Extract word-based features
    word_feats = extract_word_features(text)
    features.update(word_feats)
    
    # Extract links and then domain features
    link_info = extract_links(text)
    features["num_links"] = link_info["num_links"]
    domain_info = extract_domain_features(link_info["urls"])
    features.update(domain_info)
    
    # Extract email addresses
    email_info = extract_email_addresses(text)
    features["num_email_addresses"] = email_info["num_emails"]
    
    # Extract spelling errors
    spell_info = extract_spelling_errors(text)
    features.update(spell_info)

    # Extract urgent words
    urgent_words = extract_urgent_keywords(text)
    features.update(urgent_words)
    
    return features

def extract_urgent_keywords(text):
    keywords = ['urgent', 'verify', 'immediately', 'update', 'suspend', 'account', 'limited']
    found = [kw for kw in keywords if kw in text.lower()]
    return {
        "num_urgent_keywords": len(found),
        "urgent_keywords": found
    }

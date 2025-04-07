import os
import math
from collections import Counter
import magic
import subprocess
from oletools.olevba import VBA_Parser  
import pefile                            

def calculate_entropy(data):
    """
    Calculate the Shannon entropy of file data.
    """
    if not data:
        return 0
    counter = Counter(data)
    total = len(data)
    entropy = -sum((count / total) * math.log2(count / total) for count in counter.values())
    return entropy

def analyze_attachment(file_path):
    """
    Analyze an attachment and return a dictionary of extracted features.
    """
    features = {}

    # 1️⃣ Basic file metadata
    try:
        features["file_size"] = os.path.getsize(file_path)
    except Exception:
        features["file_size"] = 0

    try:
        with open(file_path, "rb") as f:
            data = f.read()
    except Exception:
        data = b""

    features["entropy"] = calculate_entropy(data)

    # 2️⃣ File type info
    try:
        mime = magic.from_buffer(data, mime=True)
    except Exception:
        mime = "unknown"
    features["mime_type"] = mime

    ext = os.path.splitext(file_path)[1].lower()
    features["file_extension"] = ext

    # 3️⃣ PDF Analysis (using pdfid.py)
    features["has_pdf_suspicious_tags"] = 0
    if mime == "application/pdf" or ext == ".pdf":
        try:
            output = subprocess.check_output(["pdfid.py", file_path], universal_newlines=True)
            suspicious_tags = ["/JS", "/JavaScript", "/AA", "/OpenAction", "/Launch"]
            tag_count = sum(line.startswith(tag) and int(line.split(":")[1].strip()) > 0 for line in output.splitlines() for tag in suspicious_tags)
            features["has_pdf_suspicious_tags"] = int(tag_count > 0)
        except Exception:
            features["has_pdf_suspicious_tags"] = 0

    # 4️⃣ Office Documents - Macro Detection
    features["has_macros"] = 0
    if ext in [".doc", ".docm", ".docx", ".xls", ".xlsm", ".ppt", ".pptm"]:
        try:
            vbaparser = VBA_Parser(file_path)
            features["has_macros"] = int(vbaparser.detect_vba_macros())
        except Exception:
            features["has_macros"] = 0

    # 5️⃣ Executables - PE Info
    features["pe_sections"] = 0
    features["pe_entry_point"] = 0
    if ext == ".exe":
        try:
            pe = pefile.PE(file_path)
            features["pe_sections"] = len(pe.sections)
            features["pe_entry_point"] = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        except Exception:
            pass

    return {
        "features": features
    }

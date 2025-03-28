import os
import math
from collections import Counter
import magic
import subprocess
from oletools.olevba import VBA_Parser  
import pefile                           


def calculate_entropy(data):
    """
    Calculate the Shannon entropy of the file data.
    """
    if not data:
        return 0
    counter = Counter(data)
    total = len(data)
    entropy = 0
    for count in counter.values():
        p = count / total
        entropy -= p * math.log2(p)
    return entropy

def analyze_attachment(file_path):
    """
    Analyzes the attachment file and returns a dictionary with key features.
    """
    features = {}

    # File size
    file_size = os.path.getsize(file_path)
    features["file_size"] = file_size

    # Read file bytes
    with open(file_path, "rb") as f:
        data = f.read()

    # Calculate entropy
    features["entropy"] = calculate_entropy(data)

    # Get MIME type using python-magic
    mime = magic.from_buffer(data, mime=True)
    features["mime_type"] = mime

    # Get file extension
    ext = os.path.splitext(file_path)[1].lower()
    features["file_extension"] = ext

    # PDF Analysis using pdfid.py 
    if mime == "application/pdf" or ext == ".pdf":
        try:
            # Ensure pdfid.py is in your PATH or provide the full path to it
            output = subprocess.check_output(["pdfid.py", file_path], universal_newlines=True)
            features["pdfid_output"] = output
        except Exception as e:
            features["pdfid_output"] = f"Error running pdfid: {e}"

    # Office Documents Analysis for Macros
    if ext in [".doc", ".docm", ".docx", ".xls", ".xlsm", ".ppt", ".pptm"]:
        try:
            vbaparser = VBA_Parser(file_path)
            has_macros = vbaparser.detect_vba_macros()
            features["has_macros"] = has_macros
        except Exception as e:
            features["has_macros"] = f"Error checking macros: {e}"

    # Executable Analysis using pefile
    if ext == ".exe":
        try:
            pe = pefile.PE(file_path)
            features["pe_sections"] = len(pe.sections)
            features["pe_entry_point"] = hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
        except Exception as e:
            features["pe_info"] = f"Error analyzing executable: {e}"

    return features
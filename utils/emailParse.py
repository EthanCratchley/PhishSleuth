from email import policy
from email.parser import BytesParser

def extract_email_body(msg):
    """
    Extracts the plain text body. If the email is multipart, it iterates over the parts 
    and returns the first text/plain part that is not an attachment.
    """
    if msg.is_multipart(): # an email that contains multiple versions or parts of the content (plain text, HTML, attachments) - Form a MIME multipart message
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = part.get("Content-Disposition", "") # Content Disposition is an email header that tells the email client how to present the content
            if content_type == "text/plain" and "attachment" not in content_disposition.lower():
                try:
                    return part.get_content()
                except Exception as e:
                    print(f"Error extracting text content: {e}")
    else:
        return msg.get_content()
    return ""

def extract_html_body(msg):
    """
    Extracts the HTML body from the email, if present.
    """
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

def parse_email(file_path):
    """
    Parses the given .eml file and returns a dictionary with key email details.
    """
    with open(file_path, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)

    email_data = {
        "From": msg.get("From", ""), 
        "To": msg.get("To", ""),
        "Reply-To": msg.get("Reply-To", ""),
        "Return-Path": msg.get("Return-Path", ""),
        "Subject": msg.get("Subject", ""),
        "Date": msg.get("Date", ""),
        "Received": msg.get_all("Received", []), # List of servers that handled the email
        "Message-ID": msg.get("Message-ID", ""), # Unqiue identifier 
        "X-Mailer": msg.get("X-Mailer", ""), # Software used to send an email
        "Body": extract_email_body(msg), 
        "Body_HTML": extract_html_body(msg),
    }

    return email_data

import os
import tempfile
import subprocess
import colorama
from colorama import Fore, Style
from email import policy
from email.parser import BytesParser

# Import your utility modules
from utils.emailParse import parse_email
from utils.attachmentAnalyze import analyze_attachment

def print_banner():
    banner = f"""
{Fore.CYAN}{'='*80}

__________.__    .__       .__      _________.__                 __  .__     
\______   \  |__ |__| _____|  |__  /   _____/|  |   ____  __ ___/  |_|  |__  
 |     ___/  |  \|  |/  ___/  |  \ \_____  \ |  | _/ __ \|  |  \   __\  |  \ 
 |    |   |   Y  \  |\___ \|   Y  \/        \|  |_\  ___/|  |  /|  | |   Y  \
\                                                                            
 |____|   |___|  /__/____  >___|  /_______  /|____/\___  >____/ |__| |___|  /
               \/        \/     \/        \/           \/                 \/ 

{'='*80}{Style.RESET_ALL}
    """
    print(banner)

def print_separator():
    print(Fore.MAGENTA + "-" * 60 + Style.RESET_ALL)

def extract_attachments(msg):
    """
    Extracts attachments from the email message.
    Returns a list of tuples: (filename, temporary file path).
    """
    attachments = []
    if msg.is_multipart():
        for part in msg.walk():
            content_disposition = part.get("Content-Disposition", "")
            if "attachment" in content_disposition.lower():
                filename = part.get_filename() or "unknown_attachment"
                data = part.get_payload(decode=True)
                if data:
                    # Write the attachment to a temporary file for analysis
                    with tempfile.NamedTemporaryFile(delete=False, suffix=os.path.splitext(filename)[1]) as tmp:
                        tmp.write(data)
                        tmp_path = tmp.name
                    attachments.append((filename, tmp_path))
    return attachments

def print_report(email_data, attachment_analysis):
    """
    Prints a simplified, stylized report.
    (Using placeholder risk scores and flags for now.)
    """
    # Simulated risk scores and flags (since models are not yet integrated)
    phishing_risk_score = 0.87
    phishing_flags = [
        "Unusual domain (paypal-update.com)",
        "Urgent language",
        "Spelling errors",
        "3 suspicious links"
    ]
    verdict = "High Risk Email"
    
    # Report Header
    print("\n" + Fore.CYAN + "📧 Email Analysis Report:" + Style.RESET_ALL)
    print(Fore.MAGENTA + "-" * 50 + Style.RESET_ALL)
    print(f"{Fore.GREEN}Sender:{Style.RESET_ALL} {email_data.get('From', 'N/A')}")
    print(f"{Fore.GREEN}Subject:{Style.RESET_ALL} {email_data.get('Subject', 'N/A')}\n")
    
    # Phishing Analysis
    print(f"{Fore.RED}🛑 Phishing Risk Score:{Style.RESET_ALL} {phishing_risk_score:.2f}")
    print("Flags:")
    for flag in phishing_flags:
        print(f"  - {flag}")
    print()
    
    # Attachment Analysis (if any)
    if attachment_analysis:
        for analysis in attachment_analysis:
            filename = analysis.get("filename", "unknown_attachment")
            attachment_risk_score = 0.92  # Simulated value
            attachment_flags = [
                "Contains macros",
                "High entropy",
                "Uncommon extension"
            ]
            print(f"{Fore.YELLOW}📎 Attachment:{Style.RESET_ALL} {filename}")
            print(f"{Fore.RED}⚠️ Attachment Risk Score:{Style.RESET_ALL} {attachment_risk_score:.2f}")
            print("Flags:")
            for flag in attachment_flags:
                print(f"  - {flag}")
            print()
    else:
        print(f"{Fore.YELLOW}No attachments found.{Style.RESET_ALL}\n")
    
    # Final Verdict
    print(f"{Fore.GREEN}✅ Verdict:{Style.RESET_ALL} {verdict}")
    print(Fore.MAGENTA + "-" * 50 + Style.RESET_ALL)

def main():
    colorama.init(autoreset=True)
    print_banner()
    print(Fore.CYAN + "\nWelcome to the PhishSleuth Email Analyzer CLI" + Style.RESET_ALL)
    print("Enter the path to your .eml file (or type 'quit' to exit):")
    
    while True:
        user_input = input(Fore.YELLOW + "Email file path: " + Style.RESET_ALL).strip()
        file_path = os.path.join("./Emails/", user_input)
        if user_input.lower() in ['quit', 'exit']:
            print(Fore.CYAN + "\nExiting. Goodbye!" + Style.RESET_ALL)
            break
        if not os.path.isfile(file_path):
            print(Fore.RED + "File not found. Please try again." + Style.RESET_ALL)
            continue
        
        # 1. Parse the email using the utility module
        email_data = parse_email(file_path)
        
        # 2. Open the file again to extract attachments
        with open(file_path, "rb") as f:
            msg = BytesParser(policy=policy.default).parse(f)
        attachments = extract_attachments(msg)
        
        # 3. Analyze each attachment (if any)
        attachment_analysis = []
        for filename, temp_file in attachments:
            analysis = analyze_attachment(temp_file)
            analysis["filename"] = filename
            attachment_analysis.append(analysis)
        
        # 4. Print the final simplified report
        print_report(email_data, attachment_analysis)
        
        # 5. Clean up temporary attachment files
        for _, temp_file in attachments:
            try:
                os.remove(temp_file)
            except OSError:
                pass
        
        print("\nYou can analyze another email or type 'quit' to exit.\n")

if __name__ == "__main__":
    main()

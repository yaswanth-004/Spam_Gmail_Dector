import os
import base64
import hashlib
import re
import time
import requests
from datetime import datetime
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
import joblib
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Load the AI model and the vectorizer
try:
    ai_model = joblib.load('spam_model.pkl')
    ai_vectorizer = joblib.load('vectorizer.pkl')
    print("✅ AI Spam Model Loaded Successfully")
except Exception as e:
    print(f"❌ Error loading AI model: {e}")
    ai_model, ai_vectorizer = None, None

def clean_text(text):
    """Must match the cleaning logic used in your Jupyter Notebook."""
    text = text.lower()
    text = re.sub(r'[^a-zA-Z\s]', '', text)
    return text

def get_ai_prediction(text):
    """Passes the email body string to the AI model."""
    if not ai_model or not ai_vectorizer:
        return "AI Not Loaded"
    
    if not text or text.strip() == "":
        return "NO_CONTENT"
    
    cleaned = clean_text(text)
    features = ai_vectorizer.transform([cleaned])
    prediction = ai_model.predict(features)[0]
    return "SPAM" if prediction == 1 else "HAM"

# Gmail API Configuration
SCOPES = ['https://mail.google.com/'] 
CREDENTIALS_FILE = os.getenv('GMAIL_CREDENTIALS_FILE', 'credentials.json')

# VirusTotal API Configuration - SECURE (from environment variable)
VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY', '')
VIRUSTOTAL_URL_SCAN = 'https://www.virustotal.com/api/v3/urls'
VIRUSTOTAL_FILE_SCAN = 'https://www.virustotal.com/api/v3/files'
VIRUSTOTAL_ANALYSIS = 'https://www.virustotal.com/api/v3/analyses/'

# Rate limiting configuration
RATE_LIMIT_DELAY = 15  # seconds between VirusTotal requests (4 per minute = 15 sec)
last_vt_request_time = 0

def rate_limit_check():
    """Ensures we don't exceed VirusTotal rate limits (4 requests/minute for free tier)"""
    global last_vt_request_time
    current_time = time.time()
    time_since_last_request = current_time - last_vt_request_time
    
    if time_since_last_request < RATE_LIMIT_DELAY:
        sleep_time = RATE_LIMIT_DELAY - time_since_last_request
        print(f"    ⏳ Rate limit protection: waiting {sleep_time:.1f} seconds...")
        time.sleep(sleep_time)
    
    last_vt_request_time = time.time()

# --- VirusTotal Functions ---
def scan_url_virustotal(url):
    """Scans a URL using VirusTotal API and returns the report."""
    if not VIRUSTOTAL_API_KEY:
        return "    ⚠️ VirusTotal API key not configured"
    
    rate_limit_check()
    
    headers = {
        'x-apikey': VIRUSTOTAL_API_KEY
    }
    
    try:
        print(f"    Scanning URL with VirusTotal: {url[:60]}...")
        response = requests.post(VIRUSTOTAL_URL_SCAN, headers=headers, data={'url': url})
        
        if response.status_code == 200:
            result = response.json()
            analysis_id = result['data']['id']
            
            # Wait for analysis to complete
            max_retries = 5
            for retry in range(max_retries):
                time.sleep(3)
                analysis_response = requests.get(f"{VIRUSTOTAL_ANALYSIS}{analysis_id}", headers=headers)
                
                if analysis_response.status_code == 200:
                    analysis_data = analysis_response.json()
                    status = analysis_data['data']['attributes']['status']
                    
                    if status == 'completed':
                        break
                    elif retry < max_retries - 1:
                        print(f"    ⏳ Analysis in progress... (attempt {retry + 1}/{max_retries})")
            
            # Get the final analysis report
            analysis_response = requests.get(f"{VIRUSTOTAL_ANALYSIS}{analysis_id}", headers=headers)
            
            if analysis_response.status_code == 200:
                analysis_data = analysis_response.json()
                return format_virustotal_report(analysis_data, 'url', url)
            else:
                return f"    ⚠️ Could not retrieve analysis (Status: {analysis_response.status_code})"
        else:
            return f"    ⚠️ URL scan failed (Status: {response.status_code})"
            
    except Exception as e:
        return f"    ❌ Error scanning URL: {e}"

def scan_file_hash_virustotal(file_hash):
    """Looks up a file hash in VirusTotal database."""
    if not VIRUSTOTAL_API_KEY:
        return "    ⚠️ VirusTotal API key not configured"
    
    rate_limit_check()
    
    headers = {
        'x-apikey': VIRUSTOTAL_API_KEY
    }
    
    try:
        print(f"    Checking file hash with VirusTotal: {file_hash[:16]}...")
        response = requests.get(f"{VIRUSTOTAL_FILE_SCAN}/{file_hash}", headers=headers)
        
        if response.status_code == 200:
            result = response.json()
            return format_virustotal_report(result, 'file', file_hash)
        elif response.status_code == 404:
            return "    ℹ️ File hash not found in VirusTotal database (likely safe/new file)"
        else:
            return f"    ⚠️ File lookup failed (Status: {response.status_code})"
            
    except Exception as e:
        return f"    ❌ Error checking file hash: {e}"

def download_and_scan_attachment(service, user_id, message_id, attachment_id, filename):
    """Downloads attachment and scans it with VirusTotal."""
    if not VIRUSTOTAL_API_KEY:
        return "    ⚠️ VirusTotal API key not configured"
    
    try:
        print(f"    Downloading and scanning: {filename}")
        
        # Download the attachment
        attachment = service.users().messages().attachments().get(
            userId=user_id,
            messageId=message_id,
            id=attachment_id
        ).execute()
        
        file_data = base64.urlsafe_b64decode(attachment['data'].encode('UTF-8'))
        
        # Calculate SHA256 hash
        file_hash = hashlib.sha256(file_data).hexdigest()
        
        print(f"    File Hash (SHA-256): {file_hash[:32]}...")
        
        # Check if file exists in VirusTotal database
        return scan_file_hash_virustotal(file_hash)
        
    except Exception as e:
        return f"    ❌ Error downloading/scanning attachment: {e}"

def format_virustotal_report(data, scan_type, identifier):
    """Formats the VirusTotal report for display."""
    try:
        if scan_type == 'url':
            stats = data['data']['attributes']['stats']
            report = f"\n    {'='*50}\n"
            report += f"    VirusTotal URL Scan Report\n"
            report += f"    URL: {identifier[:60]}...\n"
            report += f"    {'='*50}\n"
        else:
            stats = data['data']['attributes']['last_analysis_stats']
            report = f"\n    {'='*50}\n"
            report += f"    VirusTotal File Scan Report\n"
            report += f"    Hash: {identifier[:32]}...\n"
            report += f"    {'='*50}\n"
        
        malicious = stats.get('malicious', 0)
        suspicious = stats.get('suspicious', 0)
        harmless = stats.get('harmless', 0)
        undetected = stats.get('undetected', 0)
        
        total_scans = malicious + suspicious + harmless + undetected
        
        report += f"    🔴 Malicious: {malicious}\n"
        report += f"    🟡 Suspicious: {suspicious}\n"
        report += f"    🟢 Harmless: {harmless}\n"
        report += f"    ⚪ Undetected: {undetected}\n"
        report += f"    Total Scans: {total_scans}\n"
        
        if malicious > 0:
            report += f"\n    ⚠️ WARNING: Detected as MALICIOUS by {malicious} vendor(s)!\n"
        elif suspicious > 0:
            report += f"\n    ⚠️ CAUTION: Flagged as SUSPICIOUS by {suspicious} vendor(s)\n"
        else:
            report += f"\n    ✅ No threats detected\n"
        
        report += f"    {'='*50}\n"
        return report
        
    except Exception as e:
        return f"    ❌ Error formatting report: {e}"

def extract_urls_from_text(text):
    """Extracts URLs from email body text."""
    url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
    urls = re.findall(url_pattern, text)
    return list(set(urls))  # Remove duplicates

# --- Authentication Flow ---
def get_gmail_service():
    """Handles OAuth 2.0 authentication and builds the Gmail service object."""
    creds = None
    if os.path.exists('token.json'):
        creds = Credentials.from_authorized_user_file('token.json', SCOPES)
    
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            try:
                flow = InstalledAppFlow.from_client_secrets_file(CREDENTIALS_FILE, SCOPES)
                creds = flow.run_local_server(port=0)
            except FileNotFoundError:
                print(f"\n❌ FATAL ERROR: Credentials file '{CREDENTIALS_FILE}' not found.")
                print("Please ensure your OAuth credentials file is in the same directory.")
                return None
            except Exception as e:
                print(f"\n❌ An error occurred during authentication setup: {e}")
                return None

        with open('token.json', 'w') as token:
            token.write(creds.to_json())

    try:
        service = build('gmail', 'v1', credentials=creds)
        return service
    except HttpError as error:
        print(f'❌ An API build error occurred: {error}')
        return None

# --- User Options ---
def get_user_options(service):
    """Asks the user for the folder, max results, date filters, and search query."""
    
    try:
        results = service.users().labels().list(userId='me').execute()
        labels = results.get('labels', [])
        
        print("\n--- Folder/Label Selection ---")
        label_options = {}
        
        common_labels = ['INBOX', 'SPAM', 'SENT', 'TRASH', 'STARRED', 'DRAFT']
        for i, name in enumerate(common_labels):
            label_options[str(i+1)] = name
            print(f"{i+1}: {name}")

        custom_index = len(common_labels) + 1
        for label in labels:
            if label['name'] not in common_labels and not label['name'].startswith('CATEGORY_') and label['name'] not in label_options.values():
                label_options[str(custom_index)] = label['name']
                print(f"{custom_index}: {label['name']}")
                custom_index += 1

        choice = input(f"Enter your choice (1-{custom_index-1}) or type a custom label: ").strip()
        selected_label = label_options.get(choice, choice)

        if selected_label.startswith('CATEGORY_'):
            print("⚠️ Warning: Fetching emails from a category label might not return all expected results.")
        
    except Exception:
        print("Could not fetch labels. Using common defaults.")
        label_options = {'1': 'INBOX', '2': 'SPAM', '3': 'ALL'}
        print("1: INBOX | 2: SPAM | 3: ALL")
        choice = input("Enter your choice (1, 2, or 3): ").strip()
        selected_label = label_options.get(choice, 'INBOX')

    while True:
        try:
            max_results = int(input(f"\nHow many emails do you want to fetch from '{selected_label}'? (Max 100): ").strip() or 10)
            if 1 <= max_results <= 100:
                break
            else:
                print("Please enter a number between 1 and 100.")
        except ValueError:
            print("Invalid input. Please enter a number.")

    query = f"in:{selected_label}"
    
    while True:
        before_date_str = input("\nFilter: Enter end date (YYYY-MM-DD) or leave blank: ").strip()
        if not before_date_str:
            break
        try:
            datetime.strptime(before_date_str, '%Y-%m-%d')
            query += f" before:{before_date_str}"
            break
        except ValueError:
            print("Invalid date format. Please use YYYY-MM-DD.")
            
    while True:
        after_date_str = input("Filter: Enter start date (YYYY-MM-DD) or leave blank: ").strip()
        if not after_date_str:
            break
        try:
            datetime.strptime(after_date_str, '%Y-%m-%d')
            query += f" after:{after_date_str}"
            break
        except ValueError:
            print("Invalid date format. Please use YYYY-MM-DD.")

    print("\n--- Search Filter ---")
    search_type = input("Filter by (1) Domain (from:domain.com) or (2) Email Address (from:user@domain.com)? (1 or 2, default 1): ").strip() or '1'
    search_term = input("Enter the Domain or Email Address to search (or leave blank): ").strip()
    
    if search_term:
        if search_type == '2':
            query += f" from:\"{search_term}\""
        else:
            query += f" from:@{search_term}"
            
    print(f"\n✅ FINAL QUERY: {query}")
    return selected_label, max_results, query

# --- Message Fetching and Analysis ---
def fetch_and_hash_emails(service, query, max_results, label, user_id='me', enable_vt_scan=True):
    """Lists messages, fetches content, hashes them, and scans with VirusTotal."""
    
    print(f"\n--- Fetching up to {max_results} emails from '{label}' ---")
    
    try:
        results = service.users().messages().list(
            userId=user_id,
            q=query,
            maxResults=max_results
        ).execute()
        
        messages = results.get('messages', [])

        if not messages:
            print(f"No messages found matching your criteria.")
            return []

        print(f"Found {len(messages)} message(s). Processing...\n")
        
        def get_body_data(payload):
            if 'parts' in payload:
                for part in payload['parts']:
                    if part['mimeType'] == 'text/plain' and part['body'].get('data'):
                        return part['body']['data']
                    body_data = get_body_data(part)
                    if body_data:
                        return body_data
            return payload['body'].get('data')

        def get_attachments(payload):
            """Extracts attachment information from email."""
            attachments = []
            if 'parts' in payload:
                for part in payload['parts']:
                    if part.get('filename'):
                        attachments.append({
                            'filename': part['filename'],
                            'mimeType': part['mimeType'],
                            'size': part['body'].get('size', 0),
                            'attachmentId': part['body'].get('attachmentId')
                        })
                    if 'parts' in part:
                        attachments.extend(get_attachments(part))
            return attachments
        
        email_data = []
        
        for i, msg_info in enumerate(messages):
            message_id = msg_info['id']

            msg = service.users().messages().get(
                userId=user_id, 
                id=message_id, 
                format='full'
            ).execute()

            def get_header(name):
                return next((h['value'] for h in msg['payload']['headers'] if h['name'] == name), 'N/A')

            subject = get_header('Subject')
            sender = get_header('From')
            date = get_header('Date')

            encoded_data = get_body_data(msg['payload'])
            
            hex_digest = "N/A (No text body found)"
            body_text = ""
            ai_verdict = "NO_BODY"
            
            if encoded_data:
                try:
                    decoded_bytes = base64.urlsafe_b64decode(encoded_data.encode('utf-8'))
                    body_text = decoded_bytes.decode('utf-8')
                    
                    ai_verdict = get_ai_prediction(body_text)
                    
                    hash_object = hashlib.sha256(body_text.encode('utf-8'))
                    hex_digest = hash_object.hexdigest()
                except Exception as e:
                    hex_digest = f"ERROR HASHING: {e}"
                    ai_verdict = "ERROR"

            print(f"\n{'='*60}")
            print(f"[{i+1}/{len(messages)}] ID: {message_id}")
            print(f"  Date: {date}")
            print(f"  From: {sender}")
            print(f"  Subject: {subject}")
            
            if ai_verdict == "SPAM":
                color_dot = "🔴"
            elif ai_verdict == "HAM":
                color_dot = "🟢"
            else:
                color_dot = "⚪"
            print(f"  AI Verdict: {color_dot} {ai_verdict}")
            
            print(f"  Hash (SHA-256): {hex_digest}")
            print(f"  Snippet: {msg.get('snippet', 'No Snippet')}")
            
            # Extract and scan URLs
            url_results = []
            if body_text and enable_vt_scan:
                urls = extract_urls_from_text(body_text)
                if urls:
                    print(f"\n  📎 Found {len(urls)} URL(s) in email body:")
                    for url in urls[:3]:  # Limit to 3 URLs to avoid rate limits
                        print(f"    URL: {url[:60]}...")
                        if VIRUSTOTAL_API_KEY:
                            vt_report = scan_url_virustotal(url)
                            print(vt_report)
                            url_results.append({'url': url, 'report': vt_report})
                        else:
                            print("    ⚠️ VirusTotal API key not configured")
                    
                    if len(urls) > 3:
                        print(f"    ... and {len(urls) - 3} more URL(s) (skipped to avoid rate limits)")
            
            # Check for attachments
            attachment_results = []
            attachments = get_attachments(msg['payload'])
            if attachments:
                print(f"\n  📁 Found {len(attachments)} attachment(s):")
                for att in attachments[:3]:  # Limit to 3 attachments to avoid rate limits
                    print(f"    File: {att['filename']} ({att['mimeType']}, {att['size']} bytes)")
                    if VIRUSTOTAL_API_KEY and att.get('attachmentId') and enable_vt_scan:
                        vt_report = download_and_scan_attachment(
                            service, 
                            user_id, 
                            message_id, 
                            att['attachmentId'],
                            att['filename']
                        )
                        print(vt_report)
                        attachment_results.append({'filename': att['filename'], 'report': vt_report})
                    else:
                        print("    ℹ️ Skipping VirusTotal scan (API key not configured or disabled)")
                
                if len(attachments) > 3:
                    print(f"    ... and {len(attachments) - 3} more attachment(s) (skipped to avoid rate limits)")
            
            print(f"{'='*60}")
            
            # Store email data for potential UI use
            email_data.append({
                'id': message_id,
                'date': date,
                'from': sender,
                'subject': subject,
                'ai_verdict': ai_verdict,
                'hash': hex_digest,
                'snippet': msg.get('snippet', 'No Snippet'),
                'urls': url_results,
                'attachments': attachment_results
            })
        
        return email_data
            
    except HttpError as error:
        print(f'\n❌ An error occurred during API call: {error}')
        return []


if __name__ == '__main__':
    print("="*60)
    print("Gmail Email Scanner with VirusTotal Integration")
    print("="*60)
    
    if not VIRUSTOTAL_API_KEY:
        print("\n⚠️ WARNING: VirusTotal API key not configured!")
        print("Set VIRUSTOTAL_API_KEY in your .env file")
        print("Get your free API key at: https://www.virustotal.com/gui/join-us")
        print("\nContinuing without VirusTotal scanning...\n")
    else:
        print("\n✅ VirusTotal API key loaded successfully\n")
    
    service = get_gmail_service()
    if service:
        label, max_results, query = get_user_options(service)
        fetch_and_hash_emails(service, query, max_results, label)
#!/usr/bin/python3

# ASCII Art Banner
BANNER = r'''
       _     _     _     ____                    
 _ __ | |__ (_)___| |__ |  _ \ __ _ _ __ ___  ___
| '_ \| '_ \| / __| '_ \| |_) / _` | '__/ __/ _  \
| |_) | | | | \__ \ | | |  __/ (_| | |  \__ \  __/
| .__/|_| |_|_|___/_| |_|_|   \__,_|_|  |___\___|
|_|                  phishParse v1.1
'''

import re
import extract_msg
from email.parser import BytesParser
from email import policy
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import os
import hashlib
from functools import lru_cache
from typing import Dict, List, Optional, Set, Tuple
import sys
from datetime import datetime
import requests
import time
import base64
import dns.resolver
import whois
from ipwhois import IPWhois
from ipaddress import ip_address
import quopri
import urllib.parse
import mimetypes

# Cache compiled regex patterns
URL_PATTERN = re.compile(r'(https?://\S+)')
IP_PATTERN = re.compile(r'[\d]+\.[\d]+\.[\d]+\.[\d]+')
DEFANG_PATTERNS = [
    (re.compile(r'\.'), '[.]'),
    (re.compile(r':'), '[:]'),
    (re.compile(r'http'), 'hXXp')
]

# Cache suspicious file extensions and mime types
SUSPICIOUS_EXTENSIONS: Set[str] = {'.exe', '.bat', '.js', '.vbs', '.scr', '.jar'}
SUSPICIOUS_MIME_TYPES: Set[str] = {
    'application/x-msdownload',
    'application/x-msdos-program',
    'application/x-executable',
    'application/x-shellscript'
}
SUSPICIOUS_KEYWORDS: Set[str] = {
    'urgent', 'confirm', 'action required', 'verify',
    'suspicious activity', 'password reset', 'account blocked'
}

# Check if the terminal supports colors
def supports_color():
    """Check if the terminal supports color output."""
    if os.getenv('NO_COLOR') is not None:
        return False
    
    # Check if we're in a terminal
    if not hasattr(sys.stdout, 'isatty'):
        return False
    if not sys.stdout.isatty():
        return False
    
    # Check platform-specific cases
    plat = sys.platform
    supported_platform = plat != 'Pocket PC' and (plat != 'win32' or 'ANSICON' in os.environ)
    
    return supported_platform

# Use this to conditionally apply colors
BLUE = "\033[34m" if supports_color() else ""
RED = "\033[31m" if supports_color() else ""
WHITE = "\033[37m" if supports_color() else ""
BLUE_BOLD = "\033[1;34m" if supports_color() else ""
RESET = "\033[0m" if supports_color() else ""
PURPLE = "\033[35m" if supports_color() else ""

# Add these constants at the top
SECTION_WIDTH = 60
SEPARATOR = "=" * SECTION_WIDTH
SUBSEPARATOR = "-" * SECTION_WIDTH

# Add this with the other constants
VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY')  # User needs to set this environment variable
VIRUSTOTAL_TIMEOUT = 30  # Timeout in seconds for VirusTotal API requests

# Add this near the top of the script with other comments
"""
To use VirusTotal integration:
1. Sign up for a VirusTotal account at https://www.virustotal.com
2. Get your API key from your profile
3. Set the environment variable before running the script:
   export VIRUSTOTAL_API_KEY='USE_YOUR_OWN_API_KEY'
"""

@lru_cache(maxsize=128)
def defang_url(url: str) -> str:
    """Cache defanged URLs to avoid recomputing."""
    result = url
    for pattern, replacement in DEFANG_PATTERNS:
        result = pattern.sub(replacement, result)
    return result

@lru_cache(maxsize=128)
def defang_ip(ip_address: Optional[str]) -> Optional[str]:
    """Cache defanged IPs to avoid recomputing."""
    if ip_address is None:
        return None
    return re.sub(r'\.', '[.]', ip_address)

@lru_cache(maxsize=128)
def undefang_ip(ip_address: Optional[str]) -> Optional[str]:
    """Cache undefanged IPs to avoid recomputing."""
    if ip_address is None:
        return None
    return re.sub(r'\[\.\]', '.', ip_address)

def clean_url(url: str) -> str:
    """Clean and decode URLs before sending to VirusTotal."""
    try:
        # First decode any URL-encoded characters
        decoded_url = url.encode('utf-8').decode('unicode_escape')
        
        # Parse the URL
        parsed = urlparse(decoded_url)
        
        # Reconstruct the URL without tracking parameters
        clean_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        
        # Handle query parameters
        if parsed.query:
            # Keep only essential query parameters
            query_params = {}
            for param in parsed.query.split('&'):
                if '=' in param:
                    key, value = param.split('=', 1)
                    # Remove common tracking parameters
                    if key.lower() not in ['utm_source', 'utm_campaign', 'utm_medium', 'utm_term', 
                                         'utm_content', 'utm_id', 's', 'e', 'elqTrackId', 'elq', 
                                         'elqaid', 'elqat', 'elqak']:
                        query_params[key] = value
            if query_params:
                clean_url += '?' + '&'.join(f"{k}={v}" for k, v in query_params.items())
        
        return clean_url
    except Exception as e:
        print(f"Error cleaning URL {url}: {str(e)}")
        return url

def decode_quoted_printable(text):
    """Decode quoted-printable encoded text."""
    try:
        return quopri.decodestring(text.encode('utf-8')).decode('utf-8', errors='ignore')
    except:
        return text

def extract_links_from_text(text):
    """More efficient link extraction using pre-compiled pattern."""
    # Decode any URL-encoded characters in the text
    try:
        # First try to decode as unicode escape sequences
        try:
            decoded_text = text.encode('utf-8').decode('unicode-escape')
        except:
            decoded_text = text
        # Then try to decode as URL-encoded
        try:
            decoded_text = urllib.parse.unquote(decoded_text)
        except:
            pass
    except:
        decoded_text = text
    urls = URL_PATTERN.findall(decoded_text)
    return [clean_url(url) for url in urls]

def extract_links_from_html(html_content):
    """Extract links from HTML content, handling encoded URLs."""
    links = []
    try:
        # Handle different content types and encodings
        if isinstance(html_content, bytes):
            try:
                html_content = html_content.decode('utf-8', errors='ignore')
            except:
                html_content = html_content.decode('latin-1', errors='ignore')
        
        # Decode any quoted-printable content
        html_content = decode_quoted_printable(html_content)
        
        # Clean up common HTML email artifacts
        html_content = html_content.replace('=\n', '')  # Remove soft line breaks
        html_content = html_content.replace('=3D', '=')  # Decode equals signs
        
        # Try to decode unicode escape sequences
        try:
            html_content = html_content.encode('utf-8').decode('unicode-escape')
        except:
            pass
        
        # Try to decode URL-encoded content
        try:
            html_content = urllib.parse.unquote(html_content)
        except:
            pass
        
        soup = BeautifulSoup(html_content, "html.parser")
        
        # Extract href attributes from anchor tags
        anchor_tags = soup.find_all('a', href=True)
        
        for a in anchor_tags:
            href = a.get('href')
            if href:
                # Clean up the href
                href = href.strip()
                href = decode_quoted_printable(href)
                
                # Try to decode unicode escape sequences
                try:
                    href = href.encode('utf-8').decode('unicode-escape')
                except:
                    pass
                
                # Try to decode URL-encoded content
                try:
                    href = urllib.parse.unquote(href)
                except:
                    pass
                
                # Handle mailto: links
                if href.startswith('mailto:'):
                    continue
                
                # Handle relative URLs
                if not href.startswith(('http://', 'https://')):
                    continue
                
                cleaned_url = clean_url(href)
                links.append(cleaned_url)
        
        # Also extract URLs from text content that might be in HTML
        text_content = soup.get_text()
        # Clean up the text content
        text_content = decode_quoted_printable(text_content)
        text_content = text_content.replace('=\n', '')
        text_content = text_content.replace('=3D', '=')
        
        # Try to decode unicode escape sequences
        try:
            text_content = text_content.encode('utf-8').decode('unicode-escape')
        except:
            pass
        
        # Try to decode URL-encoded content
        try:
            text_content = urllib.parse.unquote(text_content)
        except:
            pass
        
        # Look for URLs in the text
        urls = URL_PATTERN.findall(text_content)
        for url in urls:
            url = url.strip()
            url = decode_quoted_printable(url)
            
            # Try to decode unicode escape sequences
            try:
                url = url.encode('utf-8').decode('unicode-escape')
            except:
                pass
            
            # Try to decode URL-encoded content
            try:
                url = urllib.parse.unquote(url)
            except:
                pass
            
            cleaned_url = clean_url(url)
            links.append(cleaned_url)
        
        # Remove duplicates while preserving order
        seen = set()
        unique_links = []
        for link in links:
            if link not in seen:
                seen.add(link)
                unique_links.append(link)
        
        return unique_links
    except Exception:
        return []

def extract_email_info(email_bytes, file_type):
    if file_type == "msg":
        # Handle Outlook .msg file
        msg = extract_msg.Message(email_bytes)
        subject = msg.subject
        sender = msg.sender
        date = msg.date
        
        # Initialize variables
        body = ""
        html_body = ""
        links = []
        attachments = []
        
        # Get the body content
        if hasattr(msg, 'body'):
            try:
                body = msg.body
                if isinstance(body, bytes):
                    try:
                        body = body.decode('utf-8', errors='ignore')
                    except:
                        body = body.decode('latin-1', errors='ignore')
                body = decode_quoted_printable(body)
                body_links = extract_links_from_text(body)
                links.extend(body_links)
            except Exception as e:
                print(f"Error extracting body: {str(e)}")
                body = "Error extracting body content"
        
        # Get HTML content if available
        if hasattr(msg, 'htmlBody'):
            try:
                html_body = msg.htmlBody
                if isinstance(html_body, bytes):
                    try:
                        html_body = html_body.decode('utf-8', errors='ignore')
                    except:
                        html_body = html_body.decode('latin-1', errors='ignore')
                html_body = decode_quoted_printable(html_body)
                html_links = extract_links_from_html(html_body)
                links.extend(html_links)
            except Exception as e:
                print(f"Error extracting HTML body: {str(e)}")
        
        # Extract links from all available parts
        for attachment in msg.attachments:
            try:
                if hasattr(attachment, 'data') and attachment.data:
                    content = attachment.data
                    if isinstance(content, bytes):
                        try:
                            content = content.decode('utf-8', errors='ignore')
                        except:
                            content = content.decode('latin-1', errors='ignore')
                    content = decode_quoted_printable(content)
                    attachment_links = extract_links_from_text(content)
                    links.extend(attachment_links)
            except Exception as e:
                print(f"Error extracting links from attachment: {str(e)}")
            metadata = extract_attachment_metadata(attachment, file_type="msg")
            attachments.append(metadata)
        
        sender_ip = msg.header.get("Received", [])  # IP extraction is not available from .msg files directly
        reply_to_address = msg.header.get("Reply-To", None)

        # Extract recipients (To, Cc, Bcc)
        to = msg.to
        cc = msg.cc
        bcc = msg.bcc
    elif file_type == "eml":
        # Handle standard .eml email file
        msg = BytesParser(policy=policy.default).parsebytes(email_bytes)
        subject = msg['subject']
        sender = msg['from']
        date = msg['date']
        reply_to_address = msg['reply-to']

        # Extract sender's IP address from the 'Received' headers
        sender_ip = extract_sender_ip_from_email(msg)
        sender_ip = defang_ip(sender_ip)

        # Extract the body (handling plain text and HTML parts)
        body = ""
        html_body = ""
        links = []

        # Process all parts of the email
        for part in msg.walk():
            try:
                content_type = part.get_content_type()
                content_disposition = str(part.get('Content-Disposition', ''))
                
                # Skip attachments
                if 'attachment' in content_disposition.lower():
                    continue
                
                # Get the payload
                payload = part.get_payload(decode=True)
                if not payload:
                    continue
                
                # Handle different content types
                if content_type == 'text/html':
                    if isinstance(payload, bytes):
                        try:
                            html_content = payload.decode('utf-8', errors='ignore')
                        except:
                            html_content = payload.decode('latin-1', errors='ignore')
                    else:
                        html_content = payload
                    
                    # Clean up the HTML content
                    html_content = decode_quoted_printable(html_content)
                    html_content = html_content.replace('=\n', '')
                    html_content = html_content.replace('=3D', '=')
                    
                    html_links = extract_links_from_html(html_content)
                    links.extend(html_links)
                    html_body = html_content
                
                elif content_type == 'text/plain':
                    if isinstance(payload, bytes):
                        try:
                            text_content = payload.decode('utf-8', errors='ignore')
                        except:
                            text_content = payload.decode('latin-1', errors='ignore')
                    else:
                        text_content = payload
                    
                    # Clean up the text content
                    text_content = decode_quoted_printable(text_content)
                    text_content = text_content.replace('=\n', '')
                    text_content = text_content.replace('=3D', '=')
                    
                    text_links = extract_links_from_text(text_content)
                    links.extend(text_links)
                    body = text_content
                
            except Exception as e:
                print(f"Error processing email part: {str(e)}")
                continue

        # Extract attachments with metadata
        attachments = []
        for part in msg.iter_attachments():
            metadata = extract_attachment_metadata(part, file_type="eml")
            attachments.append(metadata)

        # Extract recipients (To, Cc, Bcc)
        to = msg['to']
        cc = msg.get('cc', '')
        bcc = msg.get('bcc', '')

    else:
        raise ValueError("Unsupported file type")

    # If we have HTML but no plain text, try to extract text from HTML
    if not body and html_body:
        try:
            soup = BeautifulSoup(html_body, 'html.parser')
            body = soup.get_text(separator=' ', strip=True)
        except Exception as e:
            print(f"Error converting HTML to text: {str(e)}")
            body = "Error converting HTML content to text"

    # Return email info in a consistent format
    email_info = {
        "subject": subject,
        "sender": sender,
        "to": to,
        "cc": cc,
        "bcc": bcc,
        "reply_to_address": reply_to_address,
        "date": date,
        "body": body,
        "links": links,
        "attachments": attachments,
        "sender_ip": sender_ip
    }

    return email_info

def extract_sender_ip_from_email(msg) -> Optional[str]:
    """More efficient IP extraction using pre-compiled pattern."""
    received_headers = msg.get_all('Received')
    if not received_headers:
        return None
    
    for header in received_headers:
        ip_match = IP_PATTERN.search(header)
        if ip_match:
            return ip_match.group(0)
    return None

def extract_attachment_metadata(part, file_type: str = "eml") -> Dict:
    """Optimized metadata extraction with type hints."""
    if file_type == "eml":
        payload = part.get_payload(decode=True) if part.get_payload() else None
        
        metadata = {
            "filename": part.get_filename(),
            "content_type": part.get_content_type(),
            "size": len(payload) if payload else 0,
            "sha256": hashlib.sha256(payload).hexdigest() if payload else None,
            "content_disposition": part.get("Content-Disposition", ""),
            "content_transfer_encoding": part.get("Content-Transfer-Encoding", ""),
            "content_id": part.get("Content-ID", ""),
            "x_unix_mode": None
        }
        
        # Only check for unix mode if content type parameters exist
        if part.get_params(header="Content-Type", unquote=True):
            for param in part.get_params(header="Content-Type", unquote=True):
                if param[0] == "x-unix-mode":
                    metadata["x_unix_mode"] = param[1]
                    break
        
        return metadata
    
    # MSG file attachment handling
    try:
        data = part.data if hasattr(part, 'data') else None
        
        # Handle missing filename
        filename = None
        if hasattr(part, 'filename'):
            filename = part.filename
        elif hasattr(part, 'longFilename'):
            filename = part.longFilename
        elif hasattr(part, 'shortFilename'):
            filename = part.shortFilename
        else:
            # Generate a default filename based on content type and size
            content_type = getattr(part, 'mime_type', 'application/octet-stream')
            ext = mimetypes.guess_extension(content_type) or '.bin'
            filename = f"attachment_{len(data) if data else 0}{ext}"
        
        return {
            "filename": filename,
            "content_type": getattr(part, 'mime_type', None),
            "size": len(data) if data else 0,
            "sha256": hashlib.sha256(data).hexdigest() if data else None,
            "content_disposition": None,
            "content_transfer_encoding": None,
            "content_id": None,
            "x_unix_mode": None
        }
    except Exception as e:
        print(f"Error processing attachment metadata: {str(e)}")
        # Return minimal metadata with error information
        return {
            "filename": "unknown_attachment",
            "content_type": "application/octet-stream",
            "size": 0,
            "sha256": None,
            "content_disposition": None,
            "content_transfer_encoding": None,
            "content_id": None,
            "x_unix_mode": None,
            "error": str(e)
        }

def format_section_header(title: str) -> str:
    """Create a formatted section header."""
    return f"\n{RED}{title}{RESET}\n{SEPARATOR}"

def format_subsection_header(title: str) -> str:
    """Create a formatted subsection header."""
    return f"\n{RED}{title}{RESET}\n{SUBSEPARATOR}"

def format_field(label: str, value: str) -> str:
    """Format a field with its label and value."""
    if not value:
        value = "None"
    return f"{BLUE_BOLD}{label}{RESET}: {value}"

def format_list_items(items: List[str]) -> str:
    """Format a list of items with proper indentation."""
    if not items:
        return "None"
    return "\n  • " + "\n  • ".join(items)

def check_virustotal_url(url: str, force_fresh: bool = False) -> Dict:
    """Check a URL against VirusTotal API."""
    if not VIRUSTOTAL_API_KEY:
        return {"error": "No VirusTotal API key provided"}
    
    headers = {
        "accept": "application/json",
        "x-apikey": VIRUSTOTAL_API_KEY
    }
    
    try:
        # Clean the URL before checking with VirusTotal
        cleaned_url = clean_url(url)
        
        # Create the URL ID using URL-safe base64 encoding
        url_id = base64.urlsafe_b64encode(cleaned_url.encode()).decode().strip("=")
        
        # First, submit the URL for analysis
        submit_url = "https://www.virustotal.com/api/v3/urls"
        form_data = f"url={cleaned_url}"
        headers["content-type"] = "application/x-www-form-urlencoded"
        submit_response = requests.post(submit_url, headers=headers, data=form_data, timeout=VIRUSTOTAL_TIMEOUT)
        
        if submit_response.status_code != 200:
            return {"error": f"URL submission error: {submit_response.status_code}"}
        
        # Wait for initial processing
        time.sleep(15)  # Wait 15 seconds for initial processing
        
        # Try to get the report with retries
        max_retries = 5
        retry_delay = 15  # seconds to wait between retries
        
        for attempt in range(max_retries):
            # Get the URL report
            report_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
            response = requests.get(report_url, headers=headers, timeout=VIRUSTOTAL_TIMEOUT)
            
            if response.status_code == 200:
                data = response.json()
                stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                
                # If we have results, return them
                if stats:
                    # Create the GUI URL
                    gui_url = f"https://www.virustotal.com/gui/url/{url_id}"
                    return {
                        "found": True,
                        "malicious": stats.get('malicious', 0),
                        "suspicious": stats.get('suspicious', 0),
                        "undetected": stats.get('undetected', 0),
                        "harmless": stats.get('harmless', 0),
                        "timeout": stats.get('timeout', 0),
                        "total_scans": sum(stats.values()) if stats else 0,
                        "scan_id": url_id,
                        "gui_url": gui_url
                    }
            
            # If this was the last attempt, return a message
            if attempt == max_retries - 1:
                return {
                    "found": False,
                    "message": "Analysis still in progress. Please try again in a few moments."
                }
            
            # Wait before next retry
            time.sleep(retry_delay)
        
        return {"error": "Maximum retries exceeded"}
            
    except Exception as e:
        return {"error": str(e)}

def analyze_phishing(email_info: Dict, enable_virustotal: bool = False, force_fresh: bool = False) -> Tuple[Set[str], List[Dict], List[Dict]]:
    """Optimized phishing analysis with type hints."""
    body = email_info["body"].lower()
    suspicious_links = []
    suspicious_attachments = []

    # Keywords analysis
    found_keywords = SUSPICIOUS_KEYWORDS.intersection(body.split())
    if found_keywords:
        print(format_subsection_header("Suspicious Keywords"))
        print(format_list_items(found_keywords))

    # Links analysis
    if email_info["links"]:
        print(format_subsection_header("URL Analysis"))
        # Convert to set to remove duplicates while preserving order
        unique_urls = []
        seen_urls = set()
        for url in email_info["links"]:
            if url not in seen_urls:
                seen_urls.add(url)
                unique_urls.append(url)
                
        for original_url in unique_urls:
            # Display the defanged URL for safety
            print(f"\n{BLUE_BOLD}URL{RESET}: {defang_url(original_url)}")
            
            if enable_virustotal:
                # Submit to VirusTotal if enabled
                vt_results = check_virustotal_url(original_url, force_fresh)
                
                print(f"  {BLUE_BOLD}VirusTotal Results{RESET}:")
                if vt_results.get('error'):
                    print(format_field("    Status", f"Error: {vt_results['error']}"))
                elif not vt_results.get('found'):
                    print(format_field("    Status", vt_results.get('message', 'Analysis in progress')))
                else:
                    print(format_field("    Malicious", str(vt_results['malicious'])))
                    print(format_field("    Suspicious", str(vt_results['suspicious'])))
                    print(format_field("    Harmless", str(vt_results['harmless'])))
                    print(format_field("    Undetected", str(vt_results['undetected'])))
                    print(format_field("    Timeout", str(vt_results['timeout'])))
                    print(format_field("    Total Scans", str(vt_results['total_scans'])))
                    print(format_field("    Scan ID", vt_results['scan_id']))
                    print(format_field("    VirusTotal URL", vt_results['gui_url']))
                
                if vt_results.get("malicious", 0) > 0 or vt_results.get("suspicious", 0) > 0:
                    suspicious_links.append({
                        "url": original_url,
                        "vt_results": vt_results
                    })
            else:
                # Just store the URL without VirusTotal results
                suspicious_links.append({
                    "url": original_url,
                    "vt_results": None
                })

    # Attachments analysis
    if email_info["attachments"]:
        for attachment in email_info["attachments"]:
            reasons = []
            filename = attachment["filename"]
            
            if filename:
                ext = os.path.splitext(filename.lower())[1]
                if ext in SUSPICIOUS_EXTENSIONS:
                    reasons.append("Suspicious file extension")

            content_type = attachment["content_type"]
            if content_type in SUSPICIOUS_MIME_TYPES:
                reasons.append("Suspicious MIME type")

            if attachment["size"] > 10 * 1024 * 1024:
                reasons.append("Large file size")

            x_unix_mode = attachment["x_unix_mode"]
            if x_unix_mode in {"0755", "0777"}:
                reasons.append("Executable permissions")

            if reasons:
                suspicious_attachments.append({
                    "filename": filename,
                    "reasons": reasons,
                    "metadata": attachment
                })

    return found_keywords, suspicious_links, suspicious_attachments

def print_attachments(attachments: List[Dict], suspicious_attachments: List[Dict], enable_virustotal: bool = False) -> None:
    """Print attachment information in a consolidated way."""
    print(format_subsection_header("Attachments"))
    
    if not attachments:
        print("No attachments found.")
        return

    # Create a set of suspicious filenames for quick lookup
    suspicious_filenames = {att['filename'] for att in suspicious_attachments}

    for idx, attachment in enumerate(attachments, 1):
        filename = attachment['filename']
        print(f"\n{BLUE_BOLD}Attachment {idx}{RESET}")
        print(format_field("  Filename", filename))
        print(format_field("  Size", f"{attachment['size']:,} bytes"))
        print(format_field("  Type", attachment['content_type']))
        print(format_field("  SHA256", attachment['sha256']))
        if attachment['x_unix_mode']:
            print(format_field("  Unix Mode", attachment['x_unix_mode']))
        
        # Add VirusTotal check only if enabled
        if enable_virustotal and attachment['sha256']:
            vt_results = check_virustotal(attachment['sha256'])
            print(f"\n  {BLUE_BOLD}VirusTotal Results{RESET}:")
            if vt_results.get('error'):
                print(format_field("    Status", f"Error: {vt_results['error']}"))
            elif not vt_results.get('found'):
                print(format_field("    Status", "File not found in VirusTotal database"))
            else:
                print(format_field("    Malicious Detections", f"{RED}{str(vt_results['malicious'])}{RESET}" if vt_results['malicious'] > 0 else str(vt_results['malicious'])))
                print(format_field("    Suspicious Detections", str(vt_results['suspicious'])))
                print(format_field("    Clean Scans", str(vt_results['undetected'])))
                print(format_field("    Total Scans", str(vt_results['total_scans'])))
                print(format_field("    VirusTotal URL", vt_results['gui_url']))
            
        # If this is a suspicious attachment, print the reasons
        if filename in suspicious_filenames:
            susp_att = next(sa for sa in suspicious_attachments if sa['filename'] == filename)
            print(f"\n  {BLUE_BOLD}⚠️ Security Concerns{RESET}:")
            print(format_field("  Reasons", format_list_items(susp_att['reasons'])))

def check_virustotal(file_hash: str) -> Dict:
    """Check a file hash against VirusTotal API."""
    if not VIRUSTOTAL_API_KEY:
        return {"error": "No VirusTotal API key provided"}
    
    headers = {
        "accept": "application/json",
        "x-apikey": VIRUSTOTAL_API_KEY
    }
    
    try:
        # Check if the hash exists in VirusTotal
        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        response = requests.get(url, headers=headers, timeout=VIRUSTOTAL_TIMEOUT)
        
        if response.status_code == 200:
            data = response.json()
            stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
            # Add the GUI URL for the file hash
            gui_url = f"https://www.virustotal.com/gui/file/{file_hash}"
            return {
                "found": True,
                "malicious": stats.get('malicious', 0),
                "suspicious": stats.get('suspicious', 0),
                "undetected": stats.get('undetected', 0),
                "total_scans": sum(stats.values()) if stats else 0,
                "gui_url": gui_url
            }
        elif response.status_code == 404:
            return {"found": False}
        else:
            return {"error": f"API error: {response.status_code}"}
            
    except Exception as e:
        return {"error": str(e)}

def get_mx_records(domain: str) -> List[str]:
    """Look up MX records for a domain."""
    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
        return [str(mx.exchange).rstrip('.') for mx in mx_records]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.Timeout):
        return []
    except Exception as e:
        print(f"Error looking up MX records for {domain}: {str(e)}")
        return []

def get_ip_whois_info(ip: str) -> Dict[str, str]:
    """Get WHOIS information for an IP address."""
    try:
        # First undefang the IP if needed
        clean_ip = undefang_ip(ip)
        if not clean_ip:
            return {
                "range": "Unknown",
                "org": "Unknown",
                "country": "Unknown"
            }
            
        # Check if it's a valid IP address
        ip_obj = ip_address(clean_ip)
        
        # Get WHOIS information
        obj = IPWhois(clean_ip)
        results = obj.lookup_rdap()
        
        # Extract relevant information
        whois_info = {
            "range": f"{results.get('asn_cidr', 'Unknown')}",
            "org": results.get('asn_description', 'Unknown'),
            "country": results.get('asn_country_code', 'Unknown')
        }
        
        return whois_info
    except Exception as e:
        print(f"Error getting WHOIS info for {ip}: {str(e)}")
        return {
            "range": "Unknown",
            "org": "Unknown",
            "country": "Unknown"
        }

def main():
    """Separate main function for better organization."""
    # Display banner in red, white, and blue
    banner_lines = BANNER.split('\n')
    print(f"\n{RED}{banner_lines[0]}{RESET}")  # Empty line
    print(f"{RED}{banner_lines[1]}{RESET}")    # First line
    print(f"{WHITE}{banner_lines[2]}{RESET}")  # Second line
    print(f"{BLUE}{banner_lines[3]}{RESET}")   # Third line
    print(f"{RED}{banner_lines[4]}{RESET}")    # Fourth line
    print(f"{WHITE}{banner_lines[5]}{RESET}")  # Fifth line
    print(f"{BLUE}{banner_lines[6]}{RESET}")   # Version line

    print(f"\n{BLUE}A tool for analyzing .eml and .msg files for potential phishing indicators{RESET}")
    print(f"{BLUE}Author: Russ McGlamery{RESET}\n")

    file_path = input(f"{BLUE_BOLD}Please enter the full path to the .msg or .eml file:{RESET} ").strip()
    
    # Ask if user wants to enable VirusTotal analysis
    enable_vt = input(f"{BLUE_BOLD}Enable VirusTotal analysis? (y/n):{RESET} ").strip().lower() == 'y'
    
    # Ask if user wants to force fresh VirusTotal analysis
    force_fresh = False
    if enable_vt:
        force_fresh = input(f"{BLUE_BOLD}Force fresh VirusTotal analysis? (y/n):{RESET} ").strip().lower() == 'y'

    if not os.path.isfile(file_path):
        print("[-] File does not exist. Please provide a valid file path.")
        return

    file_extension = os.path.splitext(file_path)[1].lower()
    if file_extension not in {".msg", ".eml"}:
        print("[-] Unsupported file format. Only .msg and .eml are supported.")
        return

    file_type = file_extension[1:]  # Remove the dot
    
    try:
        with open(file_path, "rb") as file:
            email_bytes = file.read()

        # Get file stats
        file_stats = os.stat(file_path)
        file_size = file_stats.st_size
        file_created = datetime.fromtimestamp(file_stats.st_ctime).strftime('%Y-%m-%d %H:%M:%S')
        file_modified = datetime.fromtimestamp(file_stats.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
        
        # Calculate file hash
        file_hash = hashlib.sha256(email_bytes).hexdigest()

        email_info = extract_email_info(email_bytes, file_type)
        
        # Print file information first
        print(format_section_header("File Details"))
        print(format_field("Filename", os.path.basename(file_path)))
        print(format_field("Location", os.path.dirname(os.path.abspath(file_path))))
        print(format_field("Type", file_type.upper()))
        print(format_field("Size", f"{file_size:,} bytes"))
        print(format_field("Created", file_created))
        print(format_field("Modified", file_modified))
        print(format_field("SHA256", file_hash))
        
        # Rest of the email analysis
        print(format_section_header("Email Analysis Results"))
        
        # Basic email information
        print(format_subsection_header("Basic Information"))
        print(format_field("Subject", email_info['subject']))
        print(format_field("Date", str(email_info['date'])))
        
        # Participant information
        print(format_subsection_header("Participants"))
        print(format_field("From", email_info['sender']))
        print(format_field("To", email_info['to']))
        print(format_field("Cc", email_info['cc']))
        print(format_field("Bcc", email_info['bcc']))
        print(format_field("Reply-To", email_info['reply_to_address']))
        
        # Technical details
        print(format_subsection_header("Technical Details"))
        if email_info['sender_ip']:
            print(format_field("Sender's IP", email_info['sender_ip']))
            # Get WHOIS information for the IP
            whois_info = get_ip_whois_info(email_info['sender_ip'])
            print(format_field("IP Range", whois_info['range']))
            print(format_field("Organization", whois_info['org']))
            print(format_field("Country", whois_info['country']))
        else:
            print(format_field("Sender's IP", "Not available"))
        
        # Extract domain from sender's email and get MX records
        if email_info['sender']:
            try:
                # Extract domain from email address
                domain = email_info['sender'].split('@')[-1].strip('<>')
                mx_records = get_mx_records(domain)
                if mx_records:
                    print(format_field("MX Records", format_list_items(mx_records)))
                else:
                    print(format_field("MX Records", "No MX records found"))
            except Exception as e:
                print(format_field("MX Records", f"Error: {str(e)}"))
        
        # Content preview
        print(format_subsection_header("Content"))
        try:
            # Clean up the body text
            body_text = email_info['body']
            if isinstance(body_text, bytes):
                try:
                    body_text = body_text.decode('utf-8', errors='ignore')
                except:
                    body_text = body_text.decode('latin-1', errors='ignore')
            
            # Remove excessive whitespace and newlines
            body_text = ' '.join(body_text.split())
            
            # Remove any HTML tags if present
            if '<' in body_text and '>' in body_text:
                soup = BeautifulSoup(body_text, 'html.parser')
                body_text = soup.get_text(separator=' ', strip=True)
            
            # Remove any non-printable characters
            body_text = ''.join(char for char in body_text if char.isprintable() or char.isspace())
            
            # Take first 1000 characters, but ensure we don't cut words in half
            if len(body_text) > 1000:
                preview = body_text[:1000].rsplit(' ', 1)[0] + "..."
            else:
                preview = body_text
            
            print(format_field("Body Preview", preview))
        except Exception as e:
            print(format_field("Body Preview", f"Error displaying body: {str(e)}"))
        
        # Security Analysis
        print(format_section_header("Security Analysis"))
        
        # Keywords and Links analysis
        found_keywords, suspicious_links, suspicious_attachments = analyze_phishing(email_info, enable_vt, force_fresh)
        
        # Print attachments with integrated security analysis
        print_attachments(email_info['attachments'], suspicious_attachments, enable_vt)

    except Exception as e:
        print(f"[-] Error processing email: {str(e)}")
        return

if __name__ == "__main__":
    main()

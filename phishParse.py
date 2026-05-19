#!/usr/bin/python3

# Version information
VERSION = "1.7.2"
VERSION_INFO = f"phishParse v{VERSION}"

# ASCII Art Banner
BANNER = rf'''
       _     _     _     ____                    
 _ __ | |__ (_)___| |__ |  _ \ __ _ _ __ ___  ___
| '_ \| '_ \| / __| '_ \| |_) / _` | '__/ __/ _  \
| |_) | | | | \__ \ | | |  __/ (_| | |  \__ \  __/
| .__/|_| |_|_|___/_| |_|_|   \__,_|_|  |___\___|
|_|                  {VERSION_INFO}
'''

import re
import extract_msg
from email.parser import BytesParser
from email import policy
from email.utils import parseaddr
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import os
import hashlib
from functools import lru_cache
from typing import Dict, List, Optional, Set, Tuple, Union
import sys
from datetime import datetime
import requests
import time
import base64
import dns.resolver
from ipwhois import IPWhois
import whois
from ipaddress import ip_address
import quopri
import urllib.parse
import mimetypes

# Cache compiled regex patterns
URL_PATTERN = re.compile(r'(https?://[^\s<>"\']+)')
IP_PATTERN = re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b')
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
GREEN = "\033[32m" if supports_color() else ""

# Add these constants at the top
SECTION_WIDTH = 60
SEPARATOR = "=" * SECTION_WIDTH
SUBSEPARATOR = "-" * SECTION_WIDTH

# VirusTotal configuration
VIRUSTOTAL_TIMEOUT = 30  # Timeout in seconds for VirusTotal API requests

_raw_vt_key = os.getenv('VIRUSTOTAL_API_KEY', '')
VIRUSTOTAL_API_KEY = _raw_vt_key if len(_raw_vt_key) >= 64 and _raw_vt_key.isalnum() else None

# Add rate limiting
class RateLimiter:
    def __init__(self, calls_per_minute: int):
        self.calls_per_minute = calls_per_minute
        self.calls = []
    
    def wait_if_needed(self):
        now = time.time()
        # Remove calls older than 1 minute
        self.calls = [call for call in self.calls if now - call < 60]
        if len(self.calls) >= self.calls_per_minute:
            sleep_time = 60 - (now - self.calls[0])
            if sleep_time > 0:
                time.sleep(sleep_time)
        self.calls.append(now)

# Initialize rate limiters
VIRUSTOTAL_RATE_LIMITER = RateLimiter(4)  # 4 calls per minute

# Update cache sizes based on typical usage
URL_CACHE_SIZE = 1000
IP_CACHE_SIZE = 500
DEFANG_CACHE_SIZE = 1000

@lru_cache(maxsize=URL_CACHE_SIZE)
def defang_url(url: str) -> str:
    """Cache defanged URLs to avoid recomputing."""
    result = url
    for pattern, replacement in DEFANG_PATTERNS:
        result = pattern.sub(replacement, result)
    return result

@lru_cache(maxsize=IP_CACHE_SIZE)
def defang_ip(ip_str: Optional[str]) -> Optional[str]:
    """Cache defanged IPs to avoid recomputing."""
    if ip_str is None:
        return None
    return re.sub(r'\.', '[.]', ip_str)

@lru_cache(maxsize=IP_CACHE_SIZE)
def undefang_ip(ip_str: Optional[str]) -> Optional[str]:
    """Cache undefanged IPs to avoid recomputing."""
    if ip_str is None:
        return None
    return re.sub(r'\[\.\]', '.', ip_str)

def clean_url(url: str) -> str:
    """Clean and decode URLs before sending to VirusTotal."""
    try:
        # Strip trailing punctuation that is never part of a URL
        url = url.rstrip('><)"\'\\]},;.')

        # Decode percent-encoded characters before parsing
        decoded_url = urllib.parse.unquote(url)

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
        print(f"{RED}Error cleaning URL {url}: {str(e)}{RESET}")
        return url

def decode_quoted_printable(text: str) -> str:
    """Decode quoted-printable encoded text."""
    try:
        return quopri.decodestring(text.encode('utf-8')).decode('utf-8', errors='ignore')
    except Exception as e:
        print(f"{RED}Error decoding quoted-printable text: {str(e)}{RESET}")
        return text

def extract_links_from_text(text: str) -> List[str]:
    """Extract and clean links from text content."""
    try:
        decoded_text = urllib.parse.unquote(text)
    except Exception as e:
        print(f"{RED}Error decoding text: {str(e)}{RESET}")
        decoded_text = text
    
    urls = URL_PATTERN.findall(decoded_text)
    return [clean_url(url) for url in urls]

def extract_links_from_html(html_content: Union[str, bytes]) -> List[str]:
    """Extract links from HTML content, handling encoded URLs."""
    links: List[str] = []
    try:
        # Handle different content types and encodings
        if isinstance(html_content, bytes):
            try:
                html_content = html_content.decode('utf-8', errors='ignore')
            except Exception:
                html_content = html_content.decode('latin-1', errors='ignore')
        
        # Decode any quoted-printable content
        html_content = decode_quoted_printable(html_content)
        
        # Clean up common HTML email artifacts
        html_content = html_content.replace('=\n', '')  # Remove soft line breaks
        html_content = html_content.replace('=3D', '=')  # Decode equals signs
        
        # Decode percent-encoded content
        html_content = urllib.parse.unquote(html_content)
        
        soup = BeautifulSoup(html_content, "html.parser")
        
        # Extract href attributes from anchor tags
        anchor_tags = soup.find_all('a', href=True)
        
        for a in anchor_tags:
            href = a.get('href')
            if href:
                # Clean up the href
                href = href.strip()
                href = decode_quoted_printable(href)
                
                # Decode percent-encoded characters
                href = urllib.parse.unquote(href)
                
                # Handle mailto: links
                if href.startswith('mailto:'):
                    continue
                
                # Handle relative URLs
                if not href.startswith(('http://', 'https://')):
                    continue
                
                cleaned_url = clean_url(href)
                links.append(cleaned_url)
        
        # Also extract plain-text URLs that aren't in anchor tags (use parsed text to avoid HTML markup)
        text_links = extract_links_from_text(soup.get_text())
        links.extend(text_links)
        
    except Exception as e:
        print(f"{RED}Error extracting links from HTML: {str(e)}{RESET}")
    
    return list(set(links))  # Remove duplicates

def extract_email_info(file_path, email_bytes, file_type):
    if file_type == "msg":
        # Handle Outlook .msg file
        msg = extract_msg.Message(file_path)
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
                    except Exception:
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
                    except Exception:
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
                        except Exception:
                            content = content.decode('latin-1', errors='ignore')
                    content = decode_quoted_printable(content)
                    attachment_links = extract_links_from_text(content)
                    links.extend(attachment_links)
            except Exception as e:
                print(f"Error extracting links from attachment: {str(e)}")
            metadata = extract_attachment_metadata(attachment, file_type="msg")
            attachments.append(metadata)
        
        sender_ip = extract_sender_ip_from_email(msg)
        reply_to_address = msg.header.get("Reply-To", None)

        # Extract recipients (To, Cc, Bcc)
        to = msg.to
        cc = msg.cc
        bcc = msg.bcc
    elif file_type == "eml":
        # Handle standard .eml email file
        msg = BytesParser(policy=policy.default).parsebytes(email_bytes)
        subject = msg['subject'] or 'Unknown'
        sender = msg['from'] or 'Unknown'
        date = msg['date'] or 'Unknown'
        reply_to_address = msg['reply-to'] or ''

        # Extract sender's IP address from the 'Received' headers
        sender_ip = extract_sender_ip_from_email(msg)

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
                        except Exception:
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
                        except Exception:
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
        to = msg['to'] or ''
        cc = msg.get('cc') or ''
        bcc = msg.get('bcc') or ''

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

    # Deduplicate links across all extracted sources before returning
    links = list(dict.fromkeys(links))

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
    """Extract sender's IP address from email headers.
    
    For MSG files, this parses the Received headers to find the originating IP.
    For EML files, it uses the standard email header parsing.
    
    Args:
        msg: The email message object
        
    Returns:
        The sender's IP address as a string, or None if not found
    """
    try:
        # Handle MSG files
        if hasattr(msg, 'header'):
            received_headers = msg.header.get("Received", [])
            if not received_headers:
                return None
                
            # Process each Received header to find the originating IP
            for header in received_headers:
                # Look for common IP patterns in Received headers
                ip_match = IP_PATTERN.search(header)
                if ip_match:
                    ip = ip_match.group(0)
                    # Validate it's a real IP address
                    try:
                        ip_address(ip)
                        return ip
                    except ValueError:
                        continue
            return None
            
        # Handle EML files
        received_headers = msg.get_all('Received')
        if not received_headers:
            return None
            
        for header in received_headers:
            ip_match = IP_PATTERN.search(header)
            if ip_match:
                ip = ip_match.group(0)
                # Validate it's a real IP address
                try:
                    ip_address(ip)
                    return ip
                except ValueError:
                    continue
        return None
        
    except Exception as e:
        print(f"{RED}[-]{RESET} Error extracting sender IP: {str(e)}")
        return None

def extract_attachment_metadata(part, file_type: str = "eml") -> Dict:
    """
    Extract metadata from an email attachment.
    
    Args:
        part: The email part containing the attachment
        file_type: The type of email file ("eml" or "msg")
    
    Returns:
        Dict containing:
            - filename: The name of the attachment
            - content_type: The MIME type of the attachment
            - size: Size in bytes
            - sha256: SHA256 hash of the attachment
            - content_disposition: Content disposition header
            - content_transfer_encoding: Content transfer encoding
            - content_id: Content ID if present
            - x_unix_mode: Unix file mode if present
            - error: Error message if processing failed
    """
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

    base_headers = {
        "accept": "application/json",
        "x-apikey": VIRUSTOTAL_API_KEY
    }

    try:
        cleaned_url = clean_url(url)
        url_id = base64.urlsafe_b64encode(cleaned_url.encode()).decode().strip("=")
        report_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"

        # If not forcing fresh, try fetching an existing report first
        if not force_fresh:
            VIRUSTOTAL_RATE_LIMITER.wait_if_needed()
            response = requests.get(report_url, headers=base_headers, timeout=VIRUSTOTAL_TIMEOUT, verify=True)
            if response.status_code == 200:
                data = response.json()
                if 'data' in data and 'attributes' in data.get('data', {}):
                    stats = data['data']['attributes'].get('last_analysis_stats', {})
                    if stats:
                        gui_url = f"https://www.virustotal.com/gui/url/{url_id}"
                        return {
                            "found": True,
                            "malicious": stats.get('malicious', 0),
                            "suspicious": stats.get('suspicious', 0),
                            "undetected": stats.get('undetected', 0),
                            "harmless": stats.get('harmless', 0),
                            "timeout": stats.get('timeout', 0),
                            "total_scans": sum(stats.values()),
                            "scan_id": url_id,
                            "gui_url": gui_url
                        }

        # Submit URL for (re-)analysis
        VIRUSTOTAL_RATE_LIMITER.wait_if_needed()
        post_headers = {**base_headers, "content-type": "application/x-www-form-urlencoded"}
        form_data = urllib.parse.urlencode({"url": cleaned_url})
        submit_response = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=post_headers, data=form_data,
            timeout=VIRUSTOTAL_TIMEOUT, verify=True
        )

        if submit_response.status_code != 200:
            return {"error": f"URL submission error: {submit_response.status_code}"}

        # Poll for results
        max_retries = 5
        retry_delay = 15
        time.sleep(retry_delay)

        for attempt in range(max_retries):
            VIRUSTOTAL_RATE_LIMITER.wait_if_needed()
            response = requests.get(report_url, headers=base_headers, timeout=VIRUSTOTAL_TIMEOUT, verify=True)

            if response.status_code == 200:
                data = response.json()
                if 'data' not in data or 'attributes' not in data.get('data', {}):
                    return {"error": "Unexpected VirusTotal response structure"}
                stats = data['data']['attributes'].get('last_analysis_stats', {})
                if stats:
                    gui_url = f"https://www.virustotal.com/gui/url/{url_id}"
                    return {
                        "found": True,
                        "malicious": stats.get('malicious', 0),
                        "suspicious": stats.get('suspicious', 0),
                        "undetected": stats.get('undetected', 0),
                        "harmless": stats.get('harmless', 0),
                        "timeout": stats.get('timeout', 0),
                        "total_scans": sum(stats.values()),
                        "scan_id": url_id,
                        "gui_url": gui_url
                    }

            if attempt < max_retries - 1:
                time.sleep(retry_delay)

        return {"found": False, "message": "Analysis still in progress. Please try again in a few moments."}

    except Exception as e:
        return {"error": str(e)}


def analyze_phishing(email_info: Dict, enable_virustotal: bool = False, force_fresh: bool = False) -> Tuple[Set[str], List[Dict], List[Dict]]:
    """Optimized phishing analysis with type hints."""
    body = email_info["body"].lower()
    suspicious_links = []
    suspicious_attachments = []

    # Keywords analysis
    found_keywords = {kw for kw in SUSPICIOUS_KEYWORDS if kw in body}
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
        VIRUSTOTAL_RATE_LIMITER.wait_if_needed()
        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        response = requests.get(url, headers=headers, timeout=VIRUSTOTAL_TIMEOUT, verify=True)
        
        if response.status_code == 200:
            data = response.json()
            if 'data' not in data or 'attributes' not in data.get('data', {}):
                return {"error": "Unexpected VirusTotal response structure"}
            stats = data['data']['attributes'].get('last_analysis_stats', {})
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

@lru_cache(maxsize=100)
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
        
        # Get ASN/RDAP information
        obj = IPWhois(clean_ip)
        results = obj.lookup_rdap(inc_raw=False, retry_count=2, depth=1)

        # Try whois for a more specific registered org name
        org = "Unknown"
        try:
            w = whois.whois(clean_ip)
            org = w.org or results.get('asn_description', 'Unknown')
        except Exception:
            org = results.get('asn_description', 'Unknown')

        whois_info = {
            "range": f"{results.get('asn_cidr', 'Unknown')}",
            "org": org,
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

    file_path = input(f"{BLUE_BOLD}Please enter the full path to the .msg or .eml file:{RESET} ").strip().strip('"\'')
    file_path = os.path.expanduser(file_path)
    
    # Ask if user wants to enable VirusTotal analysis (default to Y)
    vt_prompt = f"{BLUE_BOLD}Enable VirusTotal analysis? (Y/n):{RESET} "
    enable_vt = input(vt_prompt).strip().lower() in {'', 'y', 'yes'}
    
    # Ask if user wants to force fresh VirusTotal analysis (default to Y)
    force_fresh = False
    if enable_vt:
        fresh_prompt = f"{BLUE_BOLD}Force fresh VirusTotal analysis? (Y/n):{RESET} "
        force_fresh = input(fresh_prompt).strip().lower() in {'', 'y', 'yes'}
    
    if enable_vt and not VIRUSTOTAL_API_KEY:
        if os.getenv('VIRUSTOTAL_API_KEY'):
            print(f"\n{RED}[-]{RESET} VIRUSTOTAL_API_KEY appears invalid (must be 64 alphanumeric characters).")
        else:
            print(f"\n{RED}[-]{RESET} VIRUSTOTAL_API_KEY environment variable is not set.")
        print(f"{BLUE}    Set it with: export VIRUSTOTAL_API_KEY=<your_key>{RESET}")
        choice = input(f"{BLUE_BOLD}    Continue without VirusTotal, or exit to add key? ({WHITE}C{BLUE_BOLD}ontinue/{WHITE}E{BLUE_BOLD}xit):{RESET} ").strip().lower()
        if choice in {'exit', 'e', 'quit', 'q'}:
            sys.exit(0)
        enable_vt = False

    if not os.path.isfile(file_path):
        print(f"{RED}[-]{RESET} File does not exist. Please provide a valid file path.")
        return

    file_extension = os.path.splitext(file_path)[1].lower()
    if file_extension not in {".msg", ".eml"}:
        print(f"{RED}[-]{RESET} Unsupported file format. Only .msg and .eml are supported.")
        return

    file_type = file_extension[1:]  # Remove the dot
    
    MAX_FILE_SIZE = 50 * 1024 * 1024  # 50 MB
    if os.path.getsize(file_path) > MAX_FILE_SIZE:
        print(f"{RED}[-]{RESET} File exceeds 50 MB limit.")
        return

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

        email_info = extract_email_info(file_path, email_bytes, file_type)
        
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
            print(format_field("Sender's IP", defang_ip(email_info['sender_ip'])))
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
                _, addr = parseaddr(email_info['sender'])
                domain = addr.split('@')[1] if '@' in addr else None
                mx_records = get_mx_records(domain) if domain else []
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
                except Exception:
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
                truncated = body_text[:1000]
                cut = truncated.rsplit(' ', 1)
                preview = (cut[0] if len(cut) > 1 else truncated) + "..."
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
        
        print(f"\n{GREEN}[+]{RESET} Email analysis completed successfully")

    except Exception as e:
        print(f"{RED}[-]{RESET} Error processing email: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()

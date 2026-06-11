# phishParse

A powerful tool for analyzing email files (.msg and .eml) for potential phishing indicators.

## Version
Current version: 1.7.3

## Features

- **File Support**: Analyzes both .msg (Outlook) and .eml (standard email) files
- **Content Analysis**:
  - Extracts and analyzes email headers
  - Identifies sender information and IP addresses
  - Extracts and defangs URLs
  - Analyzes email body content
  - Handles both plain text and HTML content
- **Attachment Analysis**:
  - Extracts attachment metadata
  - Identifies suspicious file types
  - Calculates file hashes
  - Handles missing filename attributes gracefully
- **Security Features**:
  - Defangs URLs and IP addresses for safe display
  - Identifies suspicious keywords
  - Analyzes MX records
  - WHOIS lookup for sending server IP organization name
  - Octet-bounded IP address matching to prevent false positives
  - SPF, DKIM, and DMARC authentication checks with color-coded results
  - Flags authentication failures in the Security Analysis section
- **VirusTotal Integration**:
  - Optional VirusTotal API integration
  - URL and file hash analysis
  - Configurable timeout and retry settings
  - Deduplicates URLs before scanning — emails with repeated links are only submitted to VirusTotal once per unique URL
  - Prompts to continue or exit if API key is not set
  - Validates API response structure before parsing
- **User Interface**:
  - Color-coded output
  - Formatted sections for easy reading
  - Detailed error reporting
  - File size limit enforced (50 MB) before reading

## System Requirements

- **Operating Systems**:
  - Linux (Ubuntu 18.04+, CentOS 7+, etc.)
  - macOS 10.15+
  - Windows 10/11 (with Python 3.6+)
- **Hardware**:
  - CPU: 1+ GHz processor
  - RAM: 2+ GB
  - Storage: 100+ MB free space
- **Software**:
  - Python 3.6 or higher
  - pip (Python package manager)
  - git (for installation)

## Installation

1. Install system dependencies:
```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install python3 python3-pip git

# CentOS/RHEL
sudo yum install python3 python3-pip git

# macOS (using Homebrew)
brew install python3 git

# Windows
# Download and install Python 3.6+ from python.org
# Download and install Git from git-scm.com
```

2. Clone the repository:
```bash
git clone https://github.com/rmcglamery/phishParse.git
cd phishParse
```

3. Install required packages:
```bash
python3 -m pip install -r requirements.txt
```

4. Set up API keys (optional):
```bash
# VirusTotal: https://www.virustotal.com/gui/join-us

# Linux/macOS: Add to ~/.bashrc or ~/.zshrc
export VIRUSTOTAL_API_KEY='your_api_key_here'

# Windows: Add to System Environment Variables
# or use setx in Command Prompt
setx VIRUSTOTAL_API_KEY "your_api_key_here"
```

## Usage

Run the script:
```bash
python3 phishParse.py
```

The script will prompt you for:
1. The path to the email file (.msg or .eml) — supports `~` and quoted paths
2. Whether to enable VirusTotal analysis (default: Y)
3. Whether to force fresh VirusTotal analysis (default: Y)

If VirusTotal is enabled but no API key is set, the script will ask whether to continue without it or exit to add the key.

Note: Pressing Enter without typing anything will select the default option (Y).

### Performance Notes
- Typical analysis time: 30-60 seconds
- File size limit: 50MB
- Memory usage: ~200MB during analysis
- Network usage: ~2-5MB per analysis (with APIs enabled)

## Output

The script provides detailed analysis including:
- File details (name, size, hash, etc.)
- Email metadata (subject, date, participants)
- Technical details (IP addresses, sending server organization via WHOIS, MX records)
- Authentication results (SPF, DKIM, DMARC) with color-coded pass/fail status
- Content preview
- Security analysis (suspicious keywords, links, attachments, authentication failures)
- VirusTotal results (if enabled)

## Error Handling and Troubleshooting

### Common Errors and Solutions

1. **File Not Found**
   - Ensure the file path is correct
   - Check file permissions
   - Verify the file exists

2. **API Key Errors**
   - Verify the VirusTotal API key is set correctly
   - Check API key permissions
   - Ensure network connectivity

3. **Rate Limit Exceeded**
   - Wait before retrying
   - Consider upgrading API plan
   - Reduce analysis frequency

4. **Memory Errors**
   - Close other memory-intensive applications
   - Reduce file size
   - Increase system swap space

5. **Network Issues**
   - Check internet connection
   - Verify firewall settings
   - Test API endpoints

### Interpreting Error Messages
- `[-]` prefix indicates errors
- `[+]` prefix indicates success

## Security and Compliance

### Data Handling
- No data is stored permanently
- API calls are made over HTTPS
- Results are displayed only in the terminal

### Best Practices
1. **API Key Management**
   - Use separate API keys for different environments
   - Rotate keys regularly
   - Restrict key permissions

2. **File Handling**
   - Analyze files in isolated environments
   - Use dedicated analysis machines
   - Implement proper access controls

3. **Production Use**
   - Monitor API usage
   - Implement rate limiting
   - Log analysis results
   - Regular security audits

## Changelog

### v1.7.3
- Added authentication checks — SPF, DKIM, and DMARC results parsed from `Authentication-Results`, `Received-SPF`, and `DKIM-Signature` headers
- Added Authentication subsection in Technical Details with color-coded status (green = pass, red = fail/softfail)
- Added Authentication Failures subsection in Security Analysis when any check fails or returns no result
- Supports both `.msg` and `.eml` formats for auth header extraction

### v1.7.2
- Fixed `.msg` parsing — `extract_msg.Message` now receives the file path, not raw bytes
- Fixed `ip_address` import shadowed by parameter names in `defang_ip`/`undefang_ip` — renamed to `ip_str`
- Removed unused `PURPLE` and `ORANGE` color constants
- Pinned all dependency versions in `requirements.txt` to prevent unexpected updates
- Added `*.egg-info/` to `.gitignore`

### v1.7.1
- Fixed multi-word keyword detection — phrases like "action required" now correctly matched
- Fixed rate limiter not being called — VirusTotal calls now properly throttled to 4/min
- Fixed `force_fresh=False` now checks for existing VT report before submitting — avoids unnecessary re-analysis
- Fixed headers dict mutation — POST and GET now use separate header dicts
- Fixed MSG sender IP extraction — now calls `extract_sender_ip_from_email()` like EML does
- Added VirusTotal API key format validation (must be 64 alphanumeric characters)
- Added explicit `verify=True` to all requests calls
- Added non-zero exit code (`sys.exit(1)`) on fatal errors
- Updated `.gitignore` to exclude `__pycache__/`, `*.pyc`, `.env`, `venv/`

### v1.7.0
- Fixed URL form data encoding when submitting to VirusTotal — URLs with `&` or `=` now encoded correctly
- Fixed 7 bare `except:` clauses that blocked Ctrl+C — all now use `except Exception:`
- Fixed IP regex to be octet-bounded — no longer matches values like `1.2.3.4.5`
- Fixed malformed sender address crashing MX lookup — now uses `email.utils.parseaddr()`
- Fixed IP address stored defanged internally — raw IP kept for lookups, defanged only at display time
- Fixed body preview crash on single-word bodies
- Fixed `.eml` `None` header fields — normalized at extraction to prevent downstream errors
- Added file size guard — rejects files over 50 MB before reading into memory
- Added `@lru_cache` to MX record lookups to avoid redundant DNS queries
- Added VirusTotal response structure validation before parsing stats
- Added `retry_count` and `depth` limits to IPWhois RDAP lookup to reduce hang risk

### v1.6.5
- Removed ChatGPT/OpenAI integration
- Added WHOIS lookup for sending server IP organization name
- Added interactive prompt when VirusTotal API key is missing
- Fixed file path handling: `~` expansion and surrounding quote stripping
- Removed unused dead code (exception classes, stale helpers)

### v1.6
- Added URL deduplication before VirusTotal submission
- Fixed URL extraction dropping trailing junk characters
- Replaced `unicode_escape` codec with `urllib.parse.unquote` for URL decoding

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Author

Russ McGlamery

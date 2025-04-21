# phishParse

A powerful tool for analyzing email files (.msg and .eml) for potential phishing indicators.

## Version
Current version: 1.5

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
  - Performs WHOIS lookups on IP addresses
- **VirusTotal Integration**:
  - Optional VirusTotal API integration
  - URL and file hash analysis
  - Configurable timeout and retry settings
- **ChatGPT Analysis**:
  - Optional AI-powered analysis of email indicators
  - Provides risk assessment and recommendations
  - Color-coded risk levels (High: Red, Medium: Orange, Low: Green)
  - Analyzes suspicious elements in context
  - Sanitizes sensitive information before analysis
- **User Interface**:
  - Color-coded output
  - Formatted sections for easy reading
  - Detailed error reporting

## Requirements

- Python 3.6 or higher
- Required packages (see requirements.txt):
  - extract-msg>=0.46.0
  - beautifulsoup4>=4.12.0
  - requests>=2.31.0
  - python-dateutil>=2.8.2
  - dnspython>=2.4.2
  - python-whois>=0.8.0
  - ipwhois>=1.2.0
  - openai>=1.12.0

## Installation

1. Clone the repository:
```bash
git clone https://github.com/rmcglamery/phishParse.git
cd phishParse
```

2. Install required packages:
```bash
pip install -r requirements.txt
```

3. Set up API keys:
```bash
# VirusTotal API key (optional)
export VIRUSTOTAL_API_KEY='your_api_key_here'

# OpenAI API key (optional)
export OPENAI_API_KEY='your_api_key_here'
```

## Usage

Run the script:
```bash
python3 phishParse.py
```

The script will prompt you for:
1. The path to the email file (.msg or .eml)
2. Whether to enable VirusTotal analysis (default: Y)
3. Whether to force fresh VirusTotal analysis (default: Y)
4. Whether to enable ChatGPT analysis (default: Y)

Note: Pressing Enter without typing anything will select the default option (Y).

## Output

The script provides detailed analysis including:
- File details (name, size, hash, etc.)
- Email metadata (subject, date, participants)
- Technical details (IP addresses, MX records)
- Content preview
- Security analysis (suspicious keywords, links, attachments)
- VirusTotal results (if enabled)
- ChatGPT analysis (if enabled) with color-coded risk assessment

## Error Handling

The script includes robust error handling for:
- Missing or invalid files
- Unsupported file types
- Network connectivity issues
- API rate limits
- Missing attachment attributes
- Encoding issues
- OpenAI API errors and timeouts

## Security Features

- Sensitive information redaction before ChatGPT analysis
- Secure API key management
- Defanged URLs and IP addresses
- Error messages without sensitive information
- Optional features that can be disabled

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Author

Russ McGlamery 
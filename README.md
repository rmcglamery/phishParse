# phishParse

A powerful tool for analyzing email files (.msg and .eml) for potential phishing indicators.

## Version
Current version: 1.1

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

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/phishParse.git
cd phishParse
```

2. Install required packages:
```bash
pip install -r requirements.txt
```

3. (Optional) Set up VirusTotal API key:
```bash
export VIRUSTOTAL_API_KEY='your_api_key_here'
```

## Usage

Run the script:
```bash
python phishParse.py
```

The script will prompt you for:
1. The path to the email file (.msg or .eml)
2. Whether to enable VirusTotal analysis
3. Whether to force fresh VirusTotal analysis

## Output

The script provides detailed analysis including:
- File details (name, size, hash, etc.)
- Email metadata (subject, date, participants)
- Technical details (IP addresses, MX records)
- Content preview
- Security analysis (suspicious keywords, links, attachments)
- VirusTotal results (if enabled)

## Error Handling

The script includes robust error handling for:
- Missing or invalid files
- Unsupported file types
- Network connectivity issues
- API rate limits
- Missing attachment attributes
- Encoding issues

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Author

Russ McGlamery 
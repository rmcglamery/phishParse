# phishParse

A powerful tool for analyzing email files (.msg and .eml) for potential phishing indicators.

## Version
Current version: 1.6.5

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
- **VirusTotal Integration**:
  - Optional VirusTotal API integration
  - URL and file hash analysis
  - Configurable timeout and retry settings
  - Deduplicates URLs before scanning — emails with repeated links are only submitted to VirusTotal once per unique URL
  - Prompts to continue or exit if API key is not set
- **User Interface**:
  - Color-coded output
  - Formatted sections for easy reading
  - Detailed error reporting

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
- Content preview
- Security analysis (suspicious keywords, links, attachments)
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

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Author

Russ McGlamery

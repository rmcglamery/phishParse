# PhishParse

A powerful Python script for analyzing email files (.msg and .eml) to detect potential phishing indicators and security threats.

## Features

- Supports both .msg (Outlook) and .eml email file formats
- Extracts and analyzes email metadata including:
  - Sender and recipient information
  - Email subject and date
  - Attachments with detailed metadata
  - Links and URLs
  - Sender IP addresses
- Security analysis features:
  - Suspicious keyword detection
  - URL analysis with VirusTotal integration
  - Attachment analysis for suspicious file types and MIME types
  - File hash analysis
- Color-coded console output for better readability
- Detailed file metadata analysis

## Requirements

- Python 3.x
- Required Python packages:
  - `extract_msg`
  - `beautifulsoup4`
  - `requests`

## Installation

1. Clone this repository:
```bash
git clone https://github.com/yourusername/phishParse.git
cd phishParse
```

2. Install the required dependencies:
```bash
pip install -r requirements.txt
```

3. (Optional) Set up VirusTotal API key:
```bash
export VIRUSTOTAL_API_KEY='your_api_key_here'
```

## Usage

Run the script from the command line:

```bash
python phishParse.py
```

The script will prompt you to enter the path to the email file you want to analyze.

## Output

The script provides detailed analysis in the following sections:

1. File Details
   - Filename and location
   - File type and size
   - Creation and modification dates
   - SHA256 hash

2. Email Analysis Results
   - Basic Information (subject, date)
   - Participants (from, to, cc, bcc, reply-to)
   - Technical Details (sender's IP)
   - Content Preview

3. Security Analysis
   - Suspicious Keywords
   - URL Analysis with VirusTotal results
   - Attachment Analysis
   - File Hash Analysis

## VirusTotal Integration

The script integrates with VirusTotal to provide additional security analysis:
- URL reputation checking
- File hash analysis
- Malicious content detection

To use VirusTotal features, you need to:
1. Sign up for a VirusTotal account
2. Get your API key
3. Set the environment variable `VIRUSTOTAL_API_KEY`

## Security Considerations

- The script handles potentially malicious content safely
- URLs are defanged in the output
- IP addresses are defanged in the output
- Large attachments are flagged for review

## Author

Russ McGlamery

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. 
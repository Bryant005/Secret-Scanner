# Python Secret Scanner

## Purpose
The Python Secret Scanner is a Command Line Interface (CLI) tool designed to help developers and security analysts identify hardcoded secrets, such as API keys, tokens, and passwords, inadvertently left in source code. Hardcoded secrets are a critical vulnerability (OWASP Top 10) that can lead to unauthorized access and data breaches. 

## Detection Logic
This tool reads files line-by-line and evaluates the text against a set of predefined Regular Expressions (Regex). If a string matches the specific structural pattern of a known secret format, it flags it. 

**Included Regex Patterns:**
1. **AWS Access Key:** `\bAKIA[0-9A-Z]{16}\b` (Matches the standard 20-character AWS key prefix).
2. **GitHub Token:** `\bghp_[0-9a-zA-Z]{36}\b` (Matches GitHub Personal Access Tokens).
3. **Slack Token:** `\bxox[baprs]-[0-9a-zA-Z]{10,48}\b` (Matches standard Slack bot, user, and workspace tokens).
4. **Google Cloud API Key:** `\bAIza[0-9A-Za-z\-_]{35}\b` (Matches Google Cloud API keys).
5. **RSA Private Key:** `-----BEGIN (?:RSA|OPENSSH) PRIVATE KEY-----` (Matches standard PEM encoded private key headers).
6. **Generic Passwords:** `(?i)(?:password|passwd|pwd|secret|api_key)\s*[:=]\s*['"]([^'"]+)['"]` (Catches common variable assignments like `password = "mysecret"`).

## Usage
The tool requires Python 3.x and relies entirely on standard libraries (no `pip install` required).

**Basic Scan (Directory or File):**
```bash
python secret_scanner.py --target ./my_project_folder
python secret_scanner.py -t ./config.json
Verbose Mode (See files being scanned):

Bash
python secret_scanner.py --target ./my_project_folder --verbose
Viewing Help Menu:

Bash
python secret_scanner.py --help
Limitations & False Positives
False Positives: The generic password regex might catch placeholder strings (e.g., password = "ENTER_PASSWORD_HERE").

False Negatives: The tool relies on pattern matching. If a developer uses a custom API key format, adds words between the variable and the equals sign, or obfuscates a token in a complex way (e.g., base64 encoding), the scanner will not detect it.

Performance: Very large binary files (like compiled .exe or .pdf files) are automatically skipped via UnicodeDecodeError handling to prevent memory crashes, but scanning massive directories may take time.
```
## Youtube Video Showing The Code Being Prompted
https://youtu.be/HjeCyZUbfkw

"""
Secret Scanner CLI Tool
Scans files and directories for hardcoded secrets using regular expressions.
"""

import argparse
import logging
import os
import re
import sys

PATTERNS = {
    "AWS Access Key": re.compile(r'\bAKIA[0-9A-Z]{16}\b'),
    "GitHub Personal Access Token": re.compile(r'\bghp_[0-9a-zA-Z]{36}\b'),
    "Slack Token": re.compile(r'\bxox[baprs]-[0-9a-zA-Z]{10,48}\b'),
    "Google Cloud API Key": re.compile(r'\bAIza[0-9A-Za-z\-_]{35}\b'),
    "RSA Private Key": re.compile(r'-----BEGIN (?:RSA|OPENSSH) PRIVATE KEY-----'),
    "Generic Password Assignment": re.compile(r'(?i)(?:password|passwd|pwd|secret|api_key).*?[:=]\s*[\'"]([^\'"]+)[\'"]')
}

def setup_logging(verbose: bool) -> logging.Logger:
    """Configures the logging level and format based on user input."""
    logger = logging.getLogger("SecretScanner")
    level = logging.DEBUG if verbose else logging.INFO
    
    handler = logging.StreamHandler(sys.stdout)
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s', datefmt='%H:%M:%S')
    handler.setFormatter(formatter)
    
    logger.addHandler(handler)
    logger.setLevel(level)
    return logger

def scan_file(filepath: str, logger: logging.Logger) -> list:
    """
    Scans a single file line by line for secrets.
    Safely handles encoding errors (e.g., if a binary file is accidentally scanned).
    """
    findings = []
    logger.debug(f"Scanning file: {filepath}")
    
    try:
        with open(filepath, 'r', encoding='utf-8') as file:
            for line_number, line in enumerate(file, start=1):
                for secret_type, regex in PATTERNS.items():
                    matches = regex.findall(line)
                    for match in matches:
                        # Extract the matched string cleanly (handling regex capture groups vs full matches)
                        matched_string = match if isinstance(match, str) else match[0]
                        findings.append({
                            'file': filepath,
                            'line': line_number,
                            'type': secret_type,
                            'match': matched_string.strip()
                        })
    except UnicodeDecodeError:
        logger.debug(f"Skipping binary or unreadable file: {filepath}")
    except PermissionError:
        logger.warning(f"Permission denied: {filepath}")
    except Exception as e:
        logger.error(f"Error reading file {filepath}: {e}")
        
    return findings

def scan_target(target_path: str, logger: logging.Logger) -> list:
    """
    Determines if the target is a file or directory and routes accordingly.
    Recursively scans directories.
    """
    all_findings = []
    
    if os.path.isfile(target_path):
        all_findings.extend(scan_file(target_path, logger))
    elif os.path.isdir(target_path):
        for root, _, files in os.walk(target_path):
            for file in files:
                filepath = os.path.join(root, file)
                all_findings.extend(scan_file(filepath, logger))
    else:
        logger.error(f"Invalid path: {target_path} does not exist.")
        
    return all_findings

def print_report(findings: list):
    """Outputs a cleanly formatted report of the findings."""
    print("\n" + "="*60)
    print("                 SECRET SCANNER REPORT")
    print("="*60)
    
    if not findings:
        print("No secrets found. Great job!")
        print("="*60 + "\n")
        return

    print(f"Total secrets found: {len(findings)}\n")
    for item in findings:
        print(f"[!] {item['type']} Detected!")
        print(f"    File:  {item['file']}")
        print(f"    Line:  {item['line']}")
        # Truncate the match slightly if it's too long, for clean output
        match_str = item['match'][:50] + "..." if len(item['match']) > 50 else item['match']
        print(f"    Match: {match_str}\n")
    print("="*60 + "\n")

def main():
    # Setup argparse for CLI interface
    parser = argparse.ArgumentParser(
        description="A CLI tool to scan files and directories for hardcoded secrets."
    )
    parser.add_argument(
        "-t", "--target",
        required=True,
        help="The file or directory path to scan."
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose logging (outputs files being scanned)."
    )
    
    args = parser.parse_args()
    
    # Initialize logging
    logger = setup_logging(args.verbose)
    
    # Validate input
    if not os.path.exists(args.target):
        logger.error(f"The specified target '{args.target}' does not exist.")
        sys.exit(1)
        
    logger.info(f"Starting scan on target: {args.target}")
    
    # Execute scan
    findings = scan_target(args.target, logger)
    
    logger.info("Scan complete. Generating report...")
    
    # Output results
    print_report(findings)

if __name__ == "__main__":
    main()
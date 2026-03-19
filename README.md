# AWS Security Scanner CLI

A Python-based CLI tool that scans AWS environments for common security misconfigurations, including public S3 exposure and overly permissive security group rules.

---

## Features

- Scans EC2 security groups for risky public inbound rules
- Detects public or misconfigured S3 bucket access settings
- Classifies findings by severity (HIGH, MEDIUM)
- Command-line interface with selectable checks
- Supports both human-readable and JSON output formats

---

## Technologies

- Python
- boto3 (AWS SDK)
- argparse

---
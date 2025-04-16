# CVEfinder

A Python tool for scanning Linux systems for package vulnerabilities using the National Vulnerability Database (NVD).

## Features
- Supports multiple Linux distributions (Debian/Ubuntu, RedHat/CentOS, and Arch Linux)
- Caches NVD API responses for better performance
- Parallel processing for faster scanning
- Severity-based filtering (CRITICAL, HIGH, MEDIUM, LOW)
- Report generation in text and JSON formats
- Progress tracking during scans

## Requirements
- Python 3.x
- Required Python packages (add these to requirements.txt):
  - requests
  - packaging
  - tqdm

## Installation
```bash
git clone https://github.com/irhdab/CVEfinder.git
cd CVEfinder
pip install -r requirements.txt

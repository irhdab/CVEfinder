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
- Required Python packages:
  - requests
  - packaging
  - tqdm

## Installation

```bash
git clone https://github.com/irhdab/CVEfinder.git
cd CVEfinder
pip install -r requirements.txt
```

## How It Works

CVEfinder works by:
1. Identifying installed packages on your Linux system
2. Querying the NVD API for known vulnerabilities
3. Matching package versions against vulnerable versions
4. Presenting findings with severity ratings and descriptions

The tool uses caching to improve performance and reduce API calls, and implements parallel processing to speed up scans of large systems.

## Contributing

Contributions are welcome! Please feel free to submit a pull request or open an issue if you encounter any problems or have suggestions for improvements.

## License

This project is available under the MIT License.

## Disclaimer

CVEfinder is provided for educational and informational purposes only. Always verify findings and consult with security professionals when addressing vulnerabilities in production environments.

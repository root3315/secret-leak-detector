# Secret Leak Detector

A command-line tool to scan codebases for accidentally committed secrets, API keys, tokens, and credentials.

## Features

- Detects 30+ types of secrets including:
  - AWS Access Keys and Secret Keys
  - GitHub, GitLab, and Bitbucket tokens
  - Google, Stripe, Square API keys
  - Slack tokens and webhooks
  - Database connection strings
  - Private keys (RSA, DSA, EC, OpenSSH)
  - JWT tokens
  - Hardcoded passwords
  - And many more...

- Configurable severity levels (critical, high, medium, low)
- JSON output for CI/CD integration
- Fast recursive directory scanning
- Smart file filtering (skips binary files, node_modules, etc.)
- No external dependencies required

## Installation

### From Source

```bash
git clone https://github.com/yourusername/secret-leak-detector.git
cd secret-leak-detector
pip install -e .
```

### Direct Usage

No installation required. Run directly with Python:

```bash
python -m secret_leak_detector /path/to/scan
```

## Usage

### Basic Scan

```bash
# Scan current directory
python -m secret_leak_detector

# Scan specific directory
python -m secret_leak_detector /path/to/project

# Scan specific file
python -m secret_leak_detector src/config.py
```

### Filtering by Severity

```bash
# Only show high and critical severity findings
python -m secret_leak_detector -s high ./src

# Show medium and above
python -m secret_leak_detector --severity medium ./codebase
```

### Output Options

```bash
# JSON output for CI/CD
python -m secret_leak_detector --json --output results.json .

# Verbose output with descriptions
python -m secret_leak_detector --verbose ./src

# Quiet mode (summary only)
python -m secret_leak_detector --quiet ./project

# Disable colored output
python -m secret_leak_detector --no-color ./src
```

### File Filtering

```bash
# Scan all files regardless of extension
python -m secret_leak_detector --all-files ./data

# Specify file extensions to scan
python -m secret_leak_detector --extensions ".py,.js,.env" ./project

# Exclude specific patterns
python -m secret_leak_detector --exclude-patterns "*.min.js,node_modules" ./src
```

### List Detection Patterns

```bash
python -m secret_leak_detector --list-patterns
```

## How It Works

The secret leak detector uses a pattern-based approach combined with entropy analysis:

### Pattern Matching

The tool maintains a registry of regex patterns for known secret formats:

1. **Cloud Provider Keys**: AWS, Azure, GCP credentials
2. **Service Tokens**: GitHub, GitLab, Slack, Stripe, etc.
3. **Database URLs**: Connection strings with embedded credentials
4. **Private Keys**: PEM-formatted private key headers
5. **Generic Secrets**: Common variable names with secret-like values

### Entropy Analysis

For unknown secret formats, the tool can detect high-entropy strings that exhibit characteristics of randomly generated tokens or keys.

### File Scanning

The scanner:
1. Recursively traverses directories
2. Filters out binary files and common non-source directories
3. Reads text files with UTF-8 encoding (with fallback)
4. Applies all active patterns to each line
5. Reports findings with file location and masked content

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No secrets found (or `--exit-code=never`) |
| 1 | Secrets found (or `--exit-code=always` with findings) |
| 2 | Error during scanning |

## CI/CD Integration

### GitHub Actions

```yaml
- name: Scan for secrets
  run: |
    python -m secret_leak_detector --json --output results.json .
    if [ $? -ne 0 ]; then
      echo "Secrets detected!"
      exit 1
    fi
```

### GitLab CI

```yaml
secret_scan:
  script:
    - python -m secret_leak_detector -s high .
  allow_failure: false
```

### Pre-commit Hook

```yaml
# .pre-commit-config.yaml
- repo: local
  hooks:
    - id: secret-leak-detector
      name: Secret Leak Detector
      entry: python -m secret_leak_detector
      language: system
      pass_filenames: false
      always_run: true
```

## Project Structure

```
secret_leak_detector/
├── __init__.py          # Package initialization
├── __main__.py          # Module entry point
├── cli.py               # Command-line interface
├── detector.py          # Core detection logic
├── patterns.py          # Secret detection patterns
└── scanner.py           # File scanning utilities

tests/
└── test_detector.py     # Test suite

requirements.txt         # Dependencies (none required)
README.md               # This file
```

## API Usage

```python
from secret_leak_detector import SecretDetector, FileScanner, create_scanner

# Using the detector directly
detector = SecretDetector(min_severity="high")
result = detector.scan_content("key = 'AKIAIOSFODNN7EXAMPLE'", "test.py")

for finding in result.findings:
    print(f"{finding.secret_type}: {finding.line_content}")

# Using the file scanner
scanner = create_scanner(min_severity="medium")
for result in scanner.scan_path("./src"):
    if result.has_findings:
        print(f"Found {result.finding_count} secrets in {result.file_path}")
```

## Adding Custom Patterns

```python
from secret_leak_detector import SecretDetector, SecretPattern
import re

detector = SecretDetector()

# Add a custom pattern
custom_pattern = SecretPattern(
    name="Custom API Key",
    pattern=re.compile(r"CUSTOM_API_\w{32}"),
    severity="high",
    description="Custom internal API key format",
)
detector.add_pattern(custom_pattern)
```

## Limitations

- Pattern-based detection may produce false positives
- Encrypted secrets cannot be detected
- Secrets in compiled binaries are not scanned
- Very large files (>10MB by default) are skipped

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Run the test suite: `pytest tests/`
5. Submit a pull request

## License

MIT License - see LICENSE file for details.

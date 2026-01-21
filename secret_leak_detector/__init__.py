"""
Secret Leak Detector - Scan codebases for accidentally committed secrets.

A CLI tool to detect secrets, API keys, tokens, and credentials
that may have been accidentally committed to source code.
"""

__version__ = "1.0.0"
__author__ = "Secret Leak Detector Team"

from .detector import Finding, ScanResult, SecretDetector, EntropyAnalyzer
from .patterns import SecretPattern, PatternRegistry, get_all_patterns
from .scanner import FileScanner, ScanProgress, create_scanner

__all__ = [
    "__version__",
    "Finding",
    "ScanResult",
    "SecretDetector",
    "EntropyAnalyzer",
    "SecretPattern",
    "PatternRegistry",
    "get_all_patterns",
    "FileScanner",
    "ScanProgress",
    "create_scanner",
]

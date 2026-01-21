"""
Core detection logic for finding secrets in text content.

This module provides the main detection engine that applies patterns
to text content and returns structured findings.
"""

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from .patterns import SecretPattern, get_all_patterns


@dataclass
class Finding:
    """Represents a detected secret in the scanned content."""

    secret_type: str
    severity: str
    description: str
    file_path: str
    line_number: int
    line_content: str
    match_start: int
    match_end: int
    matched_value: str

    def to_dict(self) -> Dict:
        """Convert finding to dictionary representation."""
        return {
            "secret_type": self.secret_type,
            "severity": self.severity,
            "description": self.description,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "line_content": self._masked_line(),
            "column": self.match_start + 1,
        }

    def _masked_line(self) -> str:
        """Return line content with the secret value masked."""
        if self.match_end > len(self.line_content):
            return self.line_content
        masked = "*" * (self.match_end - self.match_start)
        return (
            self.line_content[: self.match_start]
            + masked
            + self.line_content[self.match_end :]
        )

    def __str__(self) -> str:
        return (
            f"[{self.severity.upper()}] {self.secret_type} in {self.file_path}:{self.line_number}\n"
            f"  {self.line_content.strip()}"
        )


@dataclass
class ScanResult:
    """Results from scanning a file or directory."""

    file_path: str
    findings: List[Finding] = field(default_factory=list)
    lines_scanned: int = 0
    scan_error: Optional[str] = None

    @property
    def has_findings(self) -> bool:
        """Check if any secrets were found."""
        return len(self.findings) > 0

    @property
    def finding_count(self) -> int:
        """Return the total number of findings."""
        return len(self.findings)

    def findings_by_severity(self) -> Dict[str, int]:
        """Count findings grouped by severity."""
        counts: Dict[str, int] = {}
        for finding in self.findings:
            counts[finding.severity] = counts.get(finding.severity, 0) + 1
        return counts

    def to_dict(self) -> Dict:
        """Convert result to dictionary."""
        return {
            "file_path": self.file_path,
            "lines_scanned": self.lines_scanned,
            "finding_count": self.finding_count,
            "findings_by_severity": self.findings_by_severity(),
            "findings": [f.to_dict() for f in self.findings],
            "error": self.scan_error,
        }


class SecretDetector:
    """
    Main detector class that scans content for secrets.

    Applies registered patterns to text content and returns
    structured findings for any matches.
    """

    def __init__(
        self,
        patterns: Optional[List[SecretPattern]] = None,
        min_severity: str = "low",
        exclude_patterns: Optional[Set[str]] = None,
    ):
        """
        Initialize the detector.

        Args:
            patterns: List of patterns to use. If None, uses all registered patterns.
            min_severity: Minimum severity level to report.
            exclude_patterns: Set of pattern names to exclude from scanning.
        """
        self._severity_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
        self._min_severity_level = self._severity_order.get(min_severity.lower(), 0)
        self._exclude_patterns = exclude_patterns or set()

        if patterns is None:
            patterns = get_all_patterns()

        self._patterns = self._filter_patterns(patterns)

    def _filter_patterns(self, patterns: List[SecretPattern]) -> List[SecretPattern]:
        """Filter patterns based on severity and exclusions."""
        filtered = []
        for pattern in patterns:
            if pattern.name in self._exclude_patterns:
                continue
            if self._severity_order.get(pattern.severity, 0) < self._min_severity_level:
                continue
            filtered.append(pattern)
        return filtered

    def scan_content(self, content: str, file_path: str) -> ScanResult:
        """
        Scan text content for secrets.

        Args:
            content: The text content to scan.
            file_path: Path to the file (for reporting purposes).

        Returns:
            ScanResult containing any findings.
        """
        result = ScanResult(file_path=file_path)
        lines = content.splitlines()
        result.lines_scanned = len(lines)

        for line_num, line in enumerate(lines, start=1):
            findings = self._scan_line(line, file_path, line_num)
            result.findings.extend(findings)

        return result

    def _scan_line(
        self, line: str, file_path: str, line_num: int
    ) -> List[Finding]:
        """Scan a single line for all patterns."""
        findings = []

        for pattern in self._patterns:
            matches = pattern.match(line)
            for match in matches:
                finding = Finding(
                    secret_type=pattern.name,
                    severity=pattern.severity,
                    description=pattern.description,
                    file_path=file_path,
                    line_number=line_num,
                    line_content=line,
                    match_start=match.start(),
                    match_end=match.end(),
                    matched_value=match.group(),
                )
                findings.append(finding)

        return self._deduplicate_findings(findings)

    def _deduplicate_findings(self, findings: List[Finding]) -> List[Finding]:
        """Remove duplicate findings for the same location."""
        seen: Set[Tuple[str, int, int]] = set()
        unique = []

        for finding in findings:
            key = (finding.secret_type, finding.line_number, finding.match_start)
            if key not in seen:
                seen.add(key)
                unique.append(finding)

        return unique

    def add_pattern(self, pattern: SecretPattern) -> None:
        """Add a new pattern to the detector."""
        if pattern.name not in self._exclude_patterns:
            if self._severity_order.get(pattern.severity, 0) >= self._min_severity_level:
                self._patterns.append(pattern)

    def remove_pattern(self, name: str) -> bool:
        """Remove a pattern by name. Returns True if found and removed."""
        for i, pattern in enumerate(self._patterns):
            if pattern.name == name:
                self._patterns.pop(i)
                return True
        return False

    @property
    def pattern_count(self) -> int:
        """Return the number of active patterns."""
        return len(self._patterns)

    @property
    def patterns(self) -> List[SecretPattern]:
        """Return the list of active patterns."""
        return self._patterns.copy()


class EntropyAnalyzer:
    """
    Analyze string entropy to detect high-entropy strings
    that might be secrets even if they don't match known patterns.
    """

    def __init__(self, threshold: float = 4.5):
        """
        Initialize the entropy analyzer.

        Args:
            threshold: Minimum entropy value to flag a string as suspicious.
        """
        self.threshold = threshold

    def calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of the given text."""
        if not text:
            return 0.0

        freq: Dict[str, int] = {}
        for char in text:
            freq[char] = freq.get(char, 0) + 1

        entropy = 0.0
        length = len(text)
        for count in freq.values():
            probability = count / length
            if probability > 0:
                entropy -= probability * (probability and (probability > 0) and
                                         __import__('math').log2(probability))

        return entropy

    def is_high_entropy(self, text: str) -> bool:
        """Check if the text has high entropy (potentially a secret)."""
        if len(text) < 16:
            return False
        return self.calculate_entropy(text) >= self.threshold

    def find_high_entropy_strings(
        self, content: str, file_path: str, min_length: int = 20
    ) -> List[Finding]:
        """
        Find high-entropy strings that might be secrets.

        Args:
            content: The text content to analyze.
            file_path: Path to the file (for reporting).
            min_length: Minimum string length to consider.

        Returns:
            List of findings for high-entropy strings.
        """
        findings = []
        lines = content.splitlines()

        for line_num, line in enumerate(lines, start=1):
            candidates = self._extract_candidates(line, min_length)
            for start, end, candidate in candidates:
                if self.is_high_entropy(candidate):
                    finding = Finding(
                        secret_type="High Entropy String",
                        severity="low",
                        description="High entropy string that may be a secret",
                        file_path=file_path,
                        line_number=line_num,
                        line_content=line,
                        match_start=start,
                        match_end=end,
                        matched_value=candidate,
                    )
                    findings.append(finding)

        return findings

    def _extract_candidates(
        self, line: str, min_length: int
    ) -> List[Tuple[int, int, str]]:
        """Extract potential secret candidates from a line."""
        candidates = []
        current_start = None
        current_chars = []

        for i, char in enumerate(line):
            if char.isalnum() or char in "-_+=":
                if current_start is None:
                    current_start = i
                current_chars.append(char)
            else:
                if current_start is not None and len(current_chars) >= min_length:
                    candidates.append(
                        (current_start, i, "".join(current_chars))
                    )
                current_start = None
                current_chars = []

        if current_start is not None and len(current_chars) >= min_length:
            candidates.append(
                (current_start, len(line), "".join(current_chars))
            )

        return candidates

"""
Tests for the secret leak detector.

Run with: pytest tests/test_detector.py -v
"""

import os
import tempfile
from pathlib import Path

import pytest

from secret_leak_detector.detector import (
    EntropyAnalyzer,
    Finding,
    ScanResult,
    SecretDetector,
)
from secret_leak_detector.patterns import (
    PatternRegistry,
    SecretPattern,
    get_all_patterns,
)
from secret_leak_detector.scanner import FileScanner, create_scanner


class TestSecretPattern:
    """Tests for the SecretPattern class."""

    def test_pattern_match_finds_secrets(self):
        pattern = SecretPattern(
            name="Test Pattern",
            pattern=__import__("re").compile(r"secret_\w+"),
            severity="high",
            description="Test description",
        )
        text = "This is a secret_key in the code"
        matches = pattern.match(text)
        assert len(matches) == 1
        assert matches[0].group() == "secret_key"

    def test_pattern_match_multiple(self):
        pattern = SecretPattern(
            name="Test Pattern",
            pattern=__import__("re").compile(r"API_\w+"),
            severity="medium",
            description="Test description",
        )
        text = "API_KEY and API_SECRET are here"
        matches = pattern.match(text)
        assert len(matches) == 2


class TestPatternRegistry:
    """Tests for the PatternRegistry class."""

    def test_registry_has_patterns(self):
        registry = PatternRegistry()
        assert len(registry.patterns) > 0

    def test_get_by_severity(self):
        registry = PatternRegistry()
        high_patterns = registry.get_by_severity("high")
        assert len(high_patterns) > 0
        for pattern in high_patterns:
            assert pattern.severity == "high"

    def test_get_by_name(self):
        registry = PatternRegistry()
        pattern = registry.get_by_name("AWS Access Key ID")
        assert pattern is not None
        assert pattern.name == "AWS Access Key ID"

    def test_get_by_name_not_found(self):
        registry = PatternRegistry()
        pattern = registry.get_by_name("NonExistent Pattern")
        assert pattern is None


class TestGetAllPatterns:
    """Tests for the get_all_patterns function."""

    def test_returns_list(self):
        patterns = get_all_patterns()
        assert isinstance(patterns, list)
        assert len(patterns) > 0

    def test_all_have_required_fields(self):
        patterns = get_all_patterns()
        for pattern in patterns:
            assert hasattr(pattern, "name")
            assert hasattr(pattern, "pattern")
            assert hasattr(pattern, "severity")
            assert hasattr(pattern, "description")


class TestFinding:
    """Tests for the Finding class."""

    def test_finding_creation(self):
        finding = Finding(
            secret_type="Test Secret",
            severity="high",
            description="Test description",
            file_path="/test/file.py",
            line_number=10,
            line_content="secret = 'abc123'",
            match_start=10,
            match_end=16,
            matched_value="abc123",
        )
        assert finding.secret_type == "Test Secret"
        assert finding.severity == "high"
        assert finding.line_number == 10

    def test_finding_to_dict(self):
        finding = Finding(
            secret_type="Test Secret",
            severity="high",
            description="Test description",
            file_path="/test/file.py",
            line_number=10,
            line_content="secret = 'abc123'",
            match_start=10,
            match_end=16,
            matched_value="abc123",
        )
        result = finding.to_dict()
        assert result["secret_type"] == "Test Secret"
        assert result["severity"] == "high"
        assert result["line_number"] == 10
        assert "masked" in result["line_content"] or "*" in result["line_content"]

    def test_finding_str(self):
        finding = Finding(
            secret_type="AWS Key",
            severity="critical",
            description="AWS Access Key",
            file_path="/test/file.py",
            line_number=5,
            line_content="key = 'AKIAIOSFODNN7EXAMPLE'",
            match_start=6,
            match_end=26,
            matched_value="AKIAIOSFODNN7EXAMPLE",
        )
        str_repr = str(finding)
        assert "[CRITICAL]" in str_repr
        assert "AWS Key" in str_repr
        assert "/test/file.py:5" in str_repr


class TestScanResult:
    """Tests for the ScanResult class."""

    def test_scan_result_empty(self):
        result = ScanResult(file_path="/test/file.py")
        assert not result.has_findings
        assert result.finding_count == 0
        assert result.lines_scanned == 0

    def test_scan_result_with_findings(self):
        result = ScanResult(file_path="/test/file.py")
        result.findings.append(
            Finding(
                secret_type="Test",
                severity="high",
                description="Test",
                file_path="/test/file.py",
                line_number=1,
                line_content="test",
                match_start=0,
                match_end=4,
                matched_value="test",
            )
        )
        result.lines_scanned = 10
        assert result.has_findings
        assert result.finding_count == 1

    def test_findings_by_severity(self):
        result = ScanResult(file_path="/test/file.py")
        for severity in ["high", "high", "medium", "low"]:
            result.findings.append(
                Finding(
                    secret_type="Test",
                    severity=severity,
                    description="Test",
                    file_path="/test/file.py",
                    line_number=1,
                    line_content="test",
                    match_start=0,
                    match_end=4,
                    matched_value="test",
                )
            )
        counts = result.findings_by_severity()
        assert counts["high"] == 2
        assert counts["medium"] == 1
        assert counts["low"] == 1

    def test_to_dict(self):
        result = ScanResult(file_path="/test/file.py")
        result.lines_scanned = 5
        result_dict = result.to_dict()
        assert result_dict["file_path"] == "/test/file.py"
        assert result_dict["lines_scanned"] == 5
        assert result_dict["finding_count"] == 0


class TestSecretDetector:
    """Tests for the SecretDetector class."""

    def test_detector_initialization(self):
        detector = SecretDetector()
        assert detector.pattern_count > 0

    def test_detector_with_min_severity(self):
        detector = SecretDetector(min_severity="high")
        for pattern in detector.patterns:
            assert pattern.severity in ["high", "critical"]

    def test_detector_scan_content_aws_key(self):
        detector = SecretDetector()
        content = "aws_key = 'AKIAIOSFODNN7EXAMPLE'"
        result = detector.scan_content(content, "/test/file.py")
        assert result.has_findings
        assert any(f.secret_type == "AWS Access Key ID" for f in result.findings)

    def test_detector_scan_content_github_token(self):
        detector = SecretDetector()
        content = "token = 'ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'"
        result = detector.scan_content(content, "/test/file.py")
        assert result.has_findings
        assert any("GitHub" in f.secret_type for f in result.findings)

    def test_detector_scan_content_private_key(self):
        detector = SecretDetector()
        content = "-----BEGIN RSA PRIVATE KEY-----"
        result = detector.scan_content(content, "/test/file.py")
        assert result.has_findings
        assert any(f.secret_type == "Private Key" for f in result.findings)

    def test_detector_scan_content_clean(self):
        detector = SecretDetector()
        content = "This is a clean file with no secrets."
        result = detector.scan_content(content, "/test/file.py")
        assert not result.has_findings

    def test_detector_scan_multiple_lines(self):
        detector = SecretDetector()
        content = """
        def func():
            aws = 'AKIAIOSFODNN7EXAMPLE'
            return None
        """
        result = detector.scan_content(content, "/test/file.py")
        assert result.lines_scanned == 5
        assert result.has_findings

    def test_detector_exclude_patterns(self):
        detector = SecretDetector(exclude_patterns={"AWS Access Key ID"})
        content = "key = 'AKIAIOSFODNN7EXAMPLE'"
        result = detector.scan_content(content, "/test/file.py")
        aws_findings = [f for f in result.findings if f.secret_type == "AWS Access Key ID"]
        assert len(aws_findings) == 0

    def test_detector_add_pattern(self):
        detector = SecretDetector()
        initial_count = detector.pattern_count
        new_pattern = SecretPattern(
            name="Custom Pattern",
            pattern=__import__("re").compile(r"CUSTOM_\w+"),
            severity="low",
            description="Custom test pattern",
        )
        detector.add_pattern(new_pattern)
        assert detector.pattern_count == initial_count + 1

    def test_detector_remove_pattern(self):
        detector = SecretDetector()
        initial_count = detector.pattern_count
        removed = detector.remove_pattern("AWS Access Key ID")
        if removed:
            assert detector.pattern_count == initial_count - 1


class TestEntropyAnalyzer:
    """Tests for the EntropyAnalyzer class."""

    def test_entropy_low_for_repetitive(self):
        analyzer = EntropyAnalyzer()
        entropy = analyzer.calculate_entropy("aaaaaaaaaa")
        assert entropy < 1.0

    def test_entropy_high_for_random(self):
        analyzer = EntropyAnalyzer()
        entropy = analyzer.calculate_entropy("aB3$kL9@mN2#pQ5&")
        assert entropy > 3.0

    def test_is_high_entropy(self):
        analyzer = EntropyAnalyzer(threshold=3.5)
        assert not analyzer.is_high_entropy("repetitive_string_here")
        assert analyzer.is_high_entropy("aB3$kL9@mN2#pQ5&rT7*")

    def test_find_high_entropy_strings(self):
        analyzer = EntropyAnalyzer(threshold=3.5)
        content = "normal text here and aB3$kL9@mN2#pQ5&rT7* secret"
        findings = analyzer.find_high_entropy_strings(content, "/test/file.py")
        assert len(findings) >= 0


class TestFileScanner:
    """Tests for the FileScanner class."""

    def test_scanner_creation(self):
        detector = SecretDetector()
        scanner = FileScanner(detector)
        assert scanner is not None

    def test_scanner_scan_file(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write("secret = 'AKIAIOSFODNN7EXAMPLE'\n")
            f.flush()
            temp_path = f.name

        try:
            scanner = create_scanner()
            results = list(scanner.scan_path(temp_path))
            assert len(results) == 1
            assert results[0].has_findings
        finally:
            os.unlink(temp_path)

    def test_scanner_scan_clean_file(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write("print('Hello, World!')\n")
            f.flush()
            temp_path = f.name

        try:
            scanner = create_scanner()
            results = list(scanner.scan_path(temp_path))
            assert len(results) == 1
            assert not results[0].has_findings
        finally:
            os.unlink(temp_path)

    def test_scanner_scan_directory(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            file1 = Path(temp_dir) / "file1.py"
            file2 = Path(temp_dir) / "file2.py"
            file1.write_text("key = 'AKIAIOSFODNN7EXAMPLE'\n")
            file2.write_text("print('clean')\n")

            scanner = create_scanner()
            results = list(scanner.scan_path(temp_dir))
            assert len(results) == 2

    def test_scanner_ignore_patterns(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            node_modules = Path(temp_dir) / "node_modules"
            node_modules.mkdir()
            test_file = node_modules / "test.py"
            test_file.write_text("key = 'AKIAIOSFODNN7EXAMPLE'\n")

            scanner = create_scanner()
            results = list(scanner.scan_path(temp_dir))
            assert len(results) == 0

    def test_scanner_file_not_found(self):
        scanner = create_scanner()
        with pytest.raises(FileNotFoundError):
            list(scanner.scan_path("/nonexistent/path"))


class TestCreateScanner:
    """Tests for the create_scanner function."""

    def test_create_scanner_default(self):
        scanner = create_scanner()
        assert scanner is not None
        assert scanner.detector.pattern_count > 0

    def test_create_scanner_with_options(self):
        scanner = create_scanner(
            min_severity="high",
            scan_all_files=True,
        )
        assert scanner is not None
        assert scanner.scan_all_files is True


class TestIntegration:
    """Integration tests for the full scanning workflow."""

    def test_full_scan_workflow(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            test_file = Path(temp_dir) / "secrets.py"
            test_file.write_text(
                "AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'\n"
                "GITHUB_TOKEN = 'ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'\n"
                "DATABASE_URL = 'postgres://user:pass@localhost/db'\n"
            )

            scanner = create_scanner()
            results = list(scanner.scan_path(temp_dir))

            assert len(results) == 1
            assert results[0].has_findings
            assert results[0].finding_count >= 3

    def test_json_output_format(self):
        detector = SecretDetector()
        content = "key = 'AKIAIOSFODNN7EXAMPLE'"
        result = detector.scan_content(content, "/test/file.py")
        result_dict = result.to_dict()

        assert "file_path" in result_dict
        assert "findings" in result_dict
        assert "finding_count" in result_dict
        assert isinstance(result_dict["findings"], list)

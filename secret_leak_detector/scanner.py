"""
File and directory scanning utilities for the secret detector.

This module handles file system traversal, file type detection,
and exclusion pattern matching.
"""

import fnmatch
import os
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Generator, List, Optional, Set, Tuple

from .detector import ScanResult, SecretDetector


DEFAULT_IGNORE_PATTERNS = {
    ".git",
    ".svn",
    ".hg",
    "node_modules",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".tox",
    ".eggs",
    "*.egg-info",
    "venv",
    ".venv",
    "env",
    ".env",
    "dist",
    "build",
    "*.min.js",
    "*.min.css",
    "*.map",
    "*.pyc",
    "*.pyo",
    "*.so",
    "*.dll",
    "*.exe",
    "*.bin",
    "*.lock",
    "package-lock.json",
    "yarn.lock",
    "poetry.lock",
    "Cargo.lock",
    ".DS_Store",
    "Thumbs.db",
}

DEFAULT_FILE_EXTENSIONS = {
    ".py",
    ".js",
    ".ts",
    ".jsx",
    ".tsx",
    ".java",
    ".c",
    ".cpp",
    ".h",
    ".hpp",
    ".cs",
    ".go",
    ".rs",
    ".rb",
    ".php",
    ".swift",
    ".kt",
    ".kts",
    ".scala",
    ".sh",
    ".bash",
    ".zsh",
    ".fish",
    ".ps1",
    ".yaml",
    ".yml",
    ".json",
    ".toml",
    ".ini",
    ".cfg",
    ".conf",
    ".properties",
    ".env",
    ".example",
    ".sample",
    ".template",
    ".xml",
    ".html",
    ".htm",
    ".css",
    ".scss",
    ".sass",
    ".less",
    ".sql",
    ".md",
    ".rst",
    ".txt",
    ".log",
    ".sql",
    ".graphql",
    ".gql",
    ".proto",
    ".tf",
    ".tfvars",
    ".hcl",
    ".dockerfile",
    "dockerfile",
    "makefile",
    "rakefile",
    "gemfile",
    "pom.xml",
    "build.gradle",
    "settings.gradle",
    "cargo.toml",
    "cargo.lock",
}

BINARY_EXTENSIONS = {
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".bmp",
    ".ico",
    ".webp",
    ".svg",
    ".pdf",
    ".doc",
    ".docx",
    ".xls",
    ".xlsx",
    ".ppt",
    ".pptx",
    ".zip",
    ".tar",
    ".gz",
    ".rar",
    ".7z",
    ".mp3",
    ".mp4",
    ".avi",
    ".mov",
    ".wav",
    ".flac",
    ".ogg",
    ".webm",
    ".mkv",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".otf",
}


@dataclass
class ScanProgress:
    """Track progress during a directory scan."""

    files_scanned: int = 0
    files_skipped: int = 0
    total_findings: int = 0
    current_file: Optional[str] = None
    errors: List[Tuple[str, str]] = field(default_factory=list)

    def add_error(self, file_path: str, error: str) -> None:
        """Record an error encountered during scanning."""
        self.errors.append((file_path, error))

    @property
    def error_count(self) -> int:
        """Return the number of errors encountered."""
        return len(self.errors)


class FileScanner:
    """
    Scans files and directories for secrets.

    Handles file system traversal, file filtering, and
    coordinates with the SecretDetector for content analysis.
    """

    def __init__(
        self,
        detector: SecretDetector,
        ignore_patterns: Optional[Set[str]] = None,
        file_extensions: Optional[Set[str]] = None,
        scan_all_files: bool = False,
        max_file_size: int = 10 * 1024 * 1024,
    ):
        """
        Initialize the file scanner.

        Args:
            detector: SecretDetector instance to use for scanning.
            ignore_patterns: Patterns for files/dirs to ignore.
            file_extensions: File extensions to scan. If None, uses defaults.
            scan_all_files: If True, scan all files regardless of extension.
            max_file_size: Maximum file size in bytes to scan.
        """
        self.detector = detector
        self.ignore_patterns = ignore_patterns or DEFAULT_IGNORE_PATTERNS
        self.file_extensions = file_extensions or DEFAULT_FILE_EXTENSIONS
        self.scan_all_files = scan_all_files
        self.max_file_size = max_file_size

    def scan_path(self, path: str) -> Generator[ScanResult, None, None]:
        """
        Scan a file or directory for secrets.

        Args:
            path: Path to the file or directory to scan.

        Yields:
            ScanResult for each file scanned.
        """
        path_obj = Path(path)

        if not path_obj.exists():
            raise FileNotFoundError(f"Path does not exist: {path}")

        if path_obj.is_file():
            result = self._scan_file(path_obj)
            if result is not None:
                yield result
        else:
            yield from self._scan_directory(path_obj)

    def _scan_directory(
        self, directory: Path
    ) -> Generator[ScanResult, None, None]:
        """Scan all files in a directory recursively."""
        for root, dirs, files in os.walk(directory):
            root_path = Path(root)

            dirs[:] = [
                d
                for d in dirs
                if not self._should_ignore(root_path / d, is_dir=True)
            ]

            for filename in files:
                file_path = root_path / filename

                if self._should_ignore(file_path):
                    continue

                result = self._scan_file(file_path)
                if result is not None:
                    yield result

    def _scan_file(self, file_path: Path) -> Optional[ScanResult]:
        """Scan a single file for secrets."""
        try:
            if not self._is_scannable(file_path):
                return None

            file_size = file_path.stat().st_size
            if file_size > self.max_file_size:
                return ScanResult(
                    file_path=str(file_path),
                    scan_error=f"File too large ({file_size} bytes)",
                )

            content = file_path.read_text(encoding="utf-8", errors="ignore")
            return self.detector.scan_content(content, str(file_path))

        except PermissionError:
            return ScanResult(
                file_path=str(file_path),
                scan_error="Permission denied",
            )
        except UnicodeDecodeError as e:
            return ScanResult(
                file_path=str(file_path),
                scan_error=f"Encoding error: {e}",
            )
        except OSError as e:
            return ScanResult(
                file_path=str(file_path),
                scan_error=f"OS error: {e}",
            )

    def _should_ignore(self, path: Path, is_dir: bool = False) -> bool:
        """Check if a path should be ignored."""
        name = path.name

        for pattern in self.ignore_patterns:
            if fnmatch.fnmatch(name, pattern):
                return True
            if fnmatch.fnmatch(str(path), f"*{pattern}*"):
                return True

        if not is_dir and not self.scan_all_files:
            suffix = path.suffix.lower()
            if suffix not in self.file_extensions:
                return True

        return False

    def _is_scannable(self, path: Path) -> bool:
        """Check if a file is scannable (not binary, etc.)."""
        if not path.is_file():
            return False

        suffix = path.suffix.lower()
        if suffix in BINARY_EXTENSIONS:
            return False

        try:
            mode = path.stat().st_mode
            if stat.S_ISLNK(mode):
                return False
        except OSError:
            return False

        return True

    def scan_with_progress(
        self, path: str
    ) -> Tuple[Generator[ScanResult, None, None], ScanProgress]:
        """
        Scan a path while tracking progress.

        Args:
            path: Path to scan.

        Returns:
            Tuple of (results generator, progress tracker).
        """
        progress = ScanProgress()

        def tracked_scan() -> Generator[ScanResult, None, None]:
            for result in self.scan_path(path):
                progress.files_scanned += 1
                progress.current_file = result.file_path
                progress.total_findings += result.finding_count

                if result.scan_error:
                    progress.add_error(result.file_path, result.scan_error)

                yield result

        return tracked_scan(), progress


def create_scanner(
    min_severity: str = "low",
    ignore_patterns: Optional[Set[str]] = None,
    file_extensions: Optional[Set[str]] = None,
    scan_all_files: bool = False,
    exclude_pattern_names: Optional[Set[str]] = None,
) -> FileScanner:
    """
    Create a configured FileScanner instance.

    Args:
        min_severity: Minimum severity level to report.
        ignore_patterns: Patterns for files/dirs to ignore.
        file_extensions: File extensions to scan.
        scan_all_files: If True, scan all files regardless of extension.
        exclude_pattern_names: Pattern names to exclude from detection.

    Returns:
        Configured FileScanner instance.
    """
    detector = SecretDetector(
        min_severity=min_severity,
        exclude_patterns=exclude_pattern_names,
    )

    return FileScanner(
        detector=detector,
        ignore_patterns=ignore_patterns,
        file_extensions=file_extensions,
        scan_all_files=scan_all_files,
    )

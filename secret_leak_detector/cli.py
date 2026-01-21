"""
Command-line interface for the secret leak detector.

Provides a full-featured CLI for scanning codebases,
configuring detection options, and outputting results.
"""

import argparse
import json
import sys
from pathlib import Path
from typing import List, Optional, Set

from . import __version__
from .detector import Finding, ScanResult
from .scanner import FileScanner, ScanProgress, create_scanner


SEVERITY_COLORS = {
    "critical": "\033[91m",
    "high": "\033[91m",
    "medium": "\033[93m",
    "low": "\033[94m",
}

RESET_COLOR = "\033[0m"
BOLD = "\033[1m"


class OutputFormatter:
    """Format scan results for different output modes."""

    def __init__(self, use_color: bool = True, verbose: bool = False):
        self.use_color = use_color and sys.stdout.isatty()
        self.verbose = verbose

    def _color(self, text: str, severity: str) -> str:
        if not self.use_color:
            return text
        color = SEVERITY_COLORS.get(severity.lower(), "")
        return f"{color}{text}{RESET_COLOR}"

    def format_finding(self, finding: Finding) -> str:
        """Format a single finding for display."""
        severity_colored = self._color(f"[{finding.severity.upper()}]", finding.severity)
        lines = [
            f"{severity_colored} {finding.secret_type}",
            f"  Location: {finding.file_path}:{finding.line_number}:{finding.match_start + 1}",
            f"  {finding.line_content.strip()}",
        ]

        if self.verbose:
            lines.append(f"  Description: {finding.description}")
            lines.append(f"  Matched: {finding.matched_value[:50]}...")

        return "\n".join(lines)

    def format_result(self, result: ScanResult) -> str:
        """Format scan results for a file."""
        if not result.has_findings:
            return ""

        lines = [f"\n{BOLD}File: {result.file_path}{RESET_COLOR}"]
        lines.append(f"Lines scanned: {result.lines_scanned}")
        lines.append(f"Findings: {result.finding_count}")

        for finding in result.findings:
            lines.append("")
            lines.append(self.format_finding(finding))

        return "\n".join(lines)

    def format_summary(
        self,
        files_scanned: int,
        total_findings: int,
        findings_by_severity: dict,
        errors: List[tuple],
    ) -> str:
        """Format a summary of the scan."""
        lines = [
            "",
            f"{BOLD}{'=' * 60}{RESET_COLOR}",
            f"{BOLD}Scan Summary{RESET_COLOR}",
            f"{'=' * 60}",
            f"Files scanned: {files_scanned}",
            f"Total findings: {total_findings}",
        ]

        if findings_by_severity:
            lines.append("\nFindings by severity:")
            for severity in ["critical", "high", "medium", "low"]:
                count = findings_by_severity.get(severity, 0)
                if count > 0:
                    colored = self._color(severity.upper(), severity)
                    lines.append(f"  {colored}: {count}")

        if errors:
            lines.append(f"\nErrors encountered: {len(errors)}")
            if self.verbose:
                for path, error in errors[:10]:
                    lines.append(f"  - {path}: {error}")

        lines.append(f"{BOLD}{'=' * 60}{RESET_COLOR}")
        return "\n".join(lines)


def parse_args(args: Optional[List[str]] = None) -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        prog="secret-leak-detector",
        description="Scan codebases for accidentally committed secrets and credentials.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s /path/to/project
  %(prog)s -s high ./src
  %(prog)s --json --output results.json .
  %(prog)s --exclude-patterns "*.min.js,node_modules" ./codebase
  %(prog)s --list-patterns

Exit codes:
  0 - No secrets found
  1 - Secrets found
  2 - Error during scanning
        """,
    )

    parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="Path to file or directory to scan (default: current directory)",
    )

    parser.add_argument(
        "-v", "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    parser.add_argument(
        "-s", "--severity",
        choices=["low", "medium", "high", "critical"],
        default="low",
        help="Minimum severity level to report (default: low)",
    )

    parser.add_argument(
        "--json",
        action="store_true",
        help="Output results in JSON format",
    )

    parser.add_argument(
        "-o", "--output",
        metavar="FILE",
        help="Write results to a file instead of stdout",
    )

    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored output",
    )

    parser.add_argument(
        "--verbose", "-V",
        action="store_true",
        help="Show verbose output including descriptions",
    )

    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Only show summary, no individual findings",
    )

    parser.add_argument(
        "--list-patterns",
        action="store_true",
        help="List all detection patterns and exit",
    )

    parser.add_argument(
        "--exclude-patterns",
        metavar="PATTERNS",
        help="Comma-separated glob patterns to exclude (e.g., '*.min.js,node_modules')",
    )

    parser.add_argument(
        "--extensions",
        metavar="EXTS",
        help="Comma-separated file extensions to scan (default: common source files)",
    )

    parser.add_argument(
        "--all-files",
        action="store_true",
        help="Scan all files regardless of extension",
    )

    parser.add_argument(
        "--max-file-size",
        type=int,
        default=10 * 1024 * 1024,
        metavar="BYTES",
        help="Maximum file size to scan (default: 10MB)",
    )

    parser.add_argument(
        "--exit-code",
        choices=["always", "findings", "never"],
        default="findings",
        help="When to return non-zero exit code (default: findings)",
    )

    return parser.parse_args(args)


def list_patterns() -> None:
    """Print all available detection patterns."""
    from .patterns import get_all_patterns

    patterns = get_all_patterns()
    patterns_by_severity = {}

    for pattern in patterns:
        sev = pattern.severity
        if sev not in patterns_by_severity:
            patterns_by_severity[sev] = []
        patterns_by_severity[sev].append(pattern)

    print(f"{BOLD}Available Detection Patterns{RESET_COLOR}")
    print("=" * 60)

    for severity in ["critical", "high", "medium", "low"]:
        if severity in patterns_by_severity:
            print(f"\n{SEVERITY_COLORS[severity]}{severity.upper()}{RESET_COLOR}:")
            for pattern in patterns_by_severity[severity]:
                print(f"  - {pattern.name}: {pattern.description}")

    print(f"\nTotal patterns: {len(patterns)}")


def scan_directory(
    path: str,
    severity: str = "low",
    exclude_patterns: Optional[Set[str]] = None,
    file_extensions: Optional[Set[str]] = None,
    scan_all_files: bool = False,
    max_file_size: int = 10 * 1024 * 1024,
) -> tuple:
    """
    Scan a directory or file for secrets.

    Returns:
        Tuple of (results list, progress object).
    """
    scanner = create_scanner(
        min_severity=severity,
        ignore_patterns=exclude_patterns,
        file_extensions=file_extensions,
        scan_all_files=scan_all_files,
    )
    scanner.max_file_size = max_file_size

    results = []
    progress = ScanProgress()

    try:
        for result in scanner.scan_path(path):
            results.append(result)
            progress.files_scanned += 1
            progress.total_findings += result.finding_count

            if result.scan_error:
                progress.add_error(result.file_path, result.scan_error)

    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(2)
    except PermissionError as e:
        print(f"Error: Permission denied - {e}", file=sys.stderr)
        sys.exit(2)

    return results, progress


def aggregate_findings(results: List[ScanResult]) -> tuple:
    """Aggregate findings from multiple scan results."""
    all_findings = []
    findings_by_severity = {}
    total_lines = 0

    for result in results:
        all_findings.extend(result.findings)
        total_lines += result.lines_scanned

        for severity, count in result.findings_by_severity().items():
            findings_by_severity[severity] = (
                findings_by_severity.get(severity, 0) + count
            )

    return all_findings, findings_by_severity, total_lines


def output_results(
    results: List[ScanResult],
    progress: ScanProgress,
    args: argparse.Namespace,
) -> int:
    """Output scan results and return appropriate exit code."""
    all_findings, findings_by_severity, _ = aggregate_findings(results)
    total_findings = len(all_findings)

    formatter = OutputFormatter(
        use_color=not args.no_color,
        verbose=args.verbose,
    )

    output_lines = []

    if not args.quiet and not args.json:
        for result in results:
            if result.has_findings:
                output_lines.append(formatter.format_result(result))

    if args.json:
        output_data = {
            "scan_summary": {
                "files_scanned": progress.files_scanned,
                "total_findings": total_findings,
                "findings_by_severity": findings_by_severity,
                "errors": progress.error_count,
            },
            "findings": [f.to_dict() for f in all_findings],
            "errors": [
                {"file": path, "error": error}
                for path, error in progress.errors
            ],
        }
        output_text = json.dumps(output_data, indent=2)
    else:
        output_lines.append(
            formatter.format_summary(
                progress.files_scanned,
                total_findings,
                findings_by_severity,
                progress.errors,
            )
        )
        output_text = "\n".join(output_lines)

    if args.output:
        Path(args.output).write_text(output_text)
        print(f"Results written to {args.output}")
    else:
        if output_text.strip():
            print(output_text)

    if args.exit_code == "never":
        return 0
    elif args.exit_code == "always":
        return 1 if total_findings > 0 else 0
    else:
        return 1 if total_findings > 0 else 0


def main(args: Optional[List[str]] = None) -> int:
    """Main entry point for the CLI."""
    parsed_args = parse_args(args)

    if parsed_args.list_patterns:
        list_patterns()
        return 0

    exclude_patterns = None
    if parsed_args.exclude_patterns:
        exclude_patterns = set(parsed_args.exclude_patterns.split(","))

    file_extensions = None
    if parsed_args.extensions:
        file_extensions = set(f".{ext.strip().lstrip('.')}" 
                             for ext in parsed_args.extensions.split(","))

    results, progress = scan_directory(
        path=parsed_args.path,
        severity=parsed_args.severity,
        exclude_patterns=exclude_patterns,
        file_extensions=file_extensions,
        scan_all_files=parsed_args.all_files,
        max_file_size=parsed_args.max_file_size,
    )

    return output_results(results, progress, parsed_args)


if __name__ == "__main__":
    sys.exit(main())

from __future__ import annotations

import argparse
import sys

from .report import to_json, to_markdown, write_if_requested
from .scanner import scan_repository


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="repo-audit",
        description="Analyze a repository and report language mix, large files, and possible secrets.",
    )
    parser.add_argument("path", nargs="?", default=".", help="Path to repository")
    parser.add_argument(
        "--large-file-mb",
        type=float,
        default=2.0,
        help="Large file threshold in MB (default: 2.0)",
    )
    parser.add_argument(
        "--max-text-scan-mb",
        type=float,
        default=1.0,
        help="Max file size in MB for secret text scan (default: 1.0)",
    )
    parser.add_argument(
        "--top-large-files",
        type=int,
        default=10,
        help="Number of largest files to include (default: 10)",
    )
    parser.add_argument("--json", dest="json_out", help="Write full JSON report to this path")
    parser.add_argument("--md", dest="md_out", help="Write markdown report to this path")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    try:
        report = scan_repository(
            args.path,
            large_file_threshold_bytes=max(int(args.large_file_mb * 1024 * 1024), 1),
            max_text_scan_bytes=max(int(args.max_text_scan_mb * 1024 * 1024), 1),
            top_large_files=max(args.top_large_files, 1),
        )
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print(
        f"Scanned {report.total_files} files ({report.total_bytes} bytes) in {report.root}",
        file=sys.stdout,
    )
    print(f"Secret findings: {len(report.secret_findings)}", file=sys.stdout)
    print("Top languages:", file=sys.stdout)
    top_languages = sorted(
        report.language_counts.items(), key=lambda item: item[1], reverse=True
    )[:5]
    for language, count in top_languages:
        print(f"  - {language}: {count}", file=sys.stdout)

    json_content = to_json(report)
    markdown_content = to_markdown(report)

    write_if_requested(args.json_out, json_content)
    write_if_requested(args.md_out, markdown_content)

    if not args.json_out and not args.md_out:
        print("\nJSON preview:")
        print(json_content[:1200])

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

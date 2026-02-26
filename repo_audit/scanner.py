from __future__ import annotations

import os
import re
from pathlib import Path

from .models import AuditReport, LargeFile, SecretFinding

DEFAULT_EXCLUDE_DIRS = {
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    "venv",
    ".venv",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    "dist",
    "build",
}

EXTENSION_LANGUAGE_MAP = {
    ".py": "Python",
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
    ".js": "JavaScript",
    ".jsx": "JavaScript",
    ".go": "Go",
    ".rs": "Rust",
    ".java": "Java",
    ".c": "C",
    ".h": "C/C++ Header",
    ".cpp": "C++",
    ".hpp": "C++ Header",
    ".sh": "Shell",
    ".yaml": "YAML",
    ".yml": "YAML",
    ".json": "JSON",
    ".md": "Markdown",
    ".sql": "SQL",
    ".html": "HTML",
    ".css": "CSS",
}

SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("AWS Access Key", re.compile(r"AKIA[0-9A-Z]{16}")),
    (
        "Private Key Header",
        re.compile(r"-----BEGIN (RSA|OPENSSH|EC|DSA) PRIVATE KEY-----"),
    ),
    (
        "Generic API Key Assignment",
        re.compile(r"(?i)(api[_-]?key|secret|token)\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,}['\"]"),
    ),
]


def _language_for_file(file_path: Path) -> str:
    ext = file_path.suffix.lower()
    if ext in EXTENSION_LANGUAGE_MAP:
        return EXTENSION_LANGUAGE_MAP[ext]
    if file_path.name == "Dockerfile":
        return "Dockerfile"
    if ext == "":
        return "No Extension"
    return f"Other ({ext})"


def _iter_files(root: Path, exclude_dirs: set[str]) -> list[Path]:
    files: list[Path] = []
    for current_root, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in exclude_dirs]
        current_root_path = Path(current_root)
        for name in filenames:
            files.append(current_root_path / name)
    return files


def _scan_text_file_for_secrets(
    path: Path,
    root: Path,
    max_text_scan_bytes: int,
) -> list[SecretFinding]:
    findings: list[SecretFinding] = []
    if path.stat().st_size > max_text_scan_bytes:
        return findings

    try:
        with path.open("r", encoding="utf-8", errors="ignore") as fh:
            for line_no, line in enumerate(fh, start=1):
                for rule_name, pattern in SECRET_PATTERNS:
                    if pattern.search(line):
                        findings.append(
                            SecretFinding(
                                rule=rule_name,
                                file=path.relative_to(root),
                                line=line_no,
                                snippet=line.strip()[:180],
                            )
                        )
    except OSError:
        return findings

    return findings


def scan_repository(
    root: str | Path,
    *,
    large_file_threshold_bytes: int = 2_000_000,
    max_text_scan_bytes: int = 1_000_000,
    exclude_dirs: set[str] | None = None,
    top_large_files: int = 10,
) -> AuditReport:
    root_path = Path(root).resolve()
    if not root_path.exists() or not root_path.is_dir():
        raise ValueError(f"root path must be an existing directory: {root_path}")

    excluded = exclude_dirs if exclude_dirs is not None else DEFAULT_EXCLUDE_DIRS
    report = AuditReport(root=root_path)

    for file_path in _iter_files(root_path, excluded):
        try:
            size = file_path.stat().st_size
        except OSError:
            continue

        report.total_files += 1
        report.total_bytes += size

        language = _language_for_file(file_path)
        report.language_counts[language] = report.language_counts.get(language, 0) + 1

        if size >= large_file_threshold_bytes:
            report.large_files.append(
                LargeFile(file=file_path.relative_to(root_path), bytes_size=size)
            )

        report.secret_findings.extend(
            _scan_text_file_for_secrets(file_path, root_path, max_text_scan_bytes)
        )

    report.large_files.sort(key=lambda item: item.bytes_size, reverse=True)
    report.large_files = report.large_files[:top_large_files]
    return report

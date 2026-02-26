# repo-audit

`repo-audit` analyzes source repositories and reports structure and secret-leak risk.
It now provides:

- Python CLI (`python3 -m repo_audit`)
- Go HTTP API (`cmd/api`)

## Features

- Language composition by file extension
- Largest files (configurable threshold)
- Secret-like pattern detection (AWS key, private key headers, generic API key/token assignments)
- JSON and Markdown report export
- No third-party dependencies (Python standard library only)

## Run API with Docker

```bash
docker compose up -d --build
curl -fsS http://127.0.0.1:8080/healthz
```

Create scan job:

```bash
curl -fsS -X POST http://127.0.0.1:8080/api/v1/scans \
  -H 'Content-Type: application/json' \
  -d '{"path":".","top_large_files":5}'
```

Get scan result:

```bash
curl -fsS http://127.0.0.1:8080/api/v1/scans/<job_id>
```

## Run

```bash
python3 -m repo_audit . --json out/report.json --md out/report.md
```

Or quick scan of current directory:

```bash
python3 -m repo_audit .
```

## CLI Options

- `--large-file-mb`: Threshold for large files (default `2.0`)
- `--max-text-scan-mb`: Max file size scanned as text for secrets (default `1.0`)
- `--top-large-files`: Number of largest files to include (default `10`)
- `--json`: Output path for JSON report
- `--md`: Output path for Markdown report

## Test

```bash
python3 -m unittest discover -s tests -v
```

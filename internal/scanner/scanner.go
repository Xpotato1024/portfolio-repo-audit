package scanner

import (
	"bufio"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

var (
	defaultExcludeDirs = map[string]struct{}{
		".git":          {},
		".hg":           {},
		".svn":          {},
		"node_modules":  {},
		"venv":          {},
		".venv":         {},
		"__pycache__":   {},
		".mypy_cache":   {},
		".pytest_cache": {},
		"dist":          {},
		"build":         {},
	}

	extLanguageMap = map[string]string{
		".py":   "Python",
		".ts":   "TypeScript",
		".tsx":  "TypeScript",
		".js":   "JavaScript",
		".jsx":  "JavaScript",
		".go":   "Go",
		".rs":   "Rust",
		".java": "Java",
		".c":    "C",
		".h":    "C/C++ Header",
		".cpp":  "C++",
		".hpp":  "C++ Header",
		".sh":   "Shell",
		".yaml": "YAML",
		".yml":  "YAML",
		".json": "JSON",
		".md":   "Markdown",
		".sql":  "SQL",
		".html": "HTML",
		".css":  "CSS",
	}

	secretPatterns = []struct {
		rule string
		re   *regexp.Regexp
	}{
		{rule: "AWS Access Key", re: regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
		{rule: "Private Key Header", re: regexp.MustCompile(`-----BEGIN (RSA|OPENSSH|EC|DSA) PRIVATE KEY-----`)},
		{rule: "Generic API Key Assignment", re: regexp.MustCompile(`(?i)(api[_-]?key|secret|token)\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,}['\"]`)},
	}
)

func defaultOptions() Options {
	return Options{
		LargeFileThresholdBytes: 2_000_000,
		MaxTextScanBytes:        1_000_000,
		TopLargeFiles:           10,
		ExcludeDirs:             defaultExcludeDirs,
	}
}

func languageForFile(path string) string {
	base := filepath.Base(path)
	ext := strings.ToLower(filepath.Ext(base))
	if lang, ok := extLanguageMap[ext]; ok {
		return lang
	}
	if base == "Dockerfile" {
		return "Dockerfile"
	}
	if ext == "" {
		return "No Extension"
	}
	return "Other (" + ext + ")"
}

func Scan(root string, opts Options) (AuditReport, error) {
	if root == "" {
		return AuditReport{}, errors.New("root path is required")
	}

	absRoot, err := filepath.Abs(root)
	if err != nil {
		return AuditReport{}, err
	}
	info, err := os.Stat(absRoot)
	if err != nil {
		return AuditReport{}, err
	}
	if !info.IsDir() {
		return AuditReport{}, errors.New("root path must be a directory")
	}

	if opts.LargeFileThresholdBytes <= 0 {
		opts.LargeFileThresholdBytes = 2_000_000
	}
	if opts.MaxTextScanBytes <= 0 {
		opts.MaxTextScanBytes = 1_000_000
	}
	if opts.TopLargeFiles <= 0 {
		opts.TopLargeFiles = 10
	}
	if len(opts.ExcludeDirs) == 0 {
		opts.ExcludeDirs = defaultExcludeDirs
	}

	report := AuditReport{
		Root:           absRoot,
		LanguageCounts: map[string]int{},
		LargeFiles:     []LargeFile{},
		SecretFindings: []SecretFinding{},
	}

	walkErr := filepath.WalkDir(absRoot, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil
		}

		if d.IsDir() {
			if path != absRoot {
				if _, skip := opts.ExcludeDirs[d.Name()]; skip {
					return fs.SkipDir
				}
			}
			return nil
		}

		fileInfo, err := d.Info()
		if err != nil {
			return nil
		}

		size := fileInfo.Size()
		report.TotalFiles++
		report.TotalBytes += size

		lang := languageForFile(path)
		report.LanguageCounts[lang]++

		relPath, err := filepath.Rel(absRoot, path)
		if err != nil {
			relPath = path
		}
		relPath = filepath.ToSlash(relPath)

		if size >= opts.LargeFileThresholdBytes {
			report.LargeFiles = append(report.LargeFiles, LargeFile{File: relPath, BytesSize: size})
		}

		if size <= opts.MaxTextScanBytes {
			report.SecretFindings = append(report.SecretFindings, scanFileForSecrets(path, relPath)...)
		}
		return nil
	})
	if walkErr != nil {
		return AuditReport{}, walkErr
	}

	sort.Slice(report.LargeFiles, func(i, j int) bool {
		return report.LargeFiles[i].BytesSize > report.LargeFiles[j].BytesSize
	})
	if len(report.LargeFiles) > opts.TopLargeFiles {
		report.LargeFiles = report.LargeFiles[:opts.TopLargeFiles]
	}

	return report, nil
}

func scanFileForSecrets(path, relPath string) []SecretFinding {
	findings := []SecretFinding{}
	f, err := os.Open(path)
	if err != nil {
		return findings
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := scanner.Text()
		for _, p := range secretPatterns {
			if p.re.MatchString(line) {
				snippet := strings.TrimSpace(line)
				if len(snippet) > 180 {
					snippet = snippet[:180]
				}
				findings = append(findings, SecretFinding{
					Rule:    p.rule,
					File:    relPath,
					Line:    lineNo,
					Snippet: snippet,
				})
			}
		}
	}

	return findings
}

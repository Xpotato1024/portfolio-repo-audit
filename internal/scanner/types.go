package scanner

type SecretFinding struct {
	Rule    string `json:"rule"`
	File    string `json:"file"`
	Line    int    `json:"line"`
	Snippet string `json:"snippet"`
}

type LargeFile struct {
	File      string `json:"file"`
	BytesSize int64  `json:"bytes_size"`
}

type AuditReport struct {
	Root           string            `json:"root"`
	TotalFiles     int               `json:"total_files"`
	TotalBytes     int64             `json:"total_bytes"`
	LanguageCounts map[string]int    `json:"language_counts"`
	LargeFiles     []LargeFile       `json:"large_files"`
	SecretFindings []SecretFinding   `json:"secret_findings"`
}

type Options struct {
	LargeFileThresholdBytes int64
	MaxTextScanBytes        int64
	TopLargeFiles           int
	ExcludeDirs             map[string]struct{}
}

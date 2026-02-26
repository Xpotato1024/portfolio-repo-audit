package scanner

import (
	"os"
	"path/filepath"
	"testing"
)

func TestScanCollectsMetrics(t *testing.T) {
	tmp := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmp, "main.go"), []byte("package main\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmp, "config.txt"), []byte("api_key=\"abcdefghijklmnop1234\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmp, "big.bin"), make([]byte, 3000), 0o644); err != nil {
		t.Fatal(err)
	}

	report, err := Scan(tmp, Options{LargeFileThresholdBytes: 2000, MaxTextScanBytes: 5000, TopLargeFiles: 10})
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
	if report.TotalFiles != 3 {
		t.Fatalf("unexpected TotalFiles: %d", report.TotalFiles)
	}
	if len(report.LargeFiles) != 1 {
		t.Fatalf("unexpected LargeFiles count: %d", len(report.LargeFiles))
	}
	if len(report.SecretFindings) != 1 {
		t.Fatalf("unexpected SecretFindings count: %d", len(report.SecretFindings))
	}
}

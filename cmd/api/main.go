package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Xpotato1024/repo-audit/internal/scanner"
)

type scanRequest struct {
	Path                    string `json:"path"`
	LargeFileThresholdBytes int64  `json:"large_file_threshold_bytes"`
	MaxTextScanBytes        int64  `json:"max_text_scan_bytes"`
	TopLargeFiles           int    `json:"top_large_files"`
}

type scanJob struct {
	ID         string               `json:"id"`
	Status     string               `json:"status"`
	CreatedAt  time.Time            `json:"created_at"`
	UpdatedAt  time.Time            `json:"updated_at"`
	Error      string               `json:"error,omitempty"`
	Report     *scanner.AuditReport `json:"report,omitempty"`
	Request    scanRequest          `json:"request"`
	ResolvedTo string               `json:"resolved_path,omitempty"`
}

type jobStore struct {
	mu   sync.RWMutex
	jobs map[string]*scanJob
}

func newJobStore() *jobStore {
	return &jobStore{jobs: map[string]*scanJob{}}
}

func (s *jobStore) set(job *scanJob) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.jobs[job.ID] = job
}

func (s *jobStore) get(id string) (*scanJob, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	job, ok := s.jobs[id]
	if !ok {
		return nil, false
	}
	clone := *job
	if job.Report != nil {
		reportClone := *job.Report
		clone.Report = &reportClone
	}
	return &clone, true
}

func main() {
	port := getenv("PORT", "8080")
	baseRoot := getenv("SCAN_BASE_ROOT", ".")
	baseAbs, err := filepath.Abs(baseRoot)
	if err != nil {
		log.Fatalf("failed to resolve SCAN_BASE_ROOT: %v", err)
	}

	store := newJobStore()
	mux := http.NewServeMux()

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		respondJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	mux.HandleFunc("/api/v1/scans", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			respondError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}

		var req scanRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil && err != io.EOF {
			respondError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}

		jobID := randomID(8)
		now := time.Now().UTC()
		job := &scanJob{
			ID:        jobID,
			Status:    "running",
			CreatedAt: now,
			UpdatedAt: now,
			Request:   req,
		}
		store.set(job)

		go func(id string, request scanRequest) {
			targetPath := request.Path
			if strings.TrimSpace(targetPath) == "" {
				targetPath = baseAbs
			}

			resolvedPath, err := resolvePathWithinBase(baseAbs, targetPath)
			if err != nil {
				markJobFailed(store, id, err)
				return
			}

			report, err := scanner.Scan(resolvedPath, scanner.Options{
				LargeFileThresholdBytes: request.LargeFileThresholdBytes,
				MaxTextScanBytes:        request.MaxTextScanBytes,
				TopLargeFiles:           request.TopLargeFiles,
			})
			if err != nil {
				markJobFailed(store, id, err)
				return
			}

			store.mu.Lock()
			defer store.mu.Unlock()
			j := store.jobs[id]
			j.Status = "completed"
			j.UpdatedAt = time.Now().UTC()
			j.ResolvedTo = resolvedPath
			j.Report = &report
		}(jobID, req)

		respondJSON(w, http.StatusAccepted, map[string]string{
			"id":     jobID,
			"status": "running",
		})
	})

	mux.HandleFunc("/api/v1/scans/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			respondError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}

		id := strings.TrimPrefix(r.URL.Path, "/api/v1/scans/")
		if id == "" || strings.Contains(id, "/") {
			respondError(w, http.StatusBadRequest, "invalid scan id")
			return
		}

		job, ok := store.get(id)
		if !ok {
			respondError(w, http.StatusNotFound, "scan job not found")
			return
		}
		respondJSON(w, http.StatusOK, job)
	})

	addr := ":" + port
	log.Printf("repo-audit API listening on %s (SCAN_BASE_ROOT=%s)", addr, baseAbs)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatal(err)
	}
}

func markJobFailed(store *jobStore, id string, err error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	j := store.jobs[id]
	j.Status = "failed"
	j.Error = err.Error()
	j.UpdatedAt = time.Now().UTC()
}

func resolvePathWithinBase(baseAbs, target string) (string, error) {
	if !filepath.IsAbs(target) {
		target = filepath.Join(baseAbs, target)
	}
	resolved, err := filepath.Abs(target)
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(baseAbs, resolved)
	if err != nil {
		return "", err
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return "", errors.New("requested path is outside SCAN_BASE_ROOT")
	}
	return resolved, nil
}

func randomID(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return time.Now().UTC().Format("20060102150405")
	}
	return hex.EncodeToString(b)
}

func respondJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("response encode error: %v", err)
	}
}

func respondError(w http.ResponseWriter, status int, msg string) {
	respondJSON(w, status, map[string]string{"error": msg})
}

func getenv(key, fallback string) string {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	return v
}

package auditlog

import (
	"bufio"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type Writer struct {
	path     string
	maxSize  int64
	rotate   bool
	compress bool

	maxBackups int
	maxAgeDays int

	mu       sync.Mutex
	file     *os.File
	buffered *bufio.Writer
}

func NewWriter(path string, maxSizeMB int, rotate bool, maxBackups int, maxAgeDays int, compress bool) (*Writer, error) {
	if maxSizeMB <= 0 {
		maxSizeMB = 100
	}
	if maxBackups < 0 {
		maxBackups = 0
	}
	if maxAgeDays < 0 {
		maxAgeDays = 0
	}
	w := &Writer{
		path:       path,
		maxSize:    int64(maxSizeMB) * 1024 * 1024,
		rotate:     rotate,
		compress:   compress,
		maxBackups: maxBackups,
		maxAgeDays: maxAgeDays,
	}
	if err := w.open(); err != nil {
		return nil, err
	}
	return w, nil
}

func (w *Writer) open() error {
	if err := os.MkdirAll(filepath.Dir(w.path), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(w.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	w.file = f
	w.buffered = bufio.NewWriterSize(f, 64*1024)
	return nil
}

func (w *Writer) Write(event any) error {
	if w == nil {
		return nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.rotateIfNeeded(); err != nil {
		return err
	}
	raw, err := json.Marshal(event)
	if err != nil {
		return err
	}
	if _, err := w.buffered.Write(raw); err != nil {
		return err
	}
	if err := w.buffered.WriteByte('\n'); err != nil {
		return err
	}
	return w.buffered.Flush()
}

func (w *Writer) Path() string {
	if w == nil {
		return ""
	}
	return w.path
}

func (w *Writer) Close() error {
	if w == nil {
		return nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.buffered != nil {
		_ = w.buffered.Flush()
	}
	if w.file != nil {
		return w.file.Close()
	}
	return nil
}

func (w *Writer) rotateIfNeeded() error {
	if !w.rotate || w.file == nil {
		return nil
	}
	fi, err := w.file.Stat()
	if err != nil {
		return err
	}
	if fi.Size() < w.maxSize {
		return nil
	}
	if err := w.buffered.Flush(); err != nil {
		return err
	}
	if err := w.file.Close(); err != nil {
		return err
	}
	rotated := fmt.Sprintf("%s.%s", w.path, time.Now().UTC().Format("20060102T150405"))
	if err := os.Rename(w.path, rotated); err != nil {
		return err
	}
	if w.compress {
		compressed, err := compressFile(rotated)
		if err != nil {
			return err
		}
		rotated = compressed
	}
	if err := w.cleanupRotatedFiles(rotated); err != nil {
		return err
	}
	return w.open()
}

func (w *Writer) cleanupRotatedFiles(latest string) error {
	if w.maxBackups <= 0 && w.maxAgeDays <= 0 {
		return nil
	}
	pattern := w.path + ".*"
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return err
	}
	type fileInfo struct {
		path    string
		modTime time.Time
	}
	entries := make([]fileInfo, 0, len(matches))
	for _, match := range matches {
		if match == w.path {
			continue
		}
		fi, err := os.Stat(match)
		if err != nil {
			continue
		}
		if fi.IsDir() {
			continue
		}
		entries = append(entries, fileInfo{path: match, modTime: fi.ModTime()})
	}

	if w.maxAgeDays > 0 {
		cutoff := time.Now().UTC().Add(-time.Duration(w.maxAgeDays) * 24 * time.Hour)
		for _, entry := range entries {
			if entry.path == latest {
				continue
			}
			if entry.modTime.Before(cutoff) {
				_ = os.Remove(entry.path)
			}
		}
		entries = entries[:0]
		for _, match := range matches {
			if match == w.path {
				continue
			}
			fi, err := os.Stat(match)
			if err != nil || fi.IsDir() {
				continue
			}
			entries = append(entries, fileInfo{path: match, modTime: fi.ModTime()})
		}
	}

	if w.maxBackups > 0 {
		sort.Slice(entries, func(i, j int) bool {
			if entries[i].modTime.Equal(entries[j].modTime) {
				return strings.Compare(entries[i].path, entries[j].path) > 0
			}
			return entries[i].modTime.After(entries[j].modTime)
		})
		for i := w.maxBackups; i < len(entries); i++ {
			_ = os.Remove(entries[i].path)
		}
	}
	return nil
}

func compressFile(path string) (string, error) {
	in, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer in.Close()
	outPath := path + ".gz"
	out, err := os.OpenFile(outPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return "", err
	}
	gz := gzip.NewWriter(out)
	if _, err := io.Copy(gz, in); err != nil {
		_ = gz.Close()
		_ = out.Close()
		return "", err
	}
	if err := gz.Close(); err != nil {
		_ = out.Close()
		return "", err
	}
	if err := out.Close(); err != nil {
		return "", err
	}
	if err := os.Remove(path); err != nil {
		return "", err
	}
	return outPath, nil
}

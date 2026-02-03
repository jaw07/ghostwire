package logging

import (
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// RotatorConfig configures log rotation
type RotatorConfig struct {
	MaxSize  int64         // Maximum file size before rotation
	MaxAge   time.Duration // Maximum age of log files
	MaxFiles int           // Maximum number of old log files to keep
	Compress bool          // Compress rotated files
}

// DefaultRotatorConfig returns sensible defaults
func DefaultRotatorConfig() *RotatorConfig {
	return &RotatorConfig{
		MaxSize:  10 * 1024 * 1024, // 10MB
		MaxAge:   7 * 24 * time.Hour,
		MaxFiles: 10,
		Compress: true,
	}
}

// Rotator handles log file rotation
type Rotator struct {
	config *RotatorConfig
}

// NewRotator creates a new log rotator
func NewRotator(config *RotatorConfig) *Rotator {
	if config == nil {
		config = DefaultRotatorConfig()
	}
	return &Rotator{config: config}
}

// ShouldRotate returns true if the current file should be rotated
func (r *Rotator) ShouldRotate(currentSize int64) bool {
	return r.config.MaxSize > 0 && currentSize >= r.config.MaxSize
}

// Rotate rotates the log file
func (r *Rotator) Rotate(filename string) error {
	// Generate rotated filename with timestamp
	dir := filepath.Dir(filename)
	base := filepath.Base(filename)
	ext := filepath.Ext(base)
	name := strings.TrimSuffix(base, ext)

	timestamp := time.Now().UTC().Format("20060102-150405")
	rotatedName := fmt.Sprintf("%s.%s%s", name, timestamp, ext)
	rotatedPath := filepath.Join(dir, rotatedName)

	// Rename current file
	if err := os.Rename(filename, rotatedPath); err != nil {
		return fmt.Errorf("rename log file: %w", err)
	}

	// Compress if configured
	if r.config.Compress {
		if err := r.compress(rotatedPath); err != nil {
			// Non-fatal, log file is still rotated
			return nil
		}
	}

	// Clean up old files
	return r.cleanup(dir, name, ext)
}

// compress gzips the rotated file
func (r *Rotator) compress(filename string) error {
	src, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer src.Close()

	dst, err := os.Create(filename + ".gz")
	if err != nil {
		return err
	}
	defer dst.Close()

	gz := gzip.NewWriter(dst)
	gz.Name = filepath.Base(filename)
	gz.ModTime = time.Now()

	if _, err := io.Copy(gz, src); err != nil {
		return err
	}
	if err := gz.Close(); err != nil {
		return err
	}

	// Remove uncompressed file
	return os.Remove(filename)
}

// cleanup removes old log files
func (r *Rotator) cleanup(dir, name, ext string) error {
	pattern := filepath.Join(dir, name+".*"+ext+"*")
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return err
	}

	// Sort by modification time (newest first)
	type fileInfo struct {
		path    string
		modTime time.Time
	}
	files := make([]fileInfo, 0, len(matches))
	for _, match := range matches {
		// Skip the current log file
		if !strings.Contains(match, ".") {
			continue
		}
		info, err := os.Stat(match)
		if err != nil {
			continue
		}
		files = append(files, fileInfo{path: match, modTime: info.ModTime()})
	}

	sort.Slice(files, func(i, j int) bool {
		return files[i].modTime.After(files[j].modTime)
	})

	// Remove files exceeding MaxFiles count
	for i := r.config.MaxFiles; i < len(files); i++ {
		os.Remove(files[i].path)
	}

	// Remove files older than MaxAge
	if r.config.MaxAge > 0 {
		cutoff := time.Now().Add(-r.config.MaxAge)
		for _, f := range files {
			if f.modTime.Before(cutoff) {
				os.Remove(f.path)
			}
		}
	}

	return nil
}

// ListLogFiles returns all log files in the directory
func ListLogFiles(dir string) ([]LogFile, error) {
	pattern := filepath.Join(dir, "ghostwire-*.log*")
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return nil, err
	}

	files := make([]LogFile, 0, len(matches))
	for _, path := range matches {
		info, err := os.Stat(path)
		if err != nil {
			continue
		}
		files = append(files, LogFile{
			Path:       path,
			Size:       info.Size(),
			ModTime:    info.ModTime(),
			Compressed: strings.HasSuffix(path, ".gz"),
		})
	}

	// Sort by modification time (newest first)
	sort.Slice(files, func(i, j int) bool {
		return files[i].ModTime.After(files[j].ModTime)
	})

	return files, nil
}

// LogFile represents a log file on disk
type LogFile struct {
	Path       string
	Size       int64
	ModTime    time.Time
	Compressed bool
}

// SecureDelete overwrites and removes a log file
func SecureDelete(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}

	// Open file for writing
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}

	// Overwrite with zeros
	zeros := make([]byte, 4096)
	remaining := info.Size()
	for remaining > 0 {
		toWrite := int64(len(zeros))
		if remaining < toWrite {
			toWrite = remaining
		}
		n, err := f.Write(zeros[:toWrite])
		if err != nil {
			f.Close()
			return err
		}
		remaining -= int64(n)
	}

	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	f.Close()

	// Remove file
	return os.Remove(path)
}

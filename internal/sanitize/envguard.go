package sanitize

import (
	"bufio"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

var ignoredEnvValues = map[string]struct{}{
	"example":  {},
	"changeme": {},
	"test":     {},
}

func DiscoverEnvSecrets(startDir string, patterns []string, maxFileKB int) (map[string]string, error) {
	if maxFileKB <= 0 {
		maxFileKB = 256
	}
	if startDir == "" {
		startDir = "."
	}
	abs, err := filepath.Abs(startDir)
	if err != nil {
		return nil, err
	}
	searchDirs := ancestorDirs(abs)
	files := make([]string, 0)
	for _, dir := range searchDirs {
		for _, p := range patterns {
			matches, err := filepath.Glob(filepath.Join(dir, p))
			if err != nil {
				continue
			}
			files = append(files, matches...)
		}
	}
	secrets := map[string]string{}
	for _, file := range files {
		if err := loadEnvFile(file, maxFileKB, secrets); err != nil && !errors.Is(err, os.ErrNotExist) {
			continue
		}
	}
	return secrets, nil
}

func ancestorDirs(dir string) []string {
	out := []string{dir}
	for {
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		out = append(out, parent)
		dir = parent
	}
	return out
}

func loadEnvFile(path string, maxFileKB int, out map[string]string) error {
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	if fi.IsDir() || fi.Size() > int64(maxFileKB)*1024 {
		return nil
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		v = strings.Trim(v, `"'`)
		if len(v) < 8 {
			continue
		}
		if _, skip := ignoredEnvValues[strings.ToLower(v)]; skip {
			continue
		}
		out[k] = v
	}
	return scanner.Err()
}

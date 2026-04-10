package auditlog

import (
	"bufio"
	"errors"
	"io"
	"os"
	"regexp"
	"time"
)

func Tail(path string, follow bool, emit func(string)) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	reader := bufio.NewReader(f)
	for {
		line, err := reader.ReadString('\n')
		if line != "" {
			emit(line)
		}
		if err == nil {
			continue
		}
		if errors.Is(err, io.EOF) {
			if !follow {
				return nil
			}
			time.Sleep(250 * time.Millisecond)
			continue
		}
		return err
	}
}

func Grep(path, pattern string, emit func(string)) error {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return err
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	s := bufio.NewScanner(f)
	for s.Scan() {
		line := s.Text()
		if re.MatchString(line) {
			emit(line + "\n")
		}
	}
	return s.Err()
}

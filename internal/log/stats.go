package auditlog

import (
	"bufio"
	"encoding/json"
	"os"
	"sort"
	"strings"
)

type Stats struct {
	Requests   int
	Allowed    int
	Blocked    int
	Sanitized  int
	Errors     int
	TopHosts   map[string]int
	TopBlocked map[string]int
}

func ComputeStats(path string) (Stats, error) {
	f, err := os.Open(path)
	if err != nil {
		return Stats{}, err
	}
	defer f.Close()

	st := Stats{TopHosts: map[string]int{}, TopBlocked: map[string]int{}}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		var row map[string]any
		if err := json.Unmarshal(scanner.Bytes(), &row); err != nil {
			st.Errors++
			continue
		}
		action, _ := row["action"].(string)
		direction, _ := row["direction"].(string)
		isResponse := strings.EqualFold(direction, "response")
		host, _ := row["host"].(string)
		if host != "" {
			st.TopHosts[host]++
		}
		switch action {
		case "allow", "pass":
			st.Allowed++
			if !isResponse {
				st.Requests++
			}
		case "block":
			st.Blocked++
			if !isResponse {
				st.Requests++
			}
			if host != "" {
				st.TopBlocked[host]++
			}
		case "clean", "r_clean":
			st.Sanitized++
			if !isResponse {
				st.Requests++
			}
		case "error":
			st.Errors++
		}
	}
	return st, scanner.Err()
}

type HostCount struct {
	Host  string
	Count int
}

func TopN(m map[string]int, n int) []HostCount {
	out := make([]HostCount, 0, len(m))
	for host, count := range m {
		out = append(out, HostCount{Host: host, Count: count})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count == out[j].Count {
			return out[i].Host < out[j].Host
		}
		return out[i].Count > out[j].Count
	})
	if n > 0 && len(out) > n {
		out = out[:n]
	}
	return out
}

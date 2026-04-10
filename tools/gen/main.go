package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"gopkg.in/yaml.v3"
)

type secretFile struct {
	Sanitizers []struct {
		ID             string `yaml:"id"`
		Pattern        string `yaml:"pattern"`
		Replacement    string `yaml:"replacement"`
		HighConfidence bool   `yaml:"high_confidence"`
	} `yaml:"sanitizers"`
}

func main() {
	root := flag.String("root", ".", "repo root")
	flag.Parse()

	if err := genRules(*root); err != nil {
		panic(err)
	}
	if err := genSanitizers(*root); err != nil {
		panic(err)
	}
	fmt.Println("generated builtin files")
}

func genRules(root string) error {
	telemetry, err := readStringList(filepath.Join(root, "data", "telemetry_endpoints.yaml"))
	if err != nil {
		return err
	}
	strict, err := readStringList(filepath.Join(root, "data", "strict_allowlist.yaml"))
	if err != nil {
		return err
	}
	sort.Strings(telemetry)
	sort.Strings(strict)
	var buf bytes.Buffer
	buf.WriteString("package rules\n\n")
	buf.WriteString("var BuiltinTelemetryBlocklist = []string{\n")
	for _, v := range telemetry {
		buf.WriteString(fmt.Sprintf("\t%q,\n", v))
	}
	buf.WriteString("}\n\n")
	buf.WriteString("var BuiltinStrictAllowlist = []string{\n")
	for _, v := range strict {
		buf.WriteString(fmt.Sprintf("\t%q,\n", v))
	}
	buf.WriteString("}\n")
	return os.WriteFile(filepath.Join(root, "internal", "rules", "builtin.go"), buf.Bytes(), 0o644)
}

func genSanitizers(root string) error {
	raw, err := os.ReadFile(filepath.Join(root, "data", "secret_patterns.yaml"))
	if err != nil {
		return err
	}
	var f secretFile
	if err := yaml.Unmarshal(raw, &f); err != nil {
		return err
	}
	var buf bytes.Buffer
	buf.WriteString("package sanitize\n\n")
	buf.WriteString("var BuiltinPatterns = []PatternDef{\n")
	for _, s := range f.Sanitizers {
		buf.WriteString(fmt.Sprintf("\t{ID: %q, Pattern: %q, Replacement: %q, HighConfidence: %t},\n", s.ID, s.Pattern, s.Replacement, s.HighConfidence))
	}
	buf.WriteString("}\n\n")
	buf.WriteString("var TrustedLLMHosts = map[string]struct{}{\n")
	buf.WriteString("\t\"api.anthropic.com\": {},\n")
	buf.WriteString("\t\"api.openai.com\": {},\n")
	buf.WriteString("\t\"generativelanguage.googleapis.com\": {},\n")
	buf.WriteString("\t\"api.x.ai\": {},\n")
	buf.WriteString("\t\"api.deepseek.com\": {},\n")
	buf.WriteString("\t\"api.mistral.ai\": {},\n")
	buf.WriteString("\t\"api.groq.com\": {},\n")
	buf.WriteString("\t\"openrouter.ai\": {},\n")
	buf.WriteString("}\n")
	return os.WriteFile(filepath.Join(root, "internal", "sanitize", "builtin.go"), buf.Bytes(), 0o644)
}

func readStringList(path string) ([]string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var values []string
	if err := yaml.Unmarshal(raw, &values); err != nil {
		return nil, err
	}
	return values, nil
}

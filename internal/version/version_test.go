package version

import "testing"

func TestFullIncludesFields(t *testing.T) {
	m := Full()
	if m["version"] == "" || m["go"] == "" {
		t.Fatalf("missing fields in version metadata")
	}
}

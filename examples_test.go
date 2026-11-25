package main

import (
	"log/slog"
	"path/filepath"
	"testing"
)

// Every shipped example and Lab candidate parses through the same path the
// CLI uses, and only the deliberately broken toFQDNs example warns.
func TestExamplesParse(t *testing.T) {
	files, _ := filepath.Glob("examples/*.yaml")
	labs, _ := filepath.Glob("lab/candidates/*.yaml")
	fqdn, _ := filepath.Glob("lab/fqdn/fqdn-client-example-*.yaml")
	zt, _ := filepath.Glob("lab/zero-trust/0*.yaml")
	files = append(append(append(files, labs...), fqdn...), zt...)
	if len(files) == 0 {
		t.Fatal("no examples found")
	}
	for _, f := range files {
		docs, _, _, err := loadCandidateDocs(slog.Default(), []string{f}, nil, "")
		if err != nil {
			t.Errorf("%s: %v", f, err)
			continue
		}
		warns := candidateWarnings(flattenCandidateRules(docs))
		if wantWarn := filepath.Base(f) == "webapp-fqdn-without-dns-rule.yaml"; (len(warns) > 0) != wantWarn {
			t.Errorf("%s: warnings %v, want a toFQDNs warning: %v", f, warns, wantWarn)
		}
	}
}

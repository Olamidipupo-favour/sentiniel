package sentiniel

import (
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"regexp"
	"strings"
)

var suspiciousJS = regexp.MustCompile(`(?i)(?:child_process|execSync|spawnSync|require\s*\(|process\.env|eval\s*\(|new\s+Function\s*\(|https?://|Buffer\.from)`)

// HeuristicStrategy reports large api.js files with execution and network indicators. It is
// advisory and has no Fixer, so apply mode never touches what it finds.
type HeuristicStrategy struct{}

func (HeuristicStrategy) Name() string { return "heuristic" }

func (HeuristicStrategy) Candidate(path string) bool { return filepath.Base(path) == "api.js" }

func (HeuristicStrategy) Match(file File) (Finding, bool) {
	if filepath.Base(file.Path) != "api.js" || len(file.Data) < 20000 || !suspiciousJS.Match(file.Data) {
		return Finding{}, false
	}
	text := string(file.Data)
	if !strings.Contains(text, "eval") && !strings.Contains(text, "child_process") {
		return Finding{}, false
	}
	sum := sha256.Sum256(file.Data)
	return Finding{Path: file.Path, Strategy: "heuristic", Severity: "MEDIUM", Reasons: []string{"large api.js contains execution/network indicators and possible obfuscation; manual review required"}, SHA256: hex.EncodeToString(sum[:]), Action: "do not execute; inspect statically and review provenance before changing it"}, true
}

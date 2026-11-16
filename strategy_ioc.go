package sentiniel

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"strings"
)

const (
	KnownPayloadName = "fa-brand-400.orc"
	KnownPayloadPath = "backend/app/routers/public/fonts/fa-brand-400.orc"
	KnownPayloadSHA  = "af747d14f1303252002c14f82ed3c14f1da79e4d8396999b79b26ac135a0c5af"
	// KnownPayloadSHA2 was recovered from the worm commit that rewrote Sentiniel's own history.
	KnownPayloadSHA2 = "e20dc2838008cbcc0205d5a992cb3eb11a705d90fcd95582618c91c224b72549"
)

// fontHeaders lists the magic bytes each font format starts with.
var fontHeaders = map[string][][]byte{
	".ttf":   {[]byte{0, 1, 0, 0}, []byte("true"), []byte("ttcf")},
	".otf":   {[]byte("OTTO")},
	".woff":  {[]byte("wOFF")},
	".woff2": {[]byte("wOF2")},
}

// fontHeaderValid reports whether a file with a font extension really starts like one. The worm
// renamed its JavaScript payload to .ttf, so a mismatched header is the signal, not the name.
func fontHeaderValid(path string, data []byte) bool {
	headers, ok := fontHeaders[strings.ToLower(filepath.Ext(path))]
	if !ok {
		return true
	}
	for _, header := range headers {
		if bytes.HasPrefix(data, header) {
			return true
		}
	}
	return false
}

// IOCStrategy reports confirmed indicators: known payload names and hashes, and files that claim a
// font extension without a font header.
type IOCStrategy struct{}

func (IOCStrategy) Name() string { return "ioc" }

func (IOCStrategy) Candidate(path string) bool {
	base := filepath.Base(path)
	if base == KnownPayloadName {
		return true
	}
	_, isFont := fontHeaders[strings.ToLower(filepath.Ext(base))]
	return isFont
}

func (IOCStrategy) Match(file File) (Finding, bool) {
	sum := sha256.Sum256(file.Data)
	hash := hex.EncodeToString(sum[:])
	slashPath := filepath.ToSlash(file.Path)
	if hash == KnownPayloadSHA || hash == KnownPayloadSHA2 || filepath.Base(slashPath) == KnownPayloadName {
		reasons := []string{"known payload filename"}
		if hash == KnownPayloadSHA || hash == KnownPayloadSHA2 {
			reasons = append(reasons, "matches known payload SHA-256")
		}
		return Finding{Path: file.Path, Strategy: "ioc", Severity: "HIGH", Reasons: reasons, SHA256: hash, Action: "preserve evidence, quarantine the file, rotate credentials if it may have executed"}, true
	}
	if !fontHeaderValid(slashPath, file.Data) {
		return Finding{Path: file.Path, Strategy: "ioc", Severity: "HIGH", Reasons: []string{"font extension but no font header; likely a renamed script"}, SHA256: hash, Action: "preserve evidence, quarantine the file, do not execute it"}, true
	}
	return Finding{}, false
}

func (IOCStrategy) Fix(path string, data []byte) ([]byte, bool, string) {
	// Older findings plans recorded workspace files as IOC findings. Never delete them here.
	switch filepath.ToSlash(path) {
	case ".vscode/tasks.json", ".vscode/settings.json":
		return data, false, "workspace file from an older findings plan; rescan before applying"
	}
	return nil, true, "removed suspicious file"
}

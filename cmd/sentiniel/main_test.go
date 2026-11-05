package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"strings"
	"testing"

	"github.com/Olamidipupo-favour/sentiniel"
)

func TestRemediationRoot(t *testing.T) {
	clone := "/tmp/clones/owner__repo"
	if got := remediationRoot(sentiniel.Finding{Repository: "owner/repo", Local: clone}, ""); got != clone {
		t.Fatalf("cloned finding root = %q, want %q", got, clone)
	}
	if got := remediationRoot(sentiniel.Finding{Repository: "owner/repo"}, "/repo"); got != "/repo" {
		t.Fatalf("remote finding root = %q, want /repo", got)
	}
	if got := remediationRoot(sentiniel.Finding{Repository: "owner/repo"}, ""); got != "" {
		t.Fatalf("remote finding without --path root = %q, want empty", got)
	}
}

func TestParseSelection(t *testing.T) {
	cases := []struct {
		input string
		count int
		want  []int
		ok    bool
	}{
		{"", 3, []int{0, 1, 2}, true},
		{"all", 2, []int{0, 1}, true},
		{"1,3", 3, []int{0, 2}, true},
		{"2,2", 3, []int{1}, true},
		{"0", 3, nil, false},
		{"4", 3, nil, false},
		{"x", 3, nil, false},
		{",", 3, nil, false},
	}
	for _, tc := range cases {
		got, err := parseSelection(tc.input, tc.count)
		if (err == nil) != tc.ok {
			t.Fatalf("parseSelection(%q, %d) error = %v, want ok=%v", tc.input, tc.count, err, tc.ok)
		}
		if len(got) != len(tc.want) {
			t.Fatalf("parseSelection(%q, %d) = %v, want %v", tc.input, tc.count, got, tc.want)
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Fatalf("parseSelection(%q, %d) = %v, want %v", tc.input, tc.count, got, tc.want)
			}
		}
	}
}

func TestPickAsset(t *testing.T) {
	assets := []sentiniel.ReleaseAsset{
		{Name: "checksums.txt", URL: "c"},
		{Name: "sentiniel_0.4.0_linux_amd64.tar.gz", URL: "linux"},
		{Name: "sentiniel_0.4.0_darwin_arm64.tar.gz", URL: "mac"},
		{Name: "sentiniel_0.4.0_windows_amd64.zip", URL: "win"},
	}
	cases := []struct{ goos, goarch, name, url string }{
		{"linux", "amd64", "sentiniel_0.4.0_linux_amd64.tar.gz", "linux"},
		{"darwin", "arm64", "sentiniel_0.4.0_darwin_arm64.tar.gz", "mac"},
		{"windows", "amd64", "sentiniel_0.4.0_windows_amd64.zip", "win"},
		{"linux", "riscv64", "", ""},
		{"plan9", "amd64", "", ""},
	}
	for _, tc := range cases {
		name, url := pickAsset(assets, "0.4.0", tc.goos, tc.goarch)
		if name != tc.name || url != tc.url {
			t.Fatalf("pickAsset(%s/%s) = %q %q, want %q %q", tc.goos, tc.goarch, name, url, tc.name, tc.url)
		}
	}
	if name, _ := pickAsset(assets, "0.3.0", "linux", "amd64"); name != "" {
		t.Fatalf("pickAsset accepted the wrong version: %q", name)
	}
}

func TestChecksumFor(t *testing.T) {
	sum := strings.Repeat("a", 64)
	text := "1111111111111111111111111111111111111111111111111111111111111111  sentiniel_0.4.0_darwin_amd64.tar.gz\n" +
		sum + "  sentiniel_0.4.0_linux_amd64.tar.gz\n"
	got, ok := checksumFor(text, "sentiniel_0.4.0_linux_amd64.tar.gz")
	if !ok || got != sum {
		t.Fatalf("checksumFor = %q, %v", got, ok)
	}
	if _, ok := checksumFor(text, "sentiniel_0.4.0_windows_amd64.zip"); ok {
		t.Fatal("checksumFor matched a missing file")
	}
}

func TestBinaryFromTarGz(t *testing.T) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	payload := []byte("binary-bytes")
	if err := tw.WriteHeader(&tar.Header{Name: "sentiniel", Mode: 0755, Size: int64(len(payload))}); err != nil {
		t.Fatal(err)
	}
	tw.Write(payload)
	tw.Close()
	gz.Close()

	got, err := binaryFrom("sentiniel_0.4.0_linux_amd64.tar.gz", buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(payload) {
		t.Fatalf("binaryFrom = %q", got)
	}
	if _, err := binaryFrom("broken.tar.gz", []byte("not a gzip stream")); err == nil {
		t.Fatal("binaryFrom accepted a corrupt archive")
	}
}

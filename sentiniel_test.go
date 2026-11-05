package sentiniel

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestIOCDetectsFolderOpenPayloadTask(t *testing.T) {
	scanner, err := NewScanner([]string{"ioc"})
	if err != nil {
		t.Fatal(err)
	}
	files := []File{{Path: ".vscode/tasks.json", Data: []byte(`{"tasks":[{"command":"node ./backend/app/routers/public/fonts/fa-brand-400.orc","runOptions":{"runOn":"folderOpen"}}]}`)}}
	findings := scanner.Scan(files, "repo")
	if len(findings) != 1 || findings[0].Severity != "HIGH" {
		t.Fatalf("unexpected findings: %#v", findings)
	}
}

func TestDryRunDoesNotChangeLocalFiles(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, ".vscode", "tasks.json")
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	original := []byte(`{"tasks":[{"command":"node ./backend/app/routers/public/fonts/fa-brand-400.orc","runOptions":{"runOn":"folderOpen"}}]}`)
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	target := LocalTarget{Root: root}
	files, err := target.Files()
	if err != nil {
		t.Fatal(err)
	}
	scanner, _ := NewScanner([]string{"ioc"})
	findings := scanner.Scan(files, root)
	if _, err := target.Remediate(findings[0], DryRun); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(path)
	if string(got) != string(original) {
		t.Fatal("dry-run changed the task file")
	}
}

func TestApplyQuarantinesPayloadAndTask(t *testing.T) {
	root := t.TempDir()
	taskPath := filepath.Join(root, ".vscode", "tasks.json")
	payloadPath := filepath.Join(root, KnownPayloadPath)
	if err := os.MkdirAll(filepath.Dir(taskPath), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(payloadPath), 0700); err != nil {
		t.Fatal(err)
	}
	task := []byte(`{"tasks":[{"command":"node ./backend/app/routers/public/fonts/fa-brand-400.orc","runOptions":{"runOn":"folderOpen"}},{"label":"safe","command":"go test"}]}`)
	if err := os.WriteFile(taskPath, task, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(payloadPath, []byte("payload"), 0600); err != nil {
		t.Fatal(err)
	}
	target := LocalTarget{Root: root}
	files, _ := target.Files()
	scanner, _ := NewScanner([]string{"ioc"})
	for _, finding := range scanner.Scan(files, root) {
		if _, err := target.Remediate(finding, Apply); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := os.Stat(filepath.Join(root, ".sentiniel-quarantine", KnownPayloadPath)); err != nil {
		t.Fatal(err)
	}
	updated, _ := os.ReadFile(taskPath)
	if strings.Contains(string(updated), KnownPayloadPath) {
		t.Fatal("malicious task remained after apply")
	}
}

func TestLocalTargetSkipsExcludedPaths(t *testing.T) {
	root := t.TempDir()
	task := []byte(`{"tasks":[{"command":"node ./payload.orc","runOptions":{"runOn":"folderOpen"}}]}`)
	for _, rel := range []string{".vscode/tasks.json", "fixtures/infected/.vscode/tasks.json"} {
		path := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, task, 0600); err != nil {
			t.Fatal(err)
		}
	}
	files, err := (LocalTarget{Root: root, Excludes: []string{"fixtures/infected"}}).Files()
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 || files[0].Path != ".vscode/tasks.json" {
		t.Fatalf("unexpected files: %#v", files)
	}
}

func TestStoredTokenRoundTrip(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("GH_TOKEN", "")
	if err := SaveToken("  token-value  "); err != nil {
		t.Fatal(err)
	}
	got, err := LoadToken()
	if err != nil {
		t.Fatal(err)
	}
	if got != "token-value" {
		t.Fatalf("LoadToken() = %q", got)
	}
	if err := RemoveToken(); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadToken(); err == nil {
		t.Fatal("token still present after RemoveToken")
	}
}

func TestUnknownStrategyFails(t *testing.T) {
	if _, err := NewScanner([]string{"fuzzing"}); err == nil {
		t.Fatal("expected unknown strategy error")
	}
}

func FuzzDecodeGitHubContent(f *testing.F) {
	f.Add("aGVsbG8=")
	f.Add("eyJ0YXNrcyI6W119")
	f.Fuzz(func(t *testing.T, input string) {
		_, _ = decodeGitHubContent(input)
	})
}

func TestDecodeGitHubContentUsesStandardBase64(t *testing.T) {
	got, err := decodeGitHubContent("aGVs\nbG8=")
	if err != nil || string(got) != "hello" {
		t.Fatalf("got %q, err %v", got, err)
	}
}

// fakeGitHub answers API calls in memory so remote remediation can be tested without network access.
const (
	testPutSHA    = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	testDeleteSHA = "dddddddddddddddddddddddddddddddddddddddd"
)

type fakeGitHub struct {
	files    map[string][]byte
	sha      map[string]string
	requests []string
	deleted  string
	written  map[string][]byte
}

func (f *fakeGitHub) RoundTrip(req *http.Request) (*http.Response, error) {
	f.requests = append(f.requests, req.Method+" "+req.URL.Path)
	if req.URL.Path == "/repos/o/r" {
		return jsonResponse(`{"default_branch":"main"}`), nil
	}
	path := strings.TrimPrefix(req.URL.Path, "/repos/o/r/contents/")
	switch req.Method {
	case http.MethodGet:
		data, ok := f.files[path]
		if !ok {
			return jsonStatus(http.StatusNotFound, `{"message":"Not Found"}`), nil
		}
		return jsonResponse(`{"sha":"` + f.sha[path] + `","size":` + strconv.Itoa(len(data)) + `,"content":"` + base64.StdEncoding.EncodeToString(data) + `"}`), nil
	case http.MethodPut:
		var body struct {
			Content string `json:"content"`
			Message string `json:"message"`
		}
		json.NewDecoder(req.Body).Decode(&body)
		data, _ := base64.StdEncoding.DecodeString(body.Content)
		if f.written == nil {
			f.written = map[string][]byte{}
		}
		f.written[path] = data
		return jsonResponse(`{"commit":{"sha":"` + testPutSHA + `"}}`), nil
	case http.MethodDelete:
		f.deleted = path
		return jsonResponse(`{"commit":{"sha":"` + testDeleteSHA + `"}}`), nil
	}
	return nil, fmt.Errorf("unexpected request %s %s", req.Method, req.URL.Path)
}

func jsonResponse(body string) *http.Response {
	return jsonStatus(http.StatusOK, body)
}

func jsonStatus(code int, body string) *http.Response {
	return &http.Response{StatusCode: code, Body: io.NopCloser(strings.NewReader(body)), Header: http.Header{}}
}

func TestRemoteRemediateDeletesPayloadAndPreservesOriginal(t *testing.T) {
	payload := []byte("obfuscated payload")
	fake := &fakeGitHub{
		files: map[string][]byte{KnownPayloadPath: payload},
		sha:   map[string]string{KnownPayloadPath: "blob-sha"},
	}
	target := GitHubTarget{Client: &GitHubClient{Token: "t", HTTP: &http.Client{Transport: fake}}, Repo: "o/r"}
	message, err := target.Remediate(Finding{Repository: "o/r", Path: KnownPayloadPath, Strategy: "ioc"}, Apply)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(message, testDeleteSHA[:7]) {
		t.Fatalf("message = %q, want the commit SHA", message)
	}
	if fake.deleted != KnownPayloadPath {
		t.Fatalf("deleted %q, want %q", fake.deleted, KnownPayloadPath)
	}
	if got := fake.written[".sentiniel-quarantine/"+KnownPayloadPath]; string(got) != string(payload) {
		t.Fatalf("quarantine copy = %q, want the original payload", got)
	}
}

func TestRemoteRemediateStripsFolderOpenTask(t *testing.T) {
	task := `{"version":"2.0.0","tasks":[` +
		`{"label":"sync","command":"git fetch"},` +
		`{"label":"fonts","command":"node ./` + KnownPayloadPath + `","runOptions":{"runOn":"folderOpen"}}]}`
	fake := &fakeGitHub{
		files: map[string][]byte{".vscode/tasks.json": []byte(task)},
		sha:   map[string]string{".vscode/tasks.json": "task-sha"},
	}
	target := GitHubTarget{Client: &GitHubClient{Token: "t", HTTP: &http.Client{Transport: fake}}, Repo: "o/r"}
	if _, err := target.Remediate(Finding{Repository: "o/r", Path: ".vscode/tasks.json", Strategy: "ioc"}, Apply); err != nil {
		t.Fatal(err)
	}
	written := string(fake.written[".vscode/tasks.json"])
	if strings.Contains(written, "folderOpen") || strings.Contains(written, KnownPayloadPath) {
		t.Fatalf("task file still has the payload task: %s", written)
	}
	if !strings.Contains(written, "git fetch") {
		t.Fatalf("task file lost an unrelated task: %s", written)
	}
	if fake.deleted != "" {
		t.Fatalf("task remediation deleted %q instead of updating it", fake.deleted)
	}
}

func TestRemoteRemediateRequiresApplyAndIOC(t *testing.T) {
	fake := &fakeGitHub{}
	target := GitHubTarget{Client: &GitHubClient{Token: "t", HTTP: &http.Client{Transport: fake}}, Repo: "o/r"}
	message, err := target.Remediate(Finding{Repository: "o/r", Path: KnownPayloadPath, Strategy: "ioc"}, DryRun)
	if err != nil || !strings.Contains(message, "dry-run") {
		t.Fatalf("dry-run = %q, %v", message, err)
	}
	message, err = target.Remediate(Finding{Repository: "o/r", Path: "api.js", Strategy: "heuristic"}, Apply)
	if err != nil || !strings.Contains(message, "manual remediation") {
		t.Fatalf("heuristic = %q, %v", message, err)
	}
	if len(fake.requests) != 0 {
		t.Fatalf("dry-run made %d API requests: %v", len(fake.requests), fake.requests)
	}
}

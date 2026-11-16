package sentiniel

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestWorkspaceDetectsFolderOpenPayloadTask(t *testing.T) {
	scanner, err := NewScanner([]string{"workspace"})
	if err != nil {
		t.Fatal(err)
	}
	files := []File{{Path: ".vscode/tasks.json", Data: []byte(`{"tasks":[{"command":"node ./backend/app/routers/public/fonts/fa-brand-400.orc","runOptions":{"runOn":"folderOpen"}}]}`)}}
	findings := scanner.Scan(files, "repo")
	if len(findings) != 1 || findings[0].Severity != "HIGH" {
		t.Fatalf("unexpected findings: %#v", findings)
	}
}

func TestWorkspaceDetectsPayloadInTaskArgs(t *testing.T) {
	scanner, _ := NewScanner([]string{"workspace"})
	files := []File{{Path: ".vscode/tasks.json", Data: []byte(`{"tasks":[{"label":"eslint-check","command":"node","args":["./fixtures/infected/backend/app/routers/public/fonts/fa-solid-600.ttf"],"hide":true,"runOptions":{"runOn":"folderOpen"}}]}`)}}
	if findings := scanner.Scan(files, "repo"); len(findings) != 1 || findings[0].Severity != "HIGH" {
		t.Fatalf("unexpected findings: %#v", findings)
	}
}

func TestWorkspaceDetectsAutomaticTasksSetting(t *testing.T) {
	scanner, _ := NewScanner([]string{"workspace"})
	files := []File{{Path: ".vscode/settings.json", Data: []byte(`{"editor.formatOnSave":true,"task.allowAutomaticTasks":true}`)}}
	findings := scanner.Scan(files, "repo")
	if len(findings) != 1 || findings[0].Severity != "HIGH" {
		t.Fatalf("unexpected findings: %#v", findings)
	}
}

func TestWorkspaceDetectsUnparseableFolderOpenTask(t *testing.T) {
	scanner, _ := NewScanner([]string{"workspace"})
	// VS Code accepts comments in tasks.json; encoding/json does not.
	files := []File{{Path: ".vscode/tasks.json", Data: []byte("{\n // build\n \"tasks\":[{\"command\":\"node ./x.orc\",\"runOptions\":{\"runOn\":\"folderOpen\"}}]\n}")}}
	if findings := scanner.Scan(files, "repo"); len(findings) != 1 {
		t.Fatalf("unexpected findings: %#v", findings)
	}
}

func TestIOCDetectsRenamedFontPayload(t *testing.T) {
	scanner, _ := NewScanner([]string{"ioc"})
	files := []File{{Path: "public/fonts/fa-solid-600.ttf", Data: []byte(`(function(){require("child_process").execSync("id")})`)}}
	if findings := scanner.Scan(files, "repo"); len(findings) != 1 {
		t.Fatalf("unexpected findings: %#v", findings)
	}
	realFont := append([]byte{0, 1, 0, 0}, make([]byte, 64)...)
	files = []File{{Path: "public/fonts/fa-solid-600.ttf", Data: realFont}}
	if findings := scanner.Scan(files, "repo"); len(findings) != 0 {
		t.Fatalf("real font flagged: %#v", findings)
	}
}

func TestApplyDisablesAutomaticTasks(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, ".vscode", "settings.json")
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	original := []byte(`{"editor.formatOnSave":true,"task.allowAutomaticTasks":true}`)
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	target := LocalTarget{Root: root}
	files, err := target.Files(nil)
	if err != nil {
		t.Fatal(err)
	}
	scanner, _ := NewScanner([]string{"workspace"})
	findings := scanner.Scan(files, root)
	if len(findings) != 1 {
		t.Fatalf("unexpected findings: %#v", findings)
	}
	if _, err := target.Remediate(findings[0], Apply); err != nil {
		t.Fatal(err)
	}
	updated, _ := os.ReadFile(path)
	if automaticTasksEnabled(updated) || !strings.Contains(string(updated), "editor.formatOnSave") {
		t.Fatalf("settings not fixed in place: %s", updated)
	}
	if _, err := os.Stat(filepath.Join(root, ".sentiniel-quarantine", ".vscode", "settings.json")); err != nil {
		t.Fatal(err)
	}
}

func TestGitHubTargetUsesRequestedBranch(t *testing.T) {
	fake := &fakeGitHub{files: map[string][]byte{".vscode/tasks.json": []byte(`{"tasks":[]}`)}}
	client := &GitHubClient{Token: "t", HTTP: &http.Client{Transport: fake}}
	branches, err := client.Branches("o/r")
	if err != nil || len(branches) != 2 {
		t.Fatalf("Branches() = %v, %v", branches, err)
	}
	if _, err := (GitHubTarget{Client: client, Repo: "o/r", Branch: "develop"}).Files(nil); err != nil {
		t.Fatal(err)
	}
	for _, request := range fake.requests {
		if request == "GET /repos/o/r" {
			t.Fatal("scanned the default branch when a branch was requested")
		}
	}
	if !strings.Contains(strings.Join(fake.requests, "\n"), "/git/trees/develop") {
		t.Fatalf("develop tree not requested: %v", fake.requests)
	}
}

func TestGitHubFilesSkipsQuarantineAndExcludedPaths(t *testing.T) {
	task := []byte(`{"tasks":[{"command":"node ./.x.orc","runOptions":{"runOn":"folderOpen"}}]}`)
	fake := &fakeGitHub{files: map[string][]byte{
		".vscode/tasks.json": task,
		".sentiniel-quarantine/backend/app/routers/public/fonts/fa-brand-400.orc": []byte("payload"),
		"fixtures/infected/backend/app/routers/public/fonts/fa-solid-600.ttf":     []byte("payload"),
	}}
	target := GitHubTarget{Client: &GitHubClient{Token: "t", HTTP: &http.Client{Transport: fake}}, Repo: "o/r", Excludes: []string{"fixtures/infected"}}
	files, err := target.Files(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 || files[0].Path != ".vscode/tasks.json" {
		t.Fatalf("unexpected files: %#v", files)
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
	files, err := target.Files(nil)
	if err != nil {
		t.Fatal(err)
	}
	scanner, _ := NewScanner([]string{"workspace"})
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
	files, _ := target.Files(nil)
	scanner, _ := NewScanner([]string{"all"})
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
	files, err := (LocalTarget{Root: root, Excludes: []string{"fixtures/infected"}}).Files(nil)
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
	if strings.HasPrefix(req.URL.Path, "/repos/o/r/branches") {
		return jsonResponse(`[{"name":"main"},{"name":"develop"}]`), nil
	}
	if strings.HasPrefix(req.URL.Path, "/repos/o/r/git/trees/") {
		var entries []string
		for path := range f.files {
			entries = append(entries, `{"path":"`+path+`","type":"blob","url":"https://api.github.com/repos/o/r/git/blobs/`+path+`"}`)
		}
		return jsonResponse(`{"tree":[` + strings.Join(entries, ",") + `]}`), nil
	}
	if strings.HasPrefix(req.URL.Path, "/repos/o/r/git/blobs/") {
		return jsonResponse(`{"content":"` + base64.StdEncoding.EncodeToString(f.files[strings.TrimPrefix(req.URL.Path, "/repos/o/r/git/blobs/")]) + `"}`), nil
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
	if _, err := target.Remediate(Finding{Repository: "o/r", Path: ".vscode/tasks.json", Strategy: "workspace"}, Apply); err != nil {
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

func TestRemoteRemediateRequiresApplyAndFixer(t *testing.T) {
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

func TestScannerCandidateSelection(t *testing.T) {
	workspace, _ := NewScanner([]string{"workspace"})
	if !workspace.Candidate(".vscode/tasks.json") || workspace.Candidate("README.md") {
		t.Fatal("workspace candidate selection is wrong")
	}
	ioc, _ := NewScanner([]string{"ioc"})
	if !ioc.Candidate("public/fonts/fa-solid-600.ttf") || ioc.Candidate("README.md") {
		t.Fatal("ioc candidate selection is wrong")
	}
	heuristic, _ := NewScanner([]string{"heuristic"})
	if !heuristic.Candidate("src/api.js") || heuristic.Candidate(".vscode/tasks.json") {
		t.Fatal("heuristic candidate selection is wrong")
	}
}

func TestTransientReadErrorsAreRetried(t *testing.T) {
	if !transient(&url.Error{Op: "Get", URL: "https://api.github.com/x", Err: timeoutError{}}) {
		t.Fatal("timeout should be retried")
	}
	if !transient(errors.New("GitHub API 502 Bad Gateway: bad gateway")) {
		t.Fatal("5xx should be retried")
	}
	if transient(errors.New("GitHub API 404 Not Found: Not Found")) {
		t.Fatal("got a client error; found should not be retried")
	}
}

type timeoutError struct{}

func (timeoutError) Error() string   { return "timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

func TestLatestReleaseIncludesChangelog(t *testing.T) {
	fake := &releaseGitHub{body: `{"tag_name":"v1.2.3","body":"## Changelog\n* fix the thing","assets":[{"name":"checksums.txt","browser_download_url":"https://example.com/checksums.txt"}]}`}
	client := &GitHubClient{Token: "t", HTTP: &http.Client{Transport: fake}}
	release, err := client.LatestRelease()
	if err != nil {
		t.Fatal(err)
	}
	if release.Tag != "v1.2.3" || !strings.Contains(release.Notes, "fix the thing") {
		t.Fatalf("unexpected release: %#v", release)
	}
	if len(release.Assets) != 1 || release.Assets[0].Name != "checksums.txt" {
		t.Fatalf("unexpected assets: %#v", release.Assets)
	}
}

type releaseGitHub struct{ body string }

func (f *releaseGitHub) RoundTrip(*http.Request) (*http.Response, error) {
	return jsonResponse(f.body), nil
}

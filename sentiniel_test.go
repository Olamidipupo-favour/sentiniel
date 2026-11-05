package sentiniel

import (
	"os"
	"path/filepath"
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

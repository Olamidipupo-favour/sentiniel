package sentiniel

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	KnownPayloadName = "fa-brand-400.orc"
	KnownPayloadPath = "backend/app/routers/public/fonts/fa-brand-400.orc"
	KnownPayloadSHA  = "af747d14f1303252002c14f82ed3c14f1da79e4d8396999b79b26ac135a0c5af"
	// KnownPayloadSHA2 was recovered from the worm commit that rewrote Sentiniel's own history.
	KnownPayloadSHA2 = "e20dc2838008cbcc0205d5a992cb3eb11a705d90fcd95582618c91c224b72549"
)

type Mode string

const (
	DryRun Mode = "dry-run"
	Apply  Mode = "apply"
)

type Finding struct {
	Repository string   `json:"repository"`
	Local      string   `json:"local,omitempty"`
	Path       string   `json:"path"`
	Strategy   string   `json:"strategy"`
	Severity   string   `json:"severity"`
	Reasons    []string `json:"reasons"`
	SHA256     string   `json:"sha256,omitempty"`
	Action     string   `json:"action"`
}

type File struct {
	Path string
	Data []byte
}

type Strategy interface {
	Name() string
	Match(File) (Finding, bool)
}

type Scanner struct {
	Strategies []Strategy
}

func NewScanner(names []string) (*Scanner, error) {
	available := map[string]Strategy{"ioc": IOCStrategy{}, "heuristic": HeuristicStrategy{}}
	if len(names) == 0 || contains(names, "all") {
		names = []string{"ioc", "heuristic"}
	}
	var selected []Strategy
	for _, name := range names {
		strategy, ok := available[name]
		if !ok {
			return nil, fmt.Errorf("unknown strategy %q (available: ioc, heuristic, all)", name)
		}
		selected = append(selected, strategy)
	}
	return &Scanner{Strategies: selected}, nil
}

func (s *Scanner) Scan(files []File, repository string) []Finding {
	var findings []Finding
	for _, file := range files {
		for _, strategy := range s.Strategies {
			if finding, ok := strategy.Match(file); ok {
				finding.Repository = repository
				findings = append(findings, finding)
			}
		}
	}
	sort.Slice(findings, func(i, j int) bool {
		return findings[i].Repository+"/"+findings[i].Path < findings[j].Repository+"/"+findings[j].Path
	})
	return findings
}

type TaskFile struct {
	Version string `json:"version"`
	Tasks   []Task `json:"tasks"`
}

type Task struct {
	Label      string   `json:"label"`
	Command    string   `json:"command"`
	Args       []string `json:"args"`
	Hide       bool     `json:"hide"`
	RunOptions struct {
		RunOn string `json:"runOn"`
	} `json:"runOptions"`
}

var (
	taskInterpreter = regexp.MustCompile(`(?i)^(?:node|nodejs|npx|deno|bun|python[0-9.]*|py|pwsh|powershell|cmd|bash|sh)$`)
	disguisedScript = regexp.MustCompile(`(?i)\.(?:orc|ttf|otf|woff2?)$`)
	automaticTasks  = regexp.MustCompile(`"task\.allowAutomaticTasks"\s*:\s*true`)
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

// taskIsMalicious flags a task that hands a non-script file to an interpreter, or a hidden
// folder-open task. The worm puts the payload in args, so command alone is not enough.
// shortcut: only flags interpreter-plus-known-extension or a hidden folder-open task; a renamed
// payload with a novel extension still needs hash or header detection.
func taskIsMalicious(task Task) bool {
	words := append(strings.Fields(task.Command), task.Args...)
	for _, word := range words {
		word = strings.ReplaceAll(word, "\\", "/")
		if strings.Contains(word, KnownPayloadPath) || filepath.Base(word) == KnownPayloadName {
			return true
		}
	}
	if task.RunOptions.RunOn != "folderOpen" {
		return false
	}
	for _, word := range words {
		if task.Hide && taskInterpreter.MatchString(filepath.Base(strings.Trim(word, `"'()`))) {
			return true
		}
	}
	for i, word := range words {
		if !disguisedScript.MatchString(word) {
			continue
		}
		for _, previous := range words[:i] {
			if taskInterpreter.MatchString(filepath.Base(strings.Trim(previous, `"'()`))) {
				return true
			}
		}
	}
	return false
}

// decodeTaskFile tolerates the UTF-8 BOM the worm writes in front of tasks.json.
func decodeTaskFile(data []byte) (TaskFile, error) {
	var tasks TaskFile
	err := json.Unmarshal(bytes.TrimPrefix(data, []byte("\xef\xbb\xbf")), &tasks)
	return tasks, err
}

// maliciousTasks returns the tasks a .vscode/tasks.json file must lose.
func maliciousTasks(data []byte) []Task {
	tasks, err := decodeTaskFile(data)
	if err != nil {
		return nil
	}
	var bad []Task
	for _, task := range tasks.Tasks {
		if taskIsMalicious(task) {
			bad = append(bad, task)
		}
	}
	return bad
}

func withoutMaliciousTasks(tasks TaskFile) TaskFile {
	filtered := tasks.Tasks[:0]
	for _, task := range tasks.Tasks {
		if !taskIsMalicious(task) {
			filtered = append(filtered, task)
		}
	}
	tasks.Tasks = filtered
	return tasks
}

func automaticTasksEnabled(data []byte) bool { return automaticTasks.Match(data) }

func disableAutomaticTasks(data []byte) []byte {
	return automaticTasks.ReplaceAll(data, []byte(`"task.allowAutomaticTasks": false`))
}

// scannable reports whether a path is worth downloading: the workspace files, known payload names,
// api.js, and any file claiming to be a font (headers are checked after download).
func scannable(path string) bool {
	if path == ".vscode/tasks.json" || path == ".vscode/settings.json" {
		return true
	}
	base := filepath.Base(path)
	if base == KnownPayloadName || base == "api.js" {
		return true
	}
	_, isFont := fontHeaders[strings.ToLower(filepath.Ext(base))]
	return isFont
}

func excludedPath(excludes []string, path string) bool {
	path = filepath.ToSlash(path)
	for _, excluded := range excludes {
		excluded = strings.Trim(strings.ReplaceAll(excluded, "\\", "/"), "/")
		if excluded != "" && (path == excluded || strings.HasPrefix(path, excluded+"/")) {
			return true
		}
	}
	return false
}

type IOCStrategy struct{}

func (IOCStrategy) Name() string { return "ioc" }

func (IOCStrategy) Match(file File) (Finding, bool) {
	slashPath := filepath.ToSlash(file.Path)
	if slashPath == ".vscode/tasks.json" {
		if len(maliciousTasks(file.Data)) > 0 {
			return Finding{Path: file.Path, Strategy: "ioc", Severity: "HIGH", Reasons: []string{"folder-open task executes a disguised script payload"}, Action: "remove the task only after preserving the original and reviewing the repository"}, true
		}
		return Finding{}, false
	}
	sum := sha256.Sum256(file.Data)
	hash := hex.EncodeToString(sum[:])
	if slashPath == ".vscode/settings.json" {
		if !automaticTasksEnabled(file.Data) {
			return Finding{}, false
		}
		return Finding{Path: file.Path, Strategy: "ioc", Severity: "HIGH", Reasons: []string{"workspace enables automatic tasks, so a folder-open task runs without confirmation"}, SHA256: hash, Action: "set task.allowAutomaticTasks to false and review .vscode/tasks.json"}, true
	}
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

var suspiciousJS = regexp.MustCompile(`(?i)(?:child_process|execSync|spawnSync|require\s*\(|process\.env|eval\s*\(|new\s+Function\s*\(|https?://|Buffer\.from)`)

type HeuristicStrategy struct{}

func (HeuristicStrategy) Name() string { return "heuristic" }

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

type LocalTarget struct {
	Root     string
	Excludes []string
}

func (t LocalTarget) Files() ([]File, error) {
	info, err := os.Stat(t.Root)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, errors.New("local target must be a directory")
	}
	var files []File
	err = filepath.Walk(t.Root, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if info.IsDir() {
			if info.Name() == ".git" || info.Name() == "machoka" || strings.HasPrefix(info.Name(), ".sentiniel-quarantine") {
				return filepath.SkipDir
			}
			return nil
		}
		rel, err := filepath.Rel(t.Root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if excludedPath(t.Excludes, rel) {
			return nil
		}
		if scannable(rel) {
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			files = append(files, File{Path: rel, Data: data})
		}
		return nil
	})
	return files, err
}

func (t LocalTarget) Remediate(f Finding, mode Mode) (string, error) {
	if mode == DryRun {
		return "dry-run: no files changed", nil
	}
	if f.Strategy != "ioc" {
		return "manual remediation required for advisory finding; no files changed", nil
	}
	if excludedPath(t.Excludes, f.Path) {
		return "skipped: path is excluded", nil
	}
	source := filepath.Join(t.Root, filepath.FromSlash(f.Path))
	quarantine := filepath.Join(t.Root, ".sentiniel-quarantine", filepath.FromSlash(f.Path))
	if err := os.MkdirAll(filepath.Dir(quarantine), 0700); err != nil {
		return "", err
	}
	data, err := os.ReadFile(source)
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(quarantine, data, 0600); err != nil {
		return "", err
	}
	if f.Path == ".vscode/tasks.json" {
		tasks, err := decodeTaskFile(data)
		if err != nil {
			return "", err
		}
		tasks = withoutMaliciousTasks(tasks)
		out, err := json.MarshalIndent(tasks, "", "  ")
		if err != nil {
			return "", err
		}
		if err := os.WriteFile(source, append(out, '\n'), 0600); err != nil {
			return "", err
		}
		return "removed malicious folder-open task; original saved in .sentiniel-quarantine", nil
	}
	if f.Path == ".vscode/settings.json" {
		updated := disableAutomaticTasks(data)
		if bytes.Equal(updated, data) {
			return "no automatic-task setting found; no files changed", nil
		}
		if err := os.WriteFile(source, updated, 0600); err != nil {
			return "", err
		}
		return "disabled automatic workspace tasks; original saved in .sentiniel-quarantine", nil
	}
	if err := os.Remove(source); err != nil {
		return "", err
	}
	return "removed suspicious file; original saved in .sentiniel-quarantine", nil
}

type GitHubTarget struct {
	Client   *GitHubClient
	Repo     string
	Excludes []string
}

type GitHubClient struct {
	Token string
	HTTP  *http.Client
}

// TokenPath is where `sentiniel login` stores a token without relying on gh.
func TokenPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "sentiniel", "token"), nil
}

func LoadToken() (string, error) {
	path, err := TokenPath()
	if err != nil {
		return "", err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

func SaveToken(token string) error {
	path, err := TokenPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(strings.TrimSpace(token)+"\n"), 0600)
}

func RemoveToken() error {
	path, err := TokenPath()
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func NewGitHubClient(token string) (*GitHubClient, error) {
	candidates := []string{token, os.Getenv("GITHUB_TOKEN"), os.Getenv("GH_TOKEN")}
	if stored, err := LoadToken(); err == nil {
		candidates = append(candidates, stored)
	}
	for _, candidate := range candidates {
		if candidate = strings.TrimSpace(candidate); candidate != "" {
			return &GitHubClient{Token: candidate, HTTP: &http.Client{Timeout: 15 * time.Second}}, nil
		}
	}
	// Legacy fallback: reuse an existing gh session when present.
	if path, err := exec.LookPath("gh"); err == nil {
		if out, err := exec.Command(path, "auth", "token").Output(); err == nil {
			if token = strings.TrimSpace(string(out)); token != "" {
				return &GitHubClient{Token: token, HTTP: &http.Client{Timeout: 15 * time.Second}}, nil
			}
		}
	}
	return nil, errors.New("no GitHub token: run `sentiniel login`, set GITHUB_TOKEN/GH_TOKEN, or authenticate with gh")
}

func (c *GitHubClient) User() (string, error) {
	var user struct {
		Login string `json:"login"`
	}
	if err := c.get("https://api.github.com/user", &user); err != nil {
		return "", err
	}
	return user.Login, nil
}

func (c *GitHubClient) Organizations() ([]string, error) {
	var orgs []struct {
		Login string `json:"login"`
	}
	if err := c.get("https://api.github.com/user/orgs?per_page=100", &orgs); err != nil {
		return nil, err
	}
	names := make([]string, 0, len(orgs))
	for _, org := range orgs {
		names = append(names, org.Login)
	}
	return names, nil
}

func (c *GitHubClient) get(url string, target any) error {
	return c.do(http.MethodGet, url, nil, target)
}

// do performs an authenticated API call. The response body is read for the API message on failure.
func (c *GitHubClient) do(method, url string, body, target any) error {
	var payload io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return err
		}
		payload = bytes.NewReader(data)
	}
	req, err := http.NewRequest(method, url, payload)
	if err != nil {
		return err
	}
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode >= 300 {
		var apiErr struct {
			Message string `json:"message"`
		}
		json.NewDecoder(io.LimitReader(res.Body, 2048)).Decode(&apiErr)
		if apiErr.Message != "" {
			return fmt.Errorf("GitHub API %s: %s", res.Status, apiErr.Message)
		}
		return fmt.Errorf("GitHub API %s: %s", res.Status, url)
	}
	if target == nil {
		return nil
	}
	return json.NewDecoder(res.Body).Decode(target)
}

// ReleaseAsset is one downloadable file attached to a release.
type ReleaseAsset struct {
	Name string
	URL  string
}

// LatestRelease reports the newest published tag and its assets. It works without a token.
func (c *GitHubClient) LatestRelease() (string, []ReleaseAsset, error) {
	var rel struct {
		TagName string `json:"tag_name"`
		Assets  []struct {
			Name string `json:"name"`
			URL  string `json:"browser_download_url"`
		} `json:"assets"`
	}
	if err := c.get("https://api.github.com/repos/Olamidipupo-favour/sentiniel/releases/latest", &rel); err != nil {
		return "", nil, err
	}
	assets := make([]ReleaseAsset, 0, len(rel.Assets))
	for _, asset := range rel.Assets {
		assets = append(assets, ReleaseAsset{Name: asset.Name, URL: asset.URL})
	}
	return rel.TagName, assets, nil
}

func (c *GitHubClient) DefaultBranch(repo string) (string, error) {
	var info struct {
		DefaultBranch string `json:"default_branch"`
	}
	if err := c.get("https://api.github.com/repos/"+repo, &info); err != nil {
		return "", err
	}
	if info.DefaultBranch == "" {
		return "", errors.New("repository has no default branch")
	}
	return info.DefaultBranch, nil
}

type remoteFile struct {
	SHA  string
	Data []byte
}

func escapePath(path string) string {
	parts := strings.Split(path, "/")
	for i, part := range parts {
		parts[i] = url.PathEscape(part)
	}
	return strings.Join(parts, "/")
}

func (c *GitHubClient) file(repo, path, branch string) (remoteFile, error) {
	var out struct {
		SHA     string `json:"sha"`
		Content string `json:"content"`
		Size    int    `json:"size"`
	}
	u := fmt.Sprintf("https://api.github.com/repos/%s/contents/%s?ref=%s", repo, escapePath(path), url.QueryEscape(branch))
	if err := c.get(u, &out); err != nil {
		return remoteFile{}, err
	}
	if out.Content == "" && out.Size > 0 {
		return remoteFile{}, fmt.Errorf("%s is too large for the contents API", path)
	}
	data, err := decodeGitHubContent(out.Content)
	if err != nil {
		return remoteFile{}, err
	}
	return remoteFile{SHA: out.SHA, Data: data}, nil
}

// putFile writes a file and returns the commit SHA. A non-empty sha updates an existing blob.
func (c *GitHubClient) putFile(repo, path, branch, message string, data []byte, sha string) (string, error) {
	body := map[string]string{
		"message": message,
		"content": base64.StdEncoding.EncodeToString(data),
		"branch":  branch,
	}
	if sha != "" {
		body["sha"] = sha
	}
	var out struct {
		Commit struct {
			SHA string `json:"sha"`
		} `json:"commit"`
	}
	u := fmt.Sprintf("https://api.github.com/repos/%s/contents/%s", repo, escapePath(path))
	if err := c.do(http.MethodPut, u, body, &out); err != nil {
		return "", err
	}
	return out.Commit.SHA, nil
}

func (c *GitHubClient) deleteFile(repo, path, branch, message, sha string) (string, error) {
	var out struct {
		Commit struct {
			SHA string `json:"sha"`
		} `json:"commit"`
	}
	body := map[string]string{"message": message, "branch": branch, "sha": sha}
	u := fmt.Sprintf("https://api.github.com/repos/%s/contents/%s", repo, escapePath(path))
	if err := c.do(http.MethodDelete, u, body, &out); err != nil {
		return "", err
	}
	return out.Commit.SHA, nil
}

// Remediate fixes a finding directly on the remote default branch. It is only called after explicit
// user confirmation, keeps a copy under .sentiniel-quarantine, and never touches advisory findings.
func (t GitHubTarget) Remediate(f Finding, mode Mode) (string, error) {
	if mode == DryRun {
		return "dry-run: no remote changes", nil
	}
	if f.Strategy != "ioc" {
		return "manual remediation required for advisory finding; no remote changes", nil
	}
	if excludedPath(t.Excludes, f.Path) {
		return "skipped: path is excluded", nil
	}
	branch, err := t.Client.DefaultBranch(t.Repo)
	if err != nil {
		return "", err
	}
	original, err := t.Client.file(t.Repo, f.Path, branch)
	if err != nil {
		return "", err
	}
	quarantine := ".sentiniel-quarantine/" + f.Path
	if _, err := t.Client.file(t.Repo, quarantine, branch); err != nil {
		if _, err := t.Client.putFile(t.Repo, quarantine, branch, "sentiniel: preserve "+f.Path, original.Data, ""); err != nil {
			return "", fmt.Errorf("preserve original: %w", err)
		}
	}
	if f.Path == ".vscode/tasks.json" {
		tasks, err := decodeTaskFile(original.Data)
		if err != nil {
			return "", err
		}
		tasks = withoutMaliciousTasks(tasks)
		out, err := json.MarshalIndent(tasks, "", "  ")
		if err != nil {
			return "", err
		}
		sha, err := t.Client.putFile(t.Repo, f.Path, branch, "sentiniel: remove folder-open payload task", append(out, '\n'), original.SHA)
		if err != nil {
			return "", err
		}
		return "removed remote folder-open task; original preserved in .sentiniel-quarantine (commit " + shortSHA(sha) + ")", nil
	}
	if f.Path == ".vscode/settings.json" {
		updated := disableAutomaticTasks(original.Data)
		if bytes.Equal(updated, original.Data) {
			return "no automatic-task setting found; no remote changes", nil
		}
		sha, err := t.Client.putFile(t.Repo, f.Path, branch, "sentiniel: disable automatic workspace tasks", updated, original.SHA)
		if err != nil {
			return "", err
		}
		return "disabled remote automatic tasks; original preserved in .sentiniel-quarantine (commit " + shortSHA(sha) + ")", nil
	}
	sha, err := t.Client.deleteFile(t.Repo, f.Path, branch, "sentiniel: remove known payload file", original.SHA)
	if err != nil {
		return "", err
	}
	return "removed remote suspicious file; original preserved in .sentiniel-quarantine (commit " + shortSHA(sha) + ")", nil
}

func shortSHA(sha string) string {
	if len(sha) > 7 {
		return sha[:7]
	}
	return sha
}

func (c *GitHubClient) Repositories(owner string) ([]string, error) {
	seen := map[string]bool{}
	var names []string
	add := func(url string) error {
		for page := 1; ; page++ {
			var repos []struct {
				FullName string `json:"full_name"`
			}
			pageURL := fmt.Sprintf("%s&per_page=100&page=%d", url, page)
			if err := c.get(pageURL, &repos); err != nil {
				return err
			}
			for _, repo := range repos {
				if owner == "" || strings.HasPrefix(repo.FullName, owner+"/") {
					if !seen[repo.FullName] {
						seen[repo.FullName] = true
						names = append(names, repo.FullName)
					}
				}
			}
			if len(repos) < 100 {
				return nil
			}
		}
	}
	if err := add("https://api.github.com/user/repos?affiliation=owner,organization_member"); err != nil {
		return nil, err
	}
	if owner != "" {
		var orgRepos []struct {
			FullName string `json:"full_name"`
		}
		if err := c.get(fmt.Sprintf("https://api.github.com/orgs/%s/repos?type=all&per_page=100&page=1", owner), &orgRepos); err == nil {
			for _, repo := range orgRepos {
				if !seen[repo.FullName] {
					seen[repo.FullName] = true
					names = append(names, repo.FullName)
				}
			}
		}
	}
	return names, nil
}

func decodeGitHubContent(content string) ([]byte, error) {
	content = strings.Join(strings.Fields(content), "")
	data, err := base64.StdEncoding.DecodeString(content)
	if err != nil {
		return nil, fmt.Errorf("decode GitHub content: %w", err)
	}
	return data, nil
}

func contains(values []string, value string) bool {
	for _, item := range values {
		if item == value {
			return true
		}
	}
	return false
}

func (t GitHubTarget) Files() ([]File, error) {
	branch, err := t.Client.DefaultBranch(t.Repo)
	if err != nil {
		return nil, err
	}
	var tree struct {
		Tree []struct {
			Path string `json:"path"`
			Type string `json:"type"`
			URL  string `json:"url"`
		} `json:"tree"`
	}
	url := fmt.Sprintf("https://api.github.com/repos/%s/git/trees/%s?recursive=1", t.Repo, url.QueryEscape(branch))
	if err := t.Client.get(url, &tree); err != nil {
		return nil, err
	}
	var files []File
	for _, item := range tree.Tree {
		if item.Type != "blob" || !scannable(item.Path) || excludedPath(t.Excludes, item.Path) {
			continue
		}
		if strings.HasPrefix(item.Path, ".sentiniel-quarantine/") || strings.Contains(item.Path, "/.sentiniel-quarantine/") {
			continue
		}
		var content struct {
			Content string `json:"content"`
		}
		if err := t.Client.get(item.URL, &content); err != nil {
			continue
		}
		data, err := decodeGitHubContent(content.Content)
		if err == nil {
			files = append(files, File{Path: item.Path, Data: data})
		}
	}
	return files, nil
}

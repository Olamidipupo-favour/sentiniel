package sentiniel

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type Mode string

const (
	DryRun Mode = "dry-run"
	Apply  Mode = "apply"
)

type Finding struct {
	Repository string   `json:"repository"`
	Branch     string   `json:"branch,omitempty"`
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

// Strategy inspects one immutable file. Detection patterns live in the strategy, never in the
// scanner or the targets.
type Strategy interface {
	Name() string
	Match(File) (Finding, bool)
}

// Fixer is implemented by strategies that can repair what they detect. A strategy without it is
// advisory: apply mode leaves its findings alone.
type Fixer interface {
	// Fix returns replacement bytes, or remove=true for a file that must be deleted. If the
	// returned bytes equal the input, the target writes nothing.
	Fix(path string, data []byte) (updated []byte, remove bool, message string)
}

// Candidate is implemented by strategies that know which paths they can inspect. A strategy
// without it is offered every candidate file.
type Candidate interface {
	Candidate(path string) bool
}

type Scanner struct {
	Strategies []Strategy
}

func allStrategies() []Strategy {
	return []Strategy{IOCStrategy{}, WorkspaceStrategy{}, HeuristicStrategy{}}
}

func strategyByName(name string) (Strategy, bool) {
	for _, strategy := range allStrategies() {
		if strategy.Name() == name {
			return strategy, true
		}
	}
	return nil, false
}

func NewScanner(names []string) (*Scanner, error) {
	if len(names) == 0 || contains(names, "all") {
		return &Scanner{Strategies: allStrategies()}, nil
	}
	var selected []Strategy
	for _, name := range names {
		strategy, ok := strategyByName(name)
		if !ok {
			available := make([]string, 0, len(allStrategies()))
			for _, strategy := range allStrategies() {
				available = append(available, strategy.Name())
			}
			return nil, fmt.Errorf("unknown strategy %q (available: %s, all)", name, strings.Join(available, ", "))
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

// Candidate reports whether any selected strategy wants this path. Targets use it so they do not
// download files that no strategy can inspect.
func (s *Scanner) Candidate(path string) bool {
	for _, strategy := range s.Strategies {
		candidate, ok := strategy.(Candidate)
		if !ok || candidate.Candidate(path) {
			return true
		}
	}
	return false
}

type LocalTarget struct {
	Root     string
	Excludes []string
}

func (t LocalTarget) Files(accept func(string) bool) ([]File, error) {
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
		if excludedPath(t.Excludes, rel) || (accept != nil && !accept(rel)) {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		files = append(files, File{Path: rel, Data: data})
		return nil
	})
	return files, err
}

func (t LocalTarget) Remediate(f Finding, mode Mode) (string, error) {
	if mode == DryRun {
		return "dry-run: no files changed", nil
	}
	if excludedPath(t.Excludes, f.Path) {
		return "skipped: path is excluded", nil
	}
	strategy, ok := strategyByName(f.Strategy)
	fixer, ok := strategy.(Fixer)
	if !ok {
		return "manual remediation required for advisory finding; no files changed", nil
	}
	source := filepath.Join(t.Root, filepath.FromSlash(f.Path))
	data, err := os.ReadFile(source)
	if err != nil {
		return "", err
	}
	updated, remove, message := fixer.Fix(f.Path, data)
	if !remove && bytes.Equal(updated, data) {
		return message, nil
	}
	quarantine := filepath.Join(t.Root, ".sentiniel-quarantine", filepath.FromSlash(f.Path))
	if err := os.MkdirAll(filepath.Dir(quarantine), 0700); err != nil {
		return "", err
	}
	if err := os.WriteFile(quarantine, data, 0600); err != nil {
		return "", err
	}
	if remove {
		if err := os.Remove(source); err != nil {
			return "", err
		}
	} else if err := os.WriteFile(source, updated, 0600); err != nil {
		return "", err
	}
	return message + "; original saved in .sentiniel-quarantine", nil
}

type GitHubTarget struct {
	Client   *GitHubClient
	Repo     string
	Branch   string
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
	// Reads are idempotent, so a slow or flaky connection gets a retry instead of silently
	// dropping a repository from the scan.
	for attempt := 1; ; attempt++ {
		err := c.do(http.MethodGet, url, nil, target)
		if err == nil || attempt == 3 || !transient(err) {
			return err
		}
		time.Sleep(time.Duration(attempt) * time.Second)
	}
}

// transient reports whether a read is worth retrying: transport failures, timeouts, truncated
// bodies, and 5xx or rate-limit responses.
func transient(err error) bool {
	var netErr net.Error
	if errors.As(err, &netErr) || errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}
	message := err.Error()
	return strings.Contains(message, "GitHub API 5") || strings.Contains(message, "GitHub API 429")
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

// Branches lists the branches the token can see, so non-default branches are not trusted blindly.
func (c *GitHubClient) Branches(repo string) ([]string, error) {
	var branches []struct {
		Name string `json:"name"`
	}
	if err := c.get("https://api.github.com/repos/"+repo+"/branches?per_page=100", &branches); err != nil {
		return nil, err
	}
	names := make([]string, 0, len(branches))
	for _, branch := range branches {
		names = append(names, branch.Name)
	}
	return names, nil
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

// Remediate fixes a finding directly on the remote branch. It is only called after explicit user
// confirmation, keeps a copy under .sentiniel-quarantine, and never touches advisory findings.
func (t GitHubTarget) Remediate(f Finding, mode Mode) (string, error) {
	if mode == DryRun {
		return "dry-run: no remote changes", nil
	}
	if excludedPath(t.Excludes, f.Path) {
		return "skipped: path is excluded", nil
	}
	strategy, ok := strategyByName(f.Strategy)
	if !ok {
		return "unknown strategy in findings plan; rescan before applying", nil
	}
	fixer, ok := strategy.(Fixer)
	if !ok {
		return "manual remediation required for advisory finding; no remote changes", nil
	}
	branch := t.Branch
	if branch == "" {
		var err error
		if branch, err = t.Client.DefaultBranch(t.Repo); err != nil {
			return "", err
		}
	}
	original, err := t.Client.file(t.Repo, f.Path, branch)
	if err != nil {
		return "", err
	}
	updated, remove, message := fixer.Fix(f.Path, original.Data)
	if !remove && bytes.Equal(updated, original.Data) {
		return message, nil
	}
	quarantine := ".sentiniel-quarantine/" + f.Path
	if _, err := t.Client.file(t.Repo, quarantine, branch); err != nil {
		if _, err := t.Client.putFile(t.Repo, quarantine, branch, "sentiniel: preserve "+f.Path, original.Data, ""); err != nil {
			return "", fmt.Errorf("preserve original: %w", err)
		}
	}
	var sha string
	if remove {
		sha, err = t.Client.deleteFile(t.Repo, f.Path, branch, "sentiniel: "+message, original.SHA)
	} else {
		sha, err = t.Client.putFile(t.Repo, f.Path, branch, "sentiniel: "+message, updated, original.SHA)
	}
	if err != nil {
		return "", err
	}
	return message + "; original preserved in .sentiniel-quarantine (commit " + shortSHA(sha) + ")", nil
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

// excludedPath reports whether path is one of the excluded subtrees.
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

func contains(values []string, value string) bool {
	for _, item := range values {
		if item == value {
			return true
		}
	}
	return false
}

func (t GitHubTarget) Files(accept func(string) bool) ([]File, error) {
	branch := t.Branch
	if branch == "" {
		var err error
		if branch, err = t.Client.DefaultBranch(t.Repo); err != nil {
			return nil, err
		}
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
		if item.Type != "blob" || excludedPath(t.Excludes, item.Path) || (accept != nil && !accept(item.Path)) {
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

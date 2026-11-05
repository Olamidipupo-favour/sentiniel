package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Olamidipupo-favour/sentiniel"
	"golang.org/x/term"
)

type options struct {
	path, repo, owner, strategies, listen, output, findings string
	exclude, token, clone                                   string
	format                                                  string
	mode                                                    sentiniel.Mode
	recursive, confirm, interactive, forceRemote            bool
	failOn                                                  string
}

var (
	version = "dev"
	stdin   = bufio.NewReader(os.Stdin)
)

// buildVersion falls back to the module version so `go install ...@vX` is not reported as dev.
func buildVersion() string {
	if version != "dev" {
		return version
	}
	info, ok := debug.ReadBuildInfo()
	if !ok || info.Main.Version == "" || info.Main.Version == "(devel)" {
		return version
	}
	return info.Main.Version
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "scan":
		runScan(os.Args[2:])
	case "action":
		runAction(os.Args[2:])
	case "run":
		runCombined(os.Args[2:])
	case "schedule":
		runSchedule(os.Args[2:])
	case "webhook":
		runWebhook(os.Args[2:])
	case "login":
		runLogin(os.Args[2:])
	case "logout":
		runLogout()
	case "version":
		fmt.Println("sentiniel", buildVersion())
	default:
		usage()
		os.Exit(2)
	}
}

func runScan(args []string) {
	var o options
	fs := newScanFlags(&o)
	fs.Parse(args)
	if o.mode == sentiniel.Apply || o.confirm {
		fatal("scan is read-only; use action or run --apply --confirm")
	}
	findings := collectFindings(o)
	if err := writeFindings(findings, o); err != nil {
		fatal(err.Error())
	}
	printFindings(findings, o)
	exitOnSeverity(findings, o.failOn)
}

func runAction(args []string) {
	var o options
	fs := flag.NewFlagSet("action", flag.ExitOnError)
	fs.StringVar(&o.path, "path", "", "local repository")
	fs.StringVar(&o.findings, "findings", "", "JSON findings file produced by scan")
	fs.StringVar((*string)(&o.mode), "mode", string(sentiniel.DryRun), "action mode: dry-run or apply")
	fs.BoolVar(&o.confirm, "confirm", false, "confirm remediation")
	fs.BoolVar(&o.forceRemote, "force-remote", false, "write fixes to remote repositories directly")
	fs.Parse(args)
	if o.findings == "" || (o.path == "" && !o.forceRemote) {
		fatal("action requires --findings and either --path or --force-remote")
	}
	if o.mode == sentiniel.Apply && !o.confirm {
		fatal("apply action is gated; pass --confirm after reviewing the findings plan")
	}
	data, err := os.ReadFile(o.findings)
	if err != nil {
		fatal(err.Error())
	}
	var findings []sentiniel.Finding
	if err := json.Unmarshal(data, &findings); err != nil {
		fatal("findings file must be a JSON array")
	}
	client := remoteClient(o)
	remediateAll(findings, o.path, client, o.mode)
	printFindings(findings, options{format: "text", mode: o.mode})
}

// remediationRoot picks the local copy a finding belongs to, if any.
func remediationRoot(f sentiniel.Finding, fallback string) string {
	if f.Local != "" {
		return f.Local
	}
	return fallback
}

// remoteClient returns a GitHub client only when a remote write was explicitly requested.
func remoteClient(o options) *sentiniel.GitHubClient {
	if !o.forceRemote {
		return nil
	}
	if !o.confirm {
		fatal("--force-remote writes to remote repositories; pass --confirm")
	}
	client, err := sentiniel.NewGitHubClient(o.token)
	if err != nil {
		fatal(err.Error())
	}
	return client
}

// remediateAll fixes each finding in the local copy it belongs to, or on the remote repository when
// --force-remote supplied a client. A finding with no target is reported, never silently dropped.
func remediateAll(findings []sentiniel.Finding, path string, client *sentiniel.GitHubClient, mode sentiniel.Mode) (local, remote bool) {
	for i := range findings {
		var action string
		var err error
		root := remediationRoot(findings[i], path)
		switch {
		case root != "":
			action, err = sentiniel.LocalTarget{Root: root}.Remediate(findings[i], mode)
			local = true
		case client != nil && strings.Contains(findings[i].Repository, "/"):
			action, err = (sentiniel.GitHubTarget{Client: client, Repo: findings[i].Repository}).Remediate(findings[i], mode)
			remote = true
		default:
			findings[i].Action = "skipped: no local copy; use --path or --clone, or --force-remote for a remote write"
			continue
		}
		if err != nil {
			findings[i].Action = "remediation failed: " + err.Error()
		} else {
			findings[i].Action = action
		}
	}
	return local, remote
}

func runCombined(args []string) {
	var o options
	var apply bool
	fs := newScanFlags(&o)
	fs.BoolVar(&o.confirm, "confirm", false, "confirm remediation")
	fs.BoolVar(&apply, "apply", false, "enable remediation after scan")
	fs.Parse(args)
	if o.forceRemote && !o.confirm {
		fatal("--force-remote writes to remote repositories; pass --confirm after reviewing the findings")
	}
	findings := collectFindings(o)
	if o.output != "" {
		if err := writeFindings(findings, o); err != nil {
			fatal(err.Error())
		}
	}
	printFindings(findings, options{format: "text", mode: sentiniel.DryRun})
	if !apply || !o.confirm {
		return
	}
	local, remote := remediateAll(findings, o.path, remoteClient(o), sentiniel.Apply)
	if !local && !remote && len(findings) > 0 {
		fatal("confirmed actions need a target: pass --path, --clone DIR with --interactive, or --force-remote")
	}
	printFindings(findings, options{format: "text", mode: sentiniel.Apply})
}

func runLogin(args []string) {
	var token string
	fs := flag.NewFlagSet("login", flag.ExitOnError)
	fs.StringVar(&token, "token", "", "GitHub personal access token; prompted for when omitted")
	fs.Parse(args)
	if token == "" {
		fmt.Print("GitHub token (needs repo, and read:org for organizations): ")
		if term.IsTerminal(int(os.Stdin.Fd())) {
			data, err := term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Println()
			if err != nil {
				fatal(err.Error())
			}
			token = string(data)
		} else {
			line, _ := stdin.ReadString('\n')
			token = line
		}
	}
	token = strings.TrimSpace(token)
	client, err := sentiniel.NewGitHubClient(token)
	if err != nil {
		fatal(err.Error())
	}
	user, err := client.User()
	if err != nil {
		fatal("token rejected: " + err.Error())
	}
	if err := sentiniel.SaveToken(token); err != nil {
		fatal(err.Error())
	}
	path, _ := sentiniel.TokenPath()
	fmt.Printf("Signed in as %s. Token stored in %s\n", user, path)
}

func runLogout() {
	if err := sentiniel.RemoveToken(); err != nil {
		fatal(err.Error())
	}
	fmt.Println("Signed out; stored token removed.")
}

func collectInteractive(o options, scanner *sentiniel.Scanner) []sentiniel.Finding {
	client, err := sentiniel.NewGitHubClient(o.token)
	if err != nil {
		fatal(err.Error())
	}
	user, err := client.User()
	if err != nil {
		fatal(err.Error())
	}
	orgs, err := client.Organizations()
	if err != nil {
		fmt.Fprintf(os.Stderr, "sentiniel: warning: cannot list organizations: %v\n", err)
	}
	owners := append([]string{user}, orgs...)
	fmt.Fprintln(os.Stderr, "Accounts and organizations:")
	for i, owner := range owners {
		fmt.Fprintf(os.Stderr, "  %d. %s\n", i+1, owner)
	}
	choice := prompt(fmt.Sprintf("Select owners [1-%d] (comma-separated, 'all', or empty for 1): ", len(owners)))
	ownerIndices := []int{0}
	if choice != "" {
		ownerIndices, err = parseSelection(choice, len(owners))
		if err != nil {
			fatal(err.Error())
		}
	}
	repos := []string{}
	seenRepo := map[string]bool{}
	for _, index := range ownerIndices {
		ownerRepos, err := client.Repositories(owners[index])
		if err != nil {
			fmt.Fprintf(os.Stderr, "sentiniel: warning: cannot list %s: %v\n", owners[index], err)
			continue
		}
		for _, repo := range ownerRepos {
			if !seenRepo[repo] {
				seenRepo[repo] = true
				repos = append(repos, repo)
			}
		}
	}
	if len(repos) == 0 {
		fatal("no repositories visible for the selected owners")
	}
	fmt.Fprintf(os.Stderr, "Repositories in %d owner(s) (%d):\n", len(ownerIndices), len(repos))
	for i, repo := range repos {
		fmt.Fprintf(os.Stderr, "  %d. %s\n", i+1, repo)
	}
	selection := prompt("Select repositories (comma-separated numbers, 'all', or empty for all): ")
	indices, err := parseSelection(selection, len(repos))
	if err != nil {
		fatal(err.Error())
	}
	selected := make([]string, 0, len(indices))
	for _, i := range indices {
		selected = append(selected, repos[i])
	}
	if o.clone == "" {
		return scanRepos(client, selected, scanner)
	}
	return scanClones(client.Token, o.clone, selected, scanner)
}

// scanClones downloads each repository and scans the local copy, so `run --clone` can remediate it.
func scanClones(token, dir string, repos []string, scanner *sentiniel.Scanner) []sentiniel.Finding {
	if err := os.MkdirAll(dir, 0700); err != nil {
		fatal(err.Error())
	}
	root, err := filepath.Abs(dir)
	if err != nil {
		fatal(err.Error())
	}
	var all []sentiniel.Finding
	for _, repo := range repos {
		dest := filepath.Join(root, strings.ReplaceAll(repo, "/", "__"))
		if _, err := os.Stat(dest); err == nil {
			fmt.Fprintf(os.Stderr, "sentiniel: reusing %s\n", dest)
		} else if err := cloneRepo(token, repo, dest); err != nil {
			fmt.Fprintf(os.Stderr, "sentiniel: warning: skipping %s: %v\n", repo, err)
			continue
		}
		files, err := (sentiniel.LocalTarget{Root: dest}).Files()
		if err != nil {
			fmt.Fprintf(os.Stderr, "sentiniel: warning: skipping %s: %v\n", repo, err)
			continue
		}
		for _, finding := range scanner.Scan(files, repo) {
			finding.Local = dest
			all = append(all, finding)
		}
	}
	return all
}

func cloneRepo(token, repo, dest string) error {
	cmd := exec.Command("git", "clone", "--depth", "1", "--no-tags", "https://github.com/"+repo+".git", dest)
	if token != "" {
		// Env, not argv, so the token never appears in the process list or in the clone's config.
		cmd.Env = append(os.Environ(),
			"GIT_CONFIG_COUNT=1",
			"GIT_CONFIG_KEY_0=url.https://x-access-token:"+token+"@github.com/.insteadOf",
			"GIT_CONFIG_VALUE_0=https://github.com/",
		)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("git clone: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func prompt(label string) string {
	fmt.Fprint(os.Stderr, label)
	line, _ := stdin.ReadString('\n')
	return strings.TrimSpace(line)
}

func parseSelection(input string, count int) ([]int, error) {
	input = strings.TrimSpace(strings.ToLower(input))
	if input == "" || input == "all" {
		all := make([]int, count)
		for i := range all {
			all[i] = i
		}
		return all, nil
	}
	seen := map[int]bool{}
	var selected []int
	for _, part := range strings.Split(input, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		value, err := strconv.Atoi(part)
		if err != nil || value < 1 || value > count {
			return nil, fmt.Errorf("invalid selection %q (expected 1-%d)", part, count)
		}
		if !seen[value-1] {
			seen[value-1] = true
			selected = append(selected, value-1)
		}
	}
	if len(selected) == 0 {
		return nil, fmt.Errorf("no selection made")
	}
	return selected, nil
}

func newScanFlags(o *options) *flag.FlagSet {
	o.mode = sentiniel.DryRun
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	fs.StringVar(&o.path, "path", "", "local repository or parent directory")
	fs.StringVar(&o.repo, "repo", "", "GitHub repository owner/name")
	fs.StringVar(&o.owner, "owner", "", "GitHub owner or organization")
	fs.StringVar(&o.strategies, "strategies", "all", "comma-separated strategies: ioc,heuristic,all")
	fs.StringVar(&o.format, "format", "text", "output format: text or json")
	fs.StringVar(&o.output, "output", "", "write JSON findings plan to this file")
	fs.StringVar(&o.exclude, "exclude", "", "comma-separated local relative paths to exclude")
	fs.StringVar(&o.token, "token", "", "GitHub token for this run (or GITHUB_TOKEN/GH_TOKEN, sentiniel login)")
	fs.StringVar(&o.failOn, "fail-on", "", "exit nonzero when findings meet severity: low,medium,high")
	fs.BoolVar(&o.recursive, "recursive", false, "scan immediate child directories as well as --path")
	fs.BoolVar(&o.interactive, "interactive", false, "choose an account, organization, and repositories interactively")
	fs.StringVar(&o.clone, "clone", "", "with --interactive: download selected repositories into DIR, then scan those copies")
	fs.BoolVar(&o.forceRemote, "force-remote", false, "with --apply --confirm: write fixes to remote repositories directly")
	return fs
}

func collectFindings(o options) []sentiniel.Finding {
	if o.clone != "" && !o.interactive {
		fatal("--clone requires --interactive")
	}
	if o.interactive {
		if o.path != "" || o.repo != "" || o.owner != "" {
			fatal("--interactive cannot be combined with --path, --repo, or --owner")
		}
		scanner, err := sentiniel.NewScanner(split(o.strategies))
		if err != nil {
			fatal(err.Error())
		}
		return collectInteractive(o, scanner)
	}
	if o.path == "" && o.repo == "" && o.owner == "" {
		fatal("choose --path, --repo, --owner, or --interactive")
	}
	scanner, err := sentiniel.NewScanner(split(o.strategies))
	if err != nil {
		fatal(err.Error())
	}
	if o.repo != "" || o.owner != "" {
		client, err := sentiniel.NewGitHubClient(o.token)
		if err != nil {
			fatal(err.Error())
		}
		var repos []string
		if o.repo != "" {
			repos = []string{o.repo}
		} else {
			repos, err = client.Repositories(o.owner)
			if err != nil {
				fatal(err.Error())
			}
		}
		return scanRepos(client, repos, scanner)
	}
	info, err := os.Stat(o.path)
	if err != nil {
		fatal(err.Error())
	}
	if info.IsDir() && o.recursive {
		var all []sentiniel.Finding
		target := sentiniel.LocalTarget{Root: o.path, Excludes: split(o.exclude)}
		rootFiles, err := target.Files()
		if err != nil {
			fatal(err.Error())
		}
		all = append(all, scanner.Scan(rootFiles, o.path)...)
		entries, _ := os.ReadDir(o.path)
		for _, entry := range entries {
			if entry.IsDir() && entry.Name() != "machoka" && entry.Name() != ".git" && !strings.HasPrefix(entry.Name(), ".sentiniel-") {
				files, err := (sentiniel.LocalTarget{Root: filepath.Join(o.path, entry.Name()), Excludes: split(o.exclude)}).Files()
				if err != nil {
					fatal(err.Error())
				}
				all = append(all, scanner.Scan(files, filepath.Join(o.path, entry.Name()))...)
			}
		}
		return all
	}
	files, err := (sentiniel.LocalTarget{Root: o.path, Excludes: split(o.exclude)}).Files()
	if err != nil {
		fatal(err.Error())
	}
	return scanner.Scan(files, o.path)
}

func scanRepos(client *sentiniel.GitHubClient, repos []string, scanner *sentiniel.Scanner) []sentiniel.Finding {
	var all []sentiniel.Finding
	if len(repos) == 0 {
		return all
	}
	var mu sync.Mutex
	jobs := make(chan string)
	var wg sync.WaitGroup
	workers := 8
	if len(repos) < workers {
		workers = len(repos)
	}
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for repo := range jobs {
				target := sentiniel.GitHubTarget{Client: client, Repo: repo}
				files, err := target.Files()
				if err != nil {
					fmt.Fprintf(os.Stderr, "sentiniel: warning: skipping %s: %v\n", repo, err)
					continue
				}
				findings := scanner.Scan(files, repo)
				mu.Lock()
				all = append(all, findings...)
				mu.Unlock()
			}
		}()
	}
	for _, repo := range repos {
		jobs <- repo
	}
	close(jobs)
	wg.Wait()
	return all
}

func writeFindings(findings []sentiniel.Finding, o options) error {
	if o.output == "" {
		return nil
	}
	data, err := json.MarshalIndent(findings, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(o.output, append(data, '\n'), 0600)
}

func printFindings(findings []sentiniel.Finding, o options) {
	if o.format == "json" {
		if findings == nil {
			findings = []sentiniel.Finding{}
		}
		_ = json.NewEncoder(os.Stdout).Encode(findings)
		return
	}
	if len(findings) == 0 {
		fmt.Println("No indicators found.")
		return
	}
	for _, finding := range findings {
		fmt.Printf("[%s] %s %s [%s] %s\n", finding.Severity, finding.Repository, finding.Path, finding.Strategy, strings.Join(finding.Reasons, "; "))
		fmt.Println("  action:", finding.Action)
	}
	fmt.Printf("%d finding(s); mode=%s\n", len(findings), o.mode)
}

func exitOnSeverity(findings []sentiniel.Finding, threshold string) {
	if threshold == "" {
		return
	}
	rank := map[string]int{"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
	limit := rank[strings.ToUpper(threshold)]
	for _, finding := range findings {
		if rank[strings.ToUpper(finding.Severity)] >= limit {
			os.Exit(1)
		}
	}
}

func runSchedule(args []string) {
	var interval time.Duration
	fs := flag.NewFlagSet("schedule", flag.ExitOnError)
	fs.DurationVar(&interval, "interval", 24*time.Hour, "repeat interval")
	fs.Parse(args)
	fmt.Printf("Run periodically with an external scheduler: sentiniel scan --path /repo --format json (interval %s)\n", interval)
	fmt.Println("GitHub Actions, cron, launchd, Task Scheduler, and systemd timer examples are documented in docs/operations.md.")
}

func runWebhook(args []string) {
	var listen, repo string
	fs := flag.NewFlagSet("webhook", flag.ExitOnError)
	fs.StringVar(&listen, "listen", "127.0.0.1:8080", "HTTP listen address")
	fs.StringVar(&repo, "repo", "", "GitHub repository to scan on POST /scan")
	fs.Parse(args)
	if repo == "" {
		fatal("--repo is required")
	}
	client, err := sentiniel.NewGitHubClient("")
	if err != nil {
		fatal(err.Error())
	}
	scanner, _ := sentiniel.NewScanner([]string{"all"})
	http.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	http.HandleFunc("/scan", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST required", http.StatusMethodNotAllowed)
			return
		}
		files, err := (sentiniel.GitHubTarget{Client: client, Repo: repo}).Files()
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(scanner.Scan(files, repo))
	})
	fmt.Println("sentiniel webhook listening on", listen)
	if err := http.ListenAndServe(listen, nil); err != nil {
		fatal(err.Error())
	}
}

func split(value string) []string { return strings.Split(value, ",") }
func fatal(message string)        { fmt.Fprintln(os.Stderr, "sentiniel:", message); os.Exit(1) }
func usage() {
	fmt.Println(`sentiniel - extensible repository threat scanner

Commands:
  scan      Read-only scan; optionally write a JSON findings plan
  action    Apply a reviewed local or remote findings plan
  run       Chain scan and local action with explicit confirmation
  login     Store a GitHub token without requiring gh
  logout    Remove the stored GitHub token
  schedule  Print scheduler integration guidance
  webhook   Serve a read-only POST /scan endpoint
  version   Print the version

Examples:
  sentiniel login
  sentiniel scan --interactive
  sentiniel run --interactive --clone ./clones --apply --confirm
  sentiniel run --owner OWNER --apply --confirm --force-remote
  sentiniel scan --repo OWNER/REPO --format json --output findings.json
  sentiniel scan --path ./repo --exclude fixtures/infected
  sentiniel action --path ./repo --findings findings.json --confirm
  sentiniel run --path ./repo --output findings.json --apply --confirm`)
}

func init() {
	signal.Ignore(syscall.SIGPIPE)
}

package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
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
	exclude, token                                          string
	format                                                  string
	mode                                                    sentiniel.Mode
	recursive, confirm, interactive                         bool
	failOn                                                  string
}

var version = "dev"

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
		fmt.Println("sentiniel", version)
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
	fs.Parse(args)
	if o.path == "" || o.findings == "" {
		fatal("action requires --path and --findings")
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
	target := sentiniel.LocalTarget{Root: o.path}
	for i := range findings {
		if findings[i].Repository != "" && findings[i].Repository != o.path {
			continue
		}
		action, err := target.Remediate(findings[i], o.mode)
		if err != nil {
			findings[i].Action = "remediation failed: " + err.Error()
		} else {
			findings[i].Action = action
		}
	}
	printFindings(findings, options{format: "text", mode: o.mode})
}

func runCombined(args []string) {
	var o options
	var apply bool
	fs := newScanFlags(&o)
	fs.BoolVar(&o.confirm, "confirm", false, "confirm remediation")
	fs.BoolVar(&apply, "apply", false, "enable local remediation after scan")
	fs.Parse(args)
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
	if o.path == "" || o.repo != "" || o.owner != "" {
		fatal("confirmed actions are currently limited to a local --path")
	}
	target := sentiniel.LocalTarget{Root: o.path}
	for i := range findings {
		action, err := target.Remediate(findings[i], sentiniel.Apply)
		if err != nil {
			findings[i].Action = "remediation failed: " + err.Error()
		} else {
			findings[i].Action = action
		}
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
			line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
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
	fmt.Println("Accounts and organizations:")
	for i, owner := range owners {
		fmt.Printf("  %d. %s\n", i+1, owner)
	}
	choice := prompt(fmt.Sprintf("Select one [1-%d] (default 1): ", len(owners)))
	index := 0
	if choice != "" {
		indices, err := parseSelection(choice, len(owners))
		if err != nil {
			fatal(err.Error())
		}
		if len(indices) != 1 {
			fatal("select exactly one account or organization")
		}
		index = indices[0]
	}
	repos, err := client.Repositories(owners[index])
	if err != nil {
		fatal(err.Error())
	}
	if len(repos) == 0 {
		fatal("no repositories visible for " + owners[index])
	}
	fmt.Printf("Repositories in %s (%d):\n", owners[index], len(repos))
	for i, repo := range repos {
		fmt.Printf("  %d. %s\n", i+1, repo)
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
	return scanRepos(client, selected, scanner)
}

func prompt(label string) string {
	fmt.Print(label)
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
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
	return fs
}

func collectFindings(o options) []sentiniel.Finding {
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
  action    Apply a reviewed local findings plan
  run       Chain scan and local action with explicit confirmation
  login     Store a GitHub token without requiring gh
  logout    Remove the stored GitHub token
  schedule  Print scheduler integration guidance
  webhook   Serve a read-only POST /scan endpoint
  version   Print the version

Examples:
  sentiniel login
  sentiniel scan --interactive
  sentiniel scan --repo OWNER/REPO --format json --output findings.json
  sentiniel scan --path ./repo --exclude fixtures/infected
  sentiniel action --path ./repo --findings findings.json --confirm
  sentiniel run --path ./repo --output findings.json --apply --confirm`)
}

func init() {
	signal.Ignore(syscall.SIGPIPE)
}

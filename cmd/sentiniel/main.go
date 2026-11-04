package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/Olamidipupo-favour/sentiniel"
)

type options struct {
	path, repo, owner, strategies, listen, output, findings string
	format                                                  string
	mode                                                    sentiniel.Mode
	recursive, confirm                                      bool
	failOn                                                  string
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
	case "version":
		fmt.Println("sentiniel dev")
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

func newScanFlags(o *options) *flag.FlagSet {
	o.mode = sentiniel.DryRun
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	fs.StringVar(&o.path, "path", "", "local repository or parent directory")
	fs.StringVar(&o.repo, "repo", "", "GitHub repository owner/name")
	fs.StringVar(&o.owner, "owner", "", "GitHub owner or organization")
	fs.StringVar(&o.strategies, "strategies", "all", "comma-separated strategies: ioc,heuristic,all")
	fs.StringVar(&o.format, "format", "text", "output format: text or json")
	fs.StringVar(&o.output, "output", "", "write JSON findings plan to this file")
	fs.StringVar(&o.failOn, "fail-on", "", "exit nonzero when findings meet severity: low,medium,high")
	fs.BoolVar(&o.recursive, "recursive", false, "scan immediate child directories as well as --path")
	return fs
}

func collectFindings(o options) []sentiniel.Finding {
	if o.path == "" && o.repo == "" && o.owner == "" {
		fatal("choose --path, --repo, or --owner")
	}
	scanner, err := sentiniel.NewScanner(split(o.strategies))
	if err != nil {
		fatal(err.Error())
	}
	if o.repo != "" || o.owner != "" {
		client, err := sentiniel.NewGitHubClient("")
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
		var all []sentiniel.Finding
		for _, repo := range repos {
			target := sentiniel.GitHubTarget{Client: client, Repo: repo}
			files, err := target.Files()
			if err != nil {
				fmt.Fprintf(os.Stderr, "sentiniel: warning: skipping %s: %v\n", repo, err)
				continue
			}
			all = append(all, scanner.Scan(files, repo)...)
		}
		return all
	}
	info, err := os.Stat(o.path)
	if err != nil {
		fatal(err.Error())
	}
	if info.IsDir() && o.recursive {
		var all []sentiniel.Finding
		rootFiles, err := (sentiniel.LocalTarget{Root: o.path}).Files()
		if err != nil {
			fatal(err.Error())
		}
		all = append(all, scanner.Scan(rootFiles, o.path)...)
		entries, _ := os.ReadDir(o.path)
		for _, entry := range entries {
			if entry.IsDir() && entry.Name() != "machoka" && entry.Name() != ".git" && !strings.HasPrefix(entry.Name(), ".sentiniel-") {
				files, err := (sentiniel.LocalTarget{Root: filepath.Join(o.path, entry.Name())}).Files()
				if err != nil {
					fatal(err.Error())
				}
				all = append(all, scanner.Scan(files, filepath.Join(o.path, entry.Name()))...)
			}
		}
		return all
	}
	files, err := (sentiniel.LocalTarget{Root: o.path}).Files()
	if err != nil {
		fatal(err.Error())
	}
	return scanner.Scan(files, o.path)
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
  schedule  Print scheduler integration guidance
  webhook   Serve a read-only POST /scan endpoint
  version   Print the version

Examples:
  sentiniel scan --repo OWNER/REPO --format json --output findings.json
  sentiniel action --path ./repo --findings findings.json --confirm
  sentiniel run --path ./repo --output findings.json --apply --confirm`)
}

func init() {
	signal.Ignore(syscall.SIGPIPE)
}

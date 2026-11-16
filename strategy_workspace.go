package sentiniel

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"regexp"
	"strings"
)

const (
	tasksPath    = ".vscode/tasks.json"
	settingsPath = ".vscode/settings.json"
)

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
	folderOpenTask  = regexp.MustCompile(`"runOn"\s*:\s*"folderOpen"`)
)

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

// WorkspaceStrategy reports VS Code configuration that executes code when a repository is opened.
type WorkspaceStrategy struct{}

func (WorkspaceStrategy) Name() string { return "workspace" }

func (WorkspaceStrategy) Candidate(path string) bool {
	path = filepath.ToSlash(path)
	return path == tasksPath || path == settingsPath
}

func (WorkspaceStrategy) Match(file File) (Finding, bool) {
	switch filepath.ToSlash(file.Path) {
	case tasksPath:
		if len(maliciousTasks(file.Data)) > 0 {
			return Finding{Path: file.Path, Strategy: "workspace", Severity: "HIGH", Reasons: []string{"folder-open task executes a disguised script payload"}, Action: "remove the task only after preserving the original and reviewing the repository"}, true
		}
		// A task file we cannot parse still might run on folder open. Report it, but remediation
		// will refuse to rewrite it because the JSON is unknown.
		if folderOpenTask.Match(file.Data) {
			return Finding{Path: file.Path, Strategy: "workspace", Severity: "HIGH", Reasons: []string{"folder-open task could not be parsed; inspect it manually"}, Action: "inspect the task file by hand; it runs when the repository is opened"}, true
		}
	case settingsPath:
		if !automaticTasksEnabled(file.Data) {
			return Finding{}, false
		}
		return Finding{Path: file.Path, Strategy: "workspace", Severity: "HIGH", Reasons: []string{"workspace enables automatic tasks, so a folder-open task runs without confirmation"}, Action: "set task.allowAutomaticTasks to false and review .vscode/tasks.json"}, true
	}
	return Finding{}, false
}

func (WorkspaceStrategy) Fix(path string, data []byte) ([]byte, bool, string) {
	switch filepath.ToSlash(path) {
	case tasksPath:
		tasks, err := decodeTaskFile(data)
		if err != nil {
			return data, false, "task file is not plain JSON; inspect and remove the folder-open task manually"
		}
		out, err := json.MarshalIndent(withoutMaliciousTasks(tasks), "", "  ")
		if err != nil {
			return data, false, "cannot rewrite task file; inspect it manually"
		}
		return append(out, '\n'), false, "removed malicious folder-open task"
	case settingsPath:
		updated := disableAutomaticTasks(data)
		if bytes.Equal(updated, data) {
			return data, false, "no automatic-task setting found; no files changed"
		}
		return updated, false, "disabled automatic workspace tasks"
	}
	return data, false, "manual remediation required for this workspace file"
}

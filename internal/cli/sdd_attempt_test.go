package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gentleman-programming/gentle-ai/internal/sddstatus"
)

func TestRunSDDAttemptLifecycleIsMachineReadableAndResetExplicit(t *testing.T) {
	repo := initReviewCLIRepo(t)
	store, err := sddstatus.OpenRuntimeStore(context.Background(), repo, "cli-attempt")
	if err != nil {
		t.Fatal(err)
	}

	status := runSDDAttemptStatus(t, []string{"status", "--cwd", repo, "--change", "cli-attempt"})
	if status.Schema != sddstatus.RuntimeStatusSchema || status.Change != "cli-attempt" || status.Revision != "" || status.NextAction != sddstatus.RuntimeActionBegin {
		t.Fatalf("initial CLI status = %#v", status)
	}
	if _, statErr := os.Stat(store.Dir); !os.IsNotExist(statErr) {
		t.Fatalf("read-only status created native authority: %v", statErr)
	}

	started := runSDDAttemptStatus(t, []string{
		"begin", "--cwd", repo, "--change", "cli-attempt", "--expected-revision=", "--request-id", "cli-begin",
		"--work-unit", "runtime-harness", "--evidence-goal", "prove CLI runtime evidence", "--max-attempts", "1", "--max-changed-lines", "10",
	})
	if started.ActiveAttempt == nil || started.ActiveAttempt.Ordinal != 1 || started.NextAction != sddstatus.RuntimeActionFinish {
		t.Fatalf("begin CLI status = %#v", started)
	}

	failed := runSDDAttemptStatus(t, []string{
		"finish", "--cwd", repo, "--change", "cli-attempt", "--expected-revision", started.Revision, "--request-id", "cli-finish",
		"--outcome", "failed", "--evidence-revision", cliAttemptHash('a'),
		"--diagnosis", "CLI harness reproduced the bounded runtime failure", "--harness-disposition", "reused",
		"--cleanup-evidence", "CLI cleanup completed", "--process-evidence", "CLI process scan found no descendants",
	})
	if !failed.DecisionRequired || failed.NextAction != sddstatus.RuntimeActionReset {
		t.Fatalf("finish CLI status = %#v", failed)
	}

	reset := runSDDAttemptStatus(t, []string{
		"reset", "--cwd", repo, "--change", "cli-attempt", "--expected-revision", failed.Revision, "--request-id", "cli-reset",
		"--reason", "maintainer approved a changed runtime evidence scope", "--actor", "maintainer",
	})
	if reset.Objective != nil || reset.ObjectiveGeneration != 1 || reset.CumulativeAttempts != 0 || reset.LifetimeAttempts != 1 || reset.NextAction != sddstatus.RuntimeActionBegin {
		t.Fatalf("reset CLI status = %#v", reset)
	}
}

func TestRunSDDAttemptRejectsMissingOrAmbiguousInputs(t *testing.T) {
	repo := initReviewCLIRepo(t)
	tests := []struct {
		name string
		args []string
		want string
	}{
		{name: "missing operation", args: nil, want: "requires status, begin, finish, or reset"},
		{name: "unknown operation", args: []string{"again"}, want: "unknown sdd-attempt operation"},
		{name: "missing change", args: []string{"status", "--cwd", repo}, want: "--change"},
		{name: "unknown flag", args: []string{"status", "--cwd", repo, "--change", "thin", "--mystery"}, want: "flag provided but not defined"},
		{name: "irrelevant flag", args: []string{"status", "--cwd", repo, "--change", "thin", "--outcome", "failed"}, want: "flag provided but not defined"},
		{name: "missing begin CAS", args: []string{"begin", "--cwd", repo, "--change", "thin", "--request-id", "begin", "--work-unit", "unit", "--evidence-goal", "goal"}, want: "--expected-revision"},
		{name: "missing finish evidence", args: []string{"finish", "--cwd", repo, "--change", "thin", "--expected-revision", cliAttemptHash('b'), "--request-id", "finish", "--outcome", "failed", "--diagnosis", "diagnosis", "--harness-disposition", "reused", "--cleanup-evidence", "cleanup", "--process-evidence", "process"}, want: "--evidence-revision"},
		{name: "partial remediation successor", args: []string{"finish", "--cwd", repo, "--change", "thin", "--expected-revision", cliAttemptHash('b'), "--request-id", "finish", "--outcome", "passed", "--evidence-revision", cliAttemptHash('c'), "--diagnosis", "diagnosis", "--harness-disposition", "reused", "--cleanup-evidence", "cleanup", "--process-evidence", "process", "--successor-lineage", "review-successor"}, want: "remediation successor requires --expected-binding-revision, --successor-lineage, and --remediates-evidence-revision together"},
		{name: "positional argument", args: []string{"status", "--cwd", repo, "--change", "thin", "extra"}, want: "unexpected sdd-attempt argument"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var output bytes.Buffer
			err := RunSDDAttempt(tt.args, &output)
			if err == nil || !strings.Contains(err.Error(), tt.want) || output.Len() != 0 {
				t.Fatalf("RunSDDAttempt(%v) = output %q, err %v, want %q", tt.args, output.String(), err, tt.want)
			}
		})
	}
}

func runSDDAttemptStatus(t *testing.T, args []string) sddstatus.RuntimeStatus {
	t.Helper()
	var output bytes.Buffer
	if err := RunSDDAttempt(args, &output); err != nil {
		t.Fatalf("RunSDDAttempt(%v): %v", args, err)
	}
	var status sddstatus.RuntimeStatus
	decoder := json.NewDecoder(bytes.NewReader(output.Bytes()))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&status); err != nil {
		t.Fatalf("decode SDD attempt status: %v\n%s", err, output.String())
	}
	if !bytes.HasSuffix(output.Bytes(), []byte("\n")) {
		t.Fatalf("SDD attempt JSON lacks trailing newline: %q", output.Bytes())
	}
	return status
}

func cliAttemptHash(char byte) string {
	return "sha256:" + strings.Repeat(string(char), 64)
}

func TestRunSDDAttemptStatusPathUsesRepositoryCommonDir(t *testing.T) {
	repo := initReviewCLIRepo(t)
	linked := filepath.Join(t.TempDir(), "linked")
	runReviewCLIGit(t, repo, "worktree", "add", "-q", "--detach", linked)
	started := runSDDAttemptStatus(t, []string{
		"begin", "--cwd", repo, "--change", "linked-attempt", "--expected-revision=", "--request-id", "linked-begin",
		"--work-unit", "linked-work-unit", "--evidence-goal", "prove linked worktree authority", "--max-attempts", "2", "--max-changed-lines", "10",
	})
	fromLinked := runSDDAttemptStatus(t, []string{"status", "--cwd", linked, "--change", "linked-attempt"})
	if fromLinked.Revision != started.Revision || fromLinked.ActiveAttempt == nil || fromLinked.ActiveAttempt.Ordinal != 1 {
		t.Fatalf("linked status = %#v, want revision %s", fromLinked, started.Revision)
	}
}

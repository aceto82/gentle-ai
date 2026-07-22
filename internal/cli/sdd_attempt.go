package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/gentleman-programming/gentle-ai/internal/sddstatus"
)

// RunSDDAttempt exposes the artifact-store-agnostic native runtime authority.
// Every successful operation emits exactly one RuntimeStatus JSON value.
func RunSDDAttempt(args []string, stdout io.Writer) error {
	return runSDDAttempt(context.Background(), args, stdout)
}

func runSDDAttempt(ctx context.Context, args []string, stdout io.Writer) error {
	if len(args) == 0 {
		return errors.New("sdd-attempt requires status, begin, finish, or reset")
	}
	operation := args[0]
	if operation != "status" && operation != "begin" && operation != "finish" && operation != "reset" {
		return fmt.Errorf("unknown sdd-attempt operation %q", operation)
	}
	if err := validateSDDAttemptOperationFlags(operation, args[1:]); err != nil {
		return err
	}

	flags := flag.NewFlagSet("sdd-attempt "+operation, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	cwd := flags.String("cwd", "", "repository path")
	change := flags.String("change", "", "SDD change")
	expected := flags.String("expected-revision", "", "exact native runtime revision")
	requestID := flags.String("request-id", "", "idempotency request identifier")
	workUnit := flags.String("work-unit", "", "caller-facing work-unit label")
	evidenceGoal := flags.String("evidence-goal", "", "stable runtime evidence objective")
	maxAttempts := flags.Int("max-attempts", 0, "bounded attempts for a new objective")
	maxChangedLines := flags.Int("max-changed-lines", 0, "bounded changed lines for a new objective")
	outcome := flags.String("outcome", "", "failed, interrupted, or passed")
	evidenceRevision := flags.String("evidence-revision", "", "native evidence revision")
	diagnosis := flags.String("diagnosis", "", "proven runtime diagnosis")
	harnessDisposition := flags.String("harness-disposition", "", "reused or invalidated")
	cleanupEvidence := flags.String("cleanup-evidence", "", "bounded cleanup evidence")
	processEvidence := flags.String("process-evidence", "", "bounded process evidence")
	expectedBindingRevision := flags.String("expected-binding-revision", "", "exact populated binding revision for atomic remediation")
	successorLineage := flags.String("successor-lineage", "", "approved compact recovery successor lineage")
	remediatesEvidenceRevision := flags.String("remediates-evidence-revision", "", "failed evidence revision repaired by the successor")
	reason := flags.String("reason", "", "explicit objective reset reason")
	actor := flags.String("actor", "", "explicit reset actor")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected sdd-attempt argument %q", flags.Arg(0))
	}
	if strings.TrimSpace(*cwd) == "" {
		return errors.New("sdd-attempt requires --cwd")
	}
	if strings.TrimSpace(*change) == "" {
		return errors.New("sdd-attempt requires --change")
	}

	store, err := sddstatus.OpenRuntimeStore(ctx, *cwd, *change)
	if err != nil {
		return fmt.Errorf("open native SDD runtime authority: %w", err)
	}
	var status sddstatus.RuntimeStatus
	switch operation {
	case "status":
		status, err = store.Status()
	case "begin":
		if missing := missingSDDAttemptFlags(args[1:], "expected-revision", "request-id", "work-unit", "evidence-goal"); len(missing) != 0 {
			return fmt.Errorf("sdd-attempt begin requires %s", strings.Join(missing, ", "))
		}
		status, err = store.Begin(ctx, sddstatus.BeginAttemptRequest{
			ExpectedRevision: *expected, RequestID: *requestID, WorkUnit: *workUnit, EvidenceGoal: *evidenceGoal,
			MaxAttempts: *maxAttempts, MaxChangedLines: *maxChangedLines,
		})
	case "finish":
		if missing := missingSDDAttemptFlags(args[1:], "expected-revision", "request-id", "outcome", "evidence-revision", "diagnosis", "harness-disposition", "cleanup-evidence", "process-evidence"); len(missing) != 0 {
			return fmt.Errorf("sdd-attempt finish requires %s", strings.Join(missing, ", "))
		}
		remediationFlags := presentSDDAttemptFlags(args[1:], "expected-binding-revision", "successor-lineage", "remediates-evidence-revision")
		if remediationFlags != 0 && remediationFlags != 3 {
			return errors.New("remediation successor requires --expected-binding-revision, --successor-lineage, and --remediates-evidence-revision together")
		}
		status, err = store.Finish(ctx, sddstatus.FinishAttemptRequest{
			ExpectedRevision: *expected, RequestID: *requestID, Outcome: sddstatus.AttemptOutcome(*outcome),
			EvidenceRevision: *evidenceRevision, Diagnosis: *diagnosis,
			HarnessDisposition: sddstatus.HarnessDisposition(*harnessDisposition),
			CleanupEvidence:    *cleanupEvidence, ProcessEvidence: *processEvidence,
			ExpectedBindingRevision: *expectedBindingRevision, SuccessorLineageID: *successorLineage,
			RemediatesEvidenceRevision: *remediatesEvidenceRevision,
		})
	case "reset":
		if missing := missingSDDAttemptFlags(args[1:], "expected-revision", "request-id", "reason", "actor"); len(missing) != 0 {
			return fmt.Errorf("sdd-attempt reset requires %s", strings.Join(missing, ", "))
		}
		status, err = store.Reset(ctx, sddstatus.ResetObjectiveRequest{
			ExpectedRevision: *expected, RequestID: *requestID, Reason: *reason, Actor: *actor,
		})
	}
	if err != nil {
		return fmt.Errorf("sdd-attempt %s: %w", operation, err)
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(status)
}

func validateSDDAttemptOperationFlags(operation string, args []string) error {
	allowed := map[string]bool{"cwd": true, "change": true}
	for _, name := range map[string][]string{
		"begin":  {"expected-revision", "request-id", "work-unit", "evidence-goal", "max-attempts", "max-changed-lines"},
		"finish": {"expected-revision", "request-id", "outcome", "evidence-revision", "diagnosis", "harness-disposition", "cleanup-evidence", "process-evidence", "expected-binding-revision", "successor-lineage", "remediates-evidence-revision"},
		"reset":  {"expected-revision", "request-id", "reason", "actor"},
	}[operation] {
		allowed[name] = true
	}
	for index := 0; index < len(args); index++ {
		argument := args[index]
		if !strings.HasPrefix(argument, "-") || argument == "-" {
			continue
		}
		if !strings.HasPrefix(argument, "--") {
			return fmt.Errorf("flag provided but not defined: %s", argument)
		}
		name := strings.TrimPrefix(argument, "--")
		hasInlineValue := false
		if separator := strings.IndexByte(name, '='); separator >= 0 {
			name = name[:separator]
			hasInlineValue = true
		}
		if !allowed[name] {
			return fmt.Errorf("flag provided but not defined: -%s", name)
		}
		if !hasInlineValue && index+1 < len(args) {
			index++
		}
	}
	return nil
}

func missingSDDAttemptFlags(args []string, names ...string) []string {
	present := make(map[string]bool, len(names))
	for _, argument := range args {
		for _, name := range names {
			if argument == "--"+name || strings.HasPrefix(argument, "--"+name+"=") {
				present[name] = true
			}
		}
	}
	missing := make([]string, 0, len(names))
	for _, name := range names {
		if !present[name] {
			missing = append(missing, "--"+name)
		}
	}
	return missing
}

func presentSDDAttemptFlags(args []string, names ...string) int {
	present := len(names) - len(missingSDDAttemptFlags(args, names...))
	return present
}

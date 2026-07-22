package sddstatus

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/gentleman-programming/gentle-ai/internal/reviewtransaction"
)

const (
	RuntimeStatusSchema               = "gentle-ai.sdd-runtime-status/v1"
	runtimeRecordSchema               = "gentle-ai.sdd-runtime-record/v1"
	runtimeObjectiveSchema            = "gentle-ai.sdd-runtime-objective/v1"
	runtimeObjectiveSchemaV2          = "gentle-ai.sdd-runtime-objective/v2"
	DefaultRuntimeAttemptLimit        = 2
	DefaultRuntimeChangedLines        = 200
	maximumRuntimeAttemptLimit        = 100
	maximumRuntimeChangedLines        = 1_000_000
	maximumRuntimeRecordBytes         = 1 << 20
	maximumRuntimeChainRecords        = 10_000
	RuntimeActionBegin                = "begin"
	RuntimeActionFinish               = "finish"
	RuntimeActionReset                = "reset"
	RuntimeActionComplete             = "complete"
	runtimeOperationBegin             = "attempt/begin"
	runtimeOperationFinish            = "attempt/finish"
	runtimeOperationFinishRemediation = "attempt/finish-remediation"
	runtimeOperationReset             = "objective/reset"
	runtimeOperationBind              = "binding/set"
)

var (
	ErrRuntimeRevisionConflict             = errors.New("SDD runtime ledger revision conflict")
	ErrRuntimeConcurrentUpdate             = errors.New("SDD runtime ledger is concurrently updated")
	ErrRuntimeRequestConflict              = errors.New("SDD runtime request identifier was reused with different inputs")
	ErrRuntimeBudgetExhausted              = errors.New("SDD runtime objective budget is exhausted")
	ErrRuntimeAttemptActive                = errors.New("SDD runtime objective already has an active attempt")
	ErrRuntimeNoActiveAttempt              = errors.New("SDD runtime objective has no active attempt")
	ErrRuntimeObjectiveChange              = errors.New("SDD runtime objective changed without an explicit reset")
	ErrRuntimeObjectiveDone                = errors.New("SDD runtime objective is complete")
	ErrRuntimeNoObjective                  = errors.New("SDD runtime ledger has no objective to reset")
	ErrRuntimeResetNotAllowed              = errors.New("SDD runtime objective reset requires decision-required or complete state")
	ErrRuntimeRemediationSuccessorRequired = errors.New("a bound passing SDD runtime attempt requires an atomic approved recovery successor")
	ErrBindingRevisionConflict             = errors.New("SDD review binding revision conflict")

	runtimeRequestIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)
	runtimeRevisionPattern  = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
	runtimeGitTreePattern   = regexp.MustCompile(`^[a-f0-9]{40}(?:[a-f0-9]{24})?$`)

	runtimePublishRecord                     = reviewtransaction.PublishFileNoReplace
	runtimeReplaceHead                       = reviewtransaction.ReplaceFileAtomic
	runtimeSyncDirectory                     = reviewtransaction.SyncReviewDirectory
	runtimeRemediationFinalAuthorizationHook = func() {}
)

// RuntimeRevisionConflictError is a deterministic pre-publication CAS denial.
type RuntimeRevisionConflictError struct {
	Expected string
	Current  string
}

func (err *RuntimeRevisionConflictError) Error() string {
	return fmt.Sprintf("%v: expected %q, current %q", ErrRuntimeRevisionConflict, err.Expected, err.Current)
}

func (err *RuntimeRevisionConflictError) Unwrap() error { return ErrRuntimeRevisionConflict }

// BindingRevisionConflictError reports a deterministic binding-only CAS
// denial. Binding revisions deliberately use a separate namespace from the
// runtime ledger HEAD so callers cannot accidentally submit an authority or
// ledger revision as the expected binding token.
type BindingRevisionConflictError struct {
	Expected string
	Current  string
}

func (err *BindingRevisionConflictError) Error() string {
	return fmt.Sprintf("%v: expected %q, current %q", ErrBindingRevisionConflict, err.Expected, err.Current)
}

func (err *BindingRevisionConflictError) Unwrap() error { return ErrBindingRevisionConflict }

// RuntimePublicationError reports that HEAD was atomically replaced but its
// directory durability could not be confirmed. The exact request is safe to
// replay; replay reopens the immutable chain and repeats directory fsync.
type RuntimePublicationError struct {
	Revision  string
	Committed bool
	Cause     error
}

func (err *RuntimePublicationError) Error() string {
	return fmt.Sprintf("SDD runtime ledger publication for %s requires exact replay: %v", err.Revision, err.Cause)
}

func (err *RuntimePublicationError) Unwrap() error { return err.Cause }

type AttemptOutcome string

const (
	AttemptRunning     AttemptOutcome = "running"
	AttemptFailed      AttemptOutcome = "failed"
	AttemptInterrupted AttemptOutcome = "interrupted"
	AttemptPassed      AttemptOutcome = "passed"
)

type HarnessDisposition string

const (
	HarnessReused      HarnessDisposition = "reused"
	HarnessInvalidated HarnessDisposition = "invalidated"
)

type RuntimeObjective struct {
	ID                       string `json:"id"`
	Generation               int    `json:"generation"`
	WorkUnit                 string `json:"work_unit"`
	EvidenceGoal             string `json:"evidence_goal"`
	InitialCandidateIdentity string `json:"initial_candidate_identity"`
	InitialCandidateTree     string `json:"initial_candidate_tree"`
	MaxAttempts              int    `json:"max_attempts"`
	MaxChangedLines          int    `json:"max_changed_lines"`
}

type RuntimeAttempt struct {
	Ordinal                    int                `json:"ordinal"`
	ObjectiveID                string             `json:"objective_id"`
	ObjectiveGeneration        int                `json:"objective_generation"`
	WorkUnit                   string             `json:"work_unit"`
	BeginCandidateIdentity     string             `json:"begin_candidate_identity"`
	BeginCandidateTree         string             `json:"begin_candidate_tree"`
	FinishCandidateIdentity    string             `json:"finish_candidate_identity,omitempty"`
	FinishCandidateTree        string             `json:"finish_candidate_tree,omitempty"`
	Outcome                    AttemptOutcome     `json:"outcome"`
	ChangedLines               int                `json:"changed_lines"`
	EvidenceRevision           string             `json:"evidence_revision,omitempty"`
	Diagnosis                  string             `json:"diagnosis,omitempty"`
	HarnessDisposition         HarnessDisposition `json:"harness_disposition,omitempty"`
	CleanupEvidence            string             `json:"cleanup_evidence,omitempty"`
	ProcessEvidence            string             `json:"process_evidence,omitempty"`
	RemediatesEvidenceRevision string             `json:"remediates_evidence_revision,omitempty"`
	ChangedLineBudgetExceeded  bool               `json:"changed_line_budget_exceeded,omitempty"`
}

type RuntimeReset struct {
	Revision               string `json:"revision"`
	PreviousObjectiveID    string `json:"previous_objective_id"`
	PreviousGeneration     int    `json:"previous_generation"`
	ResetCandidateIdentity string `json:"reset_candidate_identity"`
	ResetCandidateTree     string `json:"reset_candidate_tree"`
	Reason                 string `json:"reason"`
	Actor                  string `json:"actor"`
}

type RuntimeStatus struct {
	Schema                 string            `json:"schema"`
	Change                 string            `json:"change"`
	Revision               string            `json:"revision"`
	Objective              *RuntimeObjective `json:"objective,omitempty"`
	ActiveAttempt          *RuntimeAttempt   `json:"active_attempt,omitempty"`
	Attempts               []RuntimeAttempt  `json:"attempts"`
	ObjectiveGeneration    int               `json:"objective_generation"`
	NextOrdinal            int               `json:"next_ordinal"`
	CumulativeAttempts     int               `json:"cumulative_attempts"`
	CumulativeChangedLines int               `json:"cumulative_changed_lines"`
	LifetimeAttempts       int               `json:"lifetime_attempts"`
	LifetimeChangedLines   int               `json:"lifetime_changed_lines"`
	EvidenceRevision       string            `json:"evidence_revision"`
	DecisionRequired       bool              `json:"decision_required"`
	Complete               bool              `json:"complete"`
	NextAction             string            `json:"next_action"`
	LastReset              *RuntimeReset     `json:"last_reset,omitempty"`
	BindingRevision        string            `json:"binding_revision"`
	Binding                *ReviewBinding    `json:"binding,omitempty"`
}

type BeginAttemptRequest struct {
	ExpectedRevision string `json:"expected_revision"`
	RequestID        string `json:"request_id"`
	WorkUnit         string `json:"work_unit"`
	EvidenceGoal     string `json:"evidence_goal"`
	MaxAttempts      int    `json:"max_attempts"`
	MaxChangedLines  int    `json:"max_changed_lines"`
}

type FinishAttemptRequest struct {
	ExpectedRevision           string             `json:"expected_revision"`
	RequestID                  string             `json:"request_id"`
	Outcome                    AttemptOutcome     `json:"outcome"`
	EvidenceRevision           string             `json:"evidence_revision"`
	Diagnosis                  string             `json:"diagnosis"`
	HarnessDisposition         HarnessDisposition `json:"harness_disposition"`
	CleanupEvidence            string             `json:"cleanup_evidence"`
	ProcessEvidence            string             `json:"process_evidence"`
	ExpectedBindingRevision    string             `json:"expected_binding_revision,omitempty"`
	SuccessorLineageID         string             `json:"successor_lineage_id,omitempty"`
	RemediatesEvidenceRevision string             `json:"remediates_evidence_revision,omitempty"`
}

type ResetObjectiveRequest struct {
	ExpectedRevision string `json:"expected_revision"`
	RequestID        string `json:"request_id"`
	Reason           string `json:"reason"`
	Actor            string `json:"actor"`
}

// BindReviewRequest performs a binding-only compare-and-swap. The expected
// value is the current ReviewBinding.Revision, not the runtime ledger HEAD and
// not the review authority revision.
type BindReviewRequest struct {
	ExpectedBindingRevision string `json:"expected_binding_revision"`
	RequestID               string `json:"request_id"`
	LineageID               string `json:"lineage_id"`
}

// RuntimeStore is one provider-owned immutable chain for one SDD change. Its
// directory is rooted in the repository Git common-dir, so linked worktrees
// and later processes observe the same attempt ordinals and line charges.
type RuntimeStore struct {
	Dir       string
	Repo      string
	Workspace string
	Change    string
	commonDir string
}

type runtimeRecord struct {
	Schema           string               `json:"schema"`
	Change           string               `json:"change"`
	PreviousRevision string               `json:"previous_revision"`
	Operation        string               `json:"operation"`
	RequestID        string               `json:"request_id"`
	RequestDigest    string               `json:"request_digest"`
	Begin            *runtimeBeginEvent   `json:"begin,omitempty"`
	Finish           *runtimeFinishEvent  `json:"finish,omitempty"`
	Reset            *runtimeResetEvent   `json:"reset,omitempty"`
	Binding          *runtimeBindingEvent `json:"binding,omitempty"`
}

type runtimeBeginEvent struct {
	ObjectiveID            string `json:"objective_id"`
	ObjectiveGeneration    int    `json:"objective_generation,omitempty"`
	WorkUnit               string `json:"work_unit"`
	EvidenceGoal           string `json:"evidence_goal"`
	MaxAttempts            int    `json:"max_attempts"`
	MaxChangedLines        int    `json:"max_changed_lines"`
	Ordinal                int    `json:"ordinal"`
	BeginCandidateIdentity string `json:"begin_candidate_identity"`
	BeginCandidateTree     string `json:"begin_candidate_tree"`
}

type runtimeResetEvent struct {
	PreviousObjectiveID    string `json:"previous_objective_id"`
	PreviousGeneration     int    `json:"previous_generation"`
	ResetCandidateIdentity string `json:"reset_candidate_identity"`
	ResetCandidateTree     string `json:"reset_candidate_tree"`
	Reason                 string `json:"reason"`
	Actor                  string `json:"actor"`
}

type runtimeFinishEvent struct {
	Ordinal                    int                `json:"ordinal"`
	FinishCandidateIdentity    string             `json:"finish_candidate_identity"`
	FinishCandidateTree        string             `json:"finish_candidate_tree"`
	Outcome                    AttemptOutcome     `json:"outcome"`
	ChangedLines               int                `json:"changed_lines"`
	EvidenceRevision           string             `json:"evidence_revision"`
	Diagnosis                  string             `json:"diagnosis"`
	HarnessDisposition         HarnessDisposition `json:"harness_disposition"`
	CleanupEvidence            string             `json:"cleanup_evidence"`
	ProcessEvidence            string             `json:"process_evidence"`
	RemediatesEvidenceRevision string             `json:"remediates_evidence_revision,omitempty"`
	ChangedLineBudgetExceeded  bool               `json:"changed_line_budget_exceeded,omitempty"`
}

type runtimeBindingEvent struct {
	ExpectedRevision string                      `json:"expected_revision"`
	Current          ReviewBinding               `json:"current"`
	LegacyImport     *runtimeLegacyBindingImport `json:"legacy_import,omitempty"`
}

type runtimeLegacyBindingImport struct {
	SourceDigest string        `json:"source_digest"`
	Binding      ReviewBinding `json:"binding"`
}

type runtimeRequestReceipt struct {
	Digest   string
	Revision string
}

type runtimeReplay struct {
	Status   RuntimeStatus
	Requests map[string]runtimeRequestReceipt
}

func OpenRuntimeStore(ctx context.Context, repo, change string) (RuntimeStore, error) {
	if !validReviewBindingChange(change) {
		return RuntimeStore{}, errors.New("invalid SDD change name")
	}
	root, err := (reviewtransaction.SnapshotBuilder{Repo: repo}).ResolveRepositoryRoot(ctx)
	if err != nil {
		return RuntimeStore{}, err
	}
	workspace, err := filepath.Abs(repo)
	if err != nil {
		return RuntimeStore{}, err
	}
	workspace, err = filepath.EvalSymlinks(workspace)
	if err != nil {
		return RuntimeStore{}, err
	}
	probe, err := reviewtransaction.CompactAuthoritativeStore(ctx, root, "sdd-runtime-probe")
	if err != nil {
		return RuntimeStore{}, err
	}
	commonDir := filepath.Dir(filepath.Dir(filepath.Dir(filepath.Dir(probe.Dir))))
	dir := filepath.Join(commonDir, "gentle-ai", "sdd-runtime", "v1", change)
	return RuntimeStore{Dir: dir, Repo: root, Workspace: workspace, Change: change, commonDir: commonDir}, nil
}

func (store RuntimeStore) Status() (RuntimeStatus, error) {
	replay, err := store.load()
	return replay.Status, err
}

func (store RuntimeStore) Begin(ctx context.Context, request BeginAttemptRequest) (RuntimeStatus, error) {
	request, err := normalizeBeginAttemptRequest(request)
	if err != nil {
		return RuntimeStatus{}, err
	}
	digest := runtimeValueHash("gentle-ai.sdd-runtime-begin-request/v1", request)
	return store.mutate(ctx, request.ExpectedRevision, request.RequestID, digest, func(replay runtimeReplay) (runtimeRecord, error) {
		status := replay.Status
		if status.ActiveAttempt != nil {
			return runtimeRecord{}, ErrRuntimeAttemptActive
		}
		if status.Complete {
			return runtimeRecord{}, ErrRuntimeObjectiveDone
		}
		if status.DecisionRequired {
			return runtimeRecord{}, ErrRuntimeBudgetExhausted
		}

		generation := status.ObjectiveGeneration + 1
		var snapshot reviewtransaction.Snapshot
		var err error
		if status.Objective != nil {
			generation = status.Objective.Generation
			if request.WorkUnit != status.Objective.WorkUnit || request.EvidenceGoal != status.Objective.EvidenceGoal ||
				request.MaxAttempts != status.Objective.MaxAttempts ||
				request.MaxChangedLines != status.Objective.MaxChangedLines {
				return runtimeRecord{}, ErrRuntimeObjectiveChange
			}
			if len(status.Attempts) == 0 {
				return runtimeRecord{}, errors.New("SDD runtime objective has no terminal candidate provenance")
			}
			last := status.Attempts[len(status.Attempts)-1]
			if last.ObjectiveID != status.Objective.ID || last.Outcome == AttemptRunning ||
				last.FinishCandidateIdentity == "" || last.FinishCandidateTree == "" {
				return runtimeRecord{}, errors.New("SDD runtime objective has invalid terminal candidate provenance")
			}
			intended, discoverErr := (reviewtransaction.SnapshotBuilder{Repo: store.Repo}).DiscoverIntendedUntracked(ctx)
			if discoverErr != nil {
				return runtimeRecord{}, fmt.Errorf("discover SDD runtime intended-untracked paths before launch: %w", discoverErr)
			}
			snapshot, err = (reviewtransaction.SnapshotBuilder{Repo: store.Repo}).Build(ctx, reviewtransaction.Target{
				Kind: reviewtransaction.TargetBaseWorkspaceOverlay, BaseRef: last.BeginCandidateTree,
				Projection: reviewtransaction.ProjectionWorkspace, IntendedUntracked: intended,
			})
			if err == nil && (snapshot.Identity != last.FinishCandidateIdentity || snapshot.CandidateTree != last.FinishCandidateTree) {
				return runtimeRecord{}, ErrRuntimeObjectiveChange
			}
		} else {
			snapshot, err = captureRuntimeCandidate(ctx, store.Repo)
		}
		if err != nil {
			return runtimeRecord{}, fmt.Errorf("capture SDD runtime candidate before launch: %w", err)
		}
		objectiveID := runtimeObjectiveID(store.Change, request.WorkUnit, request.EvidenceGoal, snapshot.Identity, generation)
		if status.Objective != nil {
			objectiveID = status.Objective.ID
		}
		if status.CumulativeAttempts >= request.MaxAttempts || status.CumulativeChangedLines >= request.MaxChangedLines {
			return runtimeRecord{}, ErrRuntimeBudgetExhausted
		}
		event := &runtimeBeginEvent{
			ObjectiveID: objectiveID, ObjectiveGeneration: generation, WorkUnit: request.WorkUnit, EvidenceGoal: request.EvidenceGoal,
			MaxAttempts: request.MaxAttempts, MaxChangedLines: request.MaxChangedLines,
			Ordinal: status.NextOrdinal, BeginCandidateIdentity: snapshot.Identity, BeginCandidateTree: snapshot.CandidateTree,
		}
		return runtimeRecord{Operation: runtimeOperationBegin, Begin: event}, nil
	})
}

func (store RuntimeStore) Finish(ctx context.Context, request FinishAttemptRequest) (RuntimeStatus, error) {
	request, err := normalizeFinishAttemptRequest(request)
	if err != nil {
		return RuntimeStatus{}, err
	}
	digest := runtimeValueHash("gentle-ai.sdd-runtime-finish-request/v1", request)
	return store.mutate(ctx, request.ExpectedRevision, request.RequestID, digest, func(replay runtimeReplay) (runtimeRecord, error) {
		status := replay.Status
		active := status.ActiveAttempt
		if active == nil {
			return runtimeRecord{}, ErrRuntimeNoActiveAttempt
		}
		remediation := finishRequestsRemediation(request)
		currentBinding := status.Binding
		var legacyBinding *ReviewBinding
		var legacyDigest string
		if request.Outcome == AttemptPassed && currentBinding == nil {
			legacyBinding, legacyDigest, err = store.readLegacyBinding()
			if err != nil {
				return runtimeRecord{}, fmt.Errorf("read legacy SDD review binding for remediation: %w", err)
			}
			currentBinding = legacyBinding
		}
		if remediation {
			if currentBinding == nil {
				return runtimeRecord{}, errors.New("atomic SDD remediation successor requires a populated native binding")
			}
			if currentBinding.Revision != request.ExpectedBindingRevision {
				return runtimeRecord{}, &BindingRevisionConflictError{Expected: request.ExpectedBindingRevision, Current: currentBinding.Revision}
			}
			if status.EvidenceRevision != "" && status.EvidenceRevision != request.RemediatesEvidenceRevision {
				return runtimeRecord{}, fmt.Errorf("failed evidence revision %q does not match native runtime evidence %q", request.RemediatesEvidenceRevision, status.EvidenceRevision)
			}
		}
		intended, err := (reviewtransaction.SnapshotBuilder{Repo: store.Repo}).DiscoverIntendedUntracked(ctx)
		if err != nil {
			return runtimeRecord{}, fmt.Errorf("discover SDD runtime intended-untracked paths: %w", err)
		}
		snapshot, err := (reviewtransaction.SnapshotBuilder{Repo: store.Repo}).Build(ctx, reviewtransaction.Target{
			Kind: reviewtransaction.TargetBaseWorkspaceOverlay, BaseRef: active.BeginCandidateTree,
			Projection: reviewtransaction.ProjectionWorkspace, IntendedUntracked: intended,
		})
		if err != nil {
			return runtimeRecord{}, fmt.Errorf("capture SDD runtime candidate after attempt: %w", err)
		}
		changedLines, err := (reviewtransaction.SnapshotBuilder{Repo: store.Repo}).ChangedLines(ctx, snapshot)
		if err != nil {
			return runtimeRecord{}, fmt.Errorf("measure native SDD runtime line charge: %w", err)
		}
		if request.Outcome == AttemptPassed && currentBinding != nil && !remediation {
			if snapshot.CandidateTree != active.BeginCandidateTree {
				return runtimeRecord{}, ErrRuntimeRemediationSuccessorRequired
			}
			if currentBinding.Change != store.Change {
				return runtimeRecord{}, errors.New("bound SDD review change does not match the runtime objective")
			}
			if validateErr := validateRuntimeBoundCandidate(ctx, store.Repo, *currentBinding, snapshot.CandidateTree); validateErr != nil {
				return runtimeRecord{}, fmt.Errorf("validate unchanged bound SDD candidate: %w", validateErr)
			}
		}
		event := &runtimeFinishEvent{
			Ordinal: active.Ordinal, FinishCandidateIdentity: snapshot.Identity, FinishCandidateTree: snapshot.CandidateTree,
			Outcome: request.Outcome, ChangedLines: changedLines, EvidenceRevision: request.EvidenceRevision,
			Diagnosis: request.Diagnosis, HarnessDisposition: request.HarnessDisposition,
			CleanupEvidence: request.CleanupEvidence, ProcessEvidence: request.ProcessEvidence,
			RemediatesEvidenceRevision: request.RemediatesEvidenceRevision,
			ChangedLineBudgetExceeded:  status.CumulativeChangedLines+changedLines > status.Objective.MaxChangedLines,
		}
		if remediation {
			prepared, prepareErr := prepareApprovedRuntimeSuccessorBinding(ctx, store.Repo, store.Workspace, store.Change, request.SuccessorLineageID)
			if prepareErr != nil {
				return runtimeRecord{}, prepareErr
			}
			if relationErr := validateRuntimeRemediationSuccessor(ctx, store.Repo, *currentBinding, prepared); relationErr != nil {
				return runtimeRecord{}, relationErr
			}
			runtimeRemediationFinalAuthorizationHook()
			finalPrepared, finalPrepareErr := prepareApprovedRuntimeSuccessorBinding(ctx, store.Repo, store.Workspace, store.Change, request.SuccessorLineageID)
			if finalPrepareErr != nil {
				return runtimeRecord{}, fmt.Errorf("approved SDD remediation successor changed before native commit: %w", finalPrepareErr)
			}
			if finalPrepared.Revision != prepared.Revision {
				return runtimeRecord{}, errors.New("approved SDD remediation successor changed before native commit")
			}
			if relationErr := validateRuntimeRemediationSuccessor(ctx, store.Repo, *currentBinding, finalPrepared); relationErr != nil {
				return runtimeRecord{}, relationErr
			}
			if finalPrepared.GateContext.CandidateTree != snapshot.CandidateTree {
				return runtimeRecord{}, errors.New("approved SDD remediation successor does not bind the natively charged candidate")
			}
			prepared = finalPrepared
			bindingEvent := &runtimeBindingEvent{ExpectedRevision: request.ExpectedBindingRevision, Current: prepared}
			if legacyBinding != nil {
				finalLegacy, finalDigest, finalErr := store.readLegacyBinding()
				if finalErr != nil || finalLegacy == nil || finalDigest != legacyDigest {
					return runtimeRecord{}, errors.New("legacy SDD review binding changed before atomic remediation import")
				}
				bindingEvent.LegacyImport = &runtimeLegacyBindingImport{SourceDigest: legacyDigest, Binding: *legacyBinding}
			}
			return runtimeRecord{
				Operation: runtimeOperationFinishRemediation, Finish: event,
				Binding: bindingEvent,
			}, nil
		}
		return runtimeRecord{Operation: runtimeOperationFinish, Finish: event}, nil
	})
}

// Reset closes a terminal objective scope without deleting its immutable
// attempts. The next Begin receives a new generation and budget while global
// ordinals and lifetime charges continue monotonically.
func (store RuntimeStore) Reset(ctx context.Context, request ResetObjectiveRequest) (RuntimeStatus, error) {
	request, err := normalizeResetObjectiveRequest(request)
	if err != nil {
		return RuntimeStatus{}, err
	}
	digest := runtimeValueHash("gentle-ai.sdd-runtime-reset-request/v1", request)
	return store.mutate(ctx, request.ExpectedRevision, request.RequestID, digest, func(replay runtimeReplay) (runtimeRecord, error) {
		status := replay.Status
		if status.ActiveAttempt != nil {
			return runtimeRecord{}, ErrRuntimeAttemptActive
		}
		if status.Objective == nil {
			return runtimeRecord{}, ErrRuntimeNoObjective
		}
		if !status.DecisionRequired && !status.Complete {
			return runtimeRecord{}, ErrRuntimeResetNotAllowed
		}
		snapshot, err := captureRuntimeCandidate(ctx, store.Repo)
		if err != nil {
			return runtimeRecord{}, fmt.Errorf("capture SDD runtime candidate at objective reset: %w", err)
		}
		return runtimeRecord{Operation: runtimeOperationReset, Reset: &runtimeResetEvent{
			PreviousObjectiveID: status.Objective.ID, PreviousGeneration: status.Objective.Generation,
			ResetCandidateIdentity: snapshot.Identity, ResetCandidateTree: snapshot.CandidateTree,
			Reason: request.Reason, Actor: request.Actor,
		}}, nil
	})
}

// bindPreparedReview imports a legacy binding at most once and replaces the
// effective binding in the same immutable runtime chain. The callback is run
// while the runtime lock is held so the approved authority is revalidated
// immediately before the single HEAD compare-and-swap.
func (store RuntimeStore) bindPreparedReview(
	ctx context.Context,
	request BindReviewRequest,
	prepare func() (ReviewBinding, error),
) (RuntimeStatus, error) {
	request, err := normalizeBindReviewRequest(request)
	if err != nil {
		return RuntimeStatus{}, err
	}
	requestDigest := runtimeValueHash("gentle-ai.sdd-runtime-bind-request/v1", request)
	if err := ctx.Err(); err != nil {
		return RuntimeStatus{}, err
	}
	if err := store.ensureDirectories(); err != nil {
		return RuntimeStatus{}, err
	}
	lock, err := reviewtransaction.AcquireAuthorityFileLock(filepath.Join(store.Dir, "LOCK"))
	if err != nil {
		if errors.Is(err, reviewtransaction.ErrConcurrentUpdate) {
			return RuntimeStatus{}, fmt.Errorf("%w: %v", ErrRuntimeConcurrentUpdate, err)
		}
		return RuntimeStatus{}, err
	}
	defer lock.Release()

	replay, err := store.load()
	if err != nil {
		return RuntimeStatus{}, err
	}
	if receipt, ok := replay.Requests[request.RequestID]; ok {
		if receipt.Digest != requestDigest {
			return RuntimeStatus{}, ErrRuntimeRequestConflict
		}
		if err := store.syncReplay(); err != nil {
			return RuntimeStatus{}, &RuntimePublicationError{Revision: receipt.Revision, Committed: true, Cause: err}
		}
		return replay.Status, nil
	}

	var legacy *ReviewBinding
	var legacyDigest string
	if replay.Status.Binding == nil {
		legacy, legacyDigest, err = store.readLegacyBinding()
		if err != nil {
			return RuntimeStatus{}, fmt.Errorf("read legacy SDD review binding: %w", err)
		}
	}

	prepared, err := prepare()
	if err != nil {
		return RuntimeStatus{}, err
	}
	prepared, err = validatePreparedRuntimeBinding(prepared, store.Change, request.LineageID)
	if err != nil {
		return RuntimeStatus{}, err
	}
	if replay.Status.Binding == nil {
		finalLegacy, finalDigest, finalErr := store.readLegacyBinding()
		if finalErr != nil {
			return RuntimeStatus{}, fmt.Errorf("reopen legacy SDD review binding: %w", finalErr)
		}
		if (legacy == nil) != (finalLegacy == nil) || legacyDigest != finalDigest {
			return RuntimeStatus{}, errors.New("legacy SDD review binding changed before native import")
		}
	}

	// A populated native binding is authoritative. Identical-candidate retries
	// are no-ops even when the caller repeats the original expected revision;
	// this preserves the existing idempotent bind contract without another
	// mutable request journal.
	if replay.Status.Binding != nil {
		if replay.Status.Binding.Revision == prepared.Revision {
			if err := store.syncReplay(); err != nil {
				return RuntimeStatus{}, &RuntimePublicationError{Revision: replay.Status.Revision, Committed: true, Cause: err}
			}
			return replay.Status, nil
		}
		if request.ExpectedBindingRevision != "" && !runtimeRevisionPattern.MatchString(request.ExpectedBindingRevision) {
			return RuntimeStatus{}, &BindingRevisionConflictError{Expected: request.ExpectedBindingRevision, Current: replay.Status.BindingRevision}
		}
		if replay.Status.BindingRevision != request.ExpectedBindingRevision {
			return RuntimeStatus{}, &BindingRevisionConflictError{Expected: request.ExpectedBindingRevision, Current: replay.Status.BindingRevision}
		}
	} else {
		current := ""
		if legacy != nil {
			current = legacy.Revision
		}
		if request.ExpectedBindingRevision != "" && !runtimeRevisionPattern.MatchString(request.ExpectedBindingRevision) {
			return RuntimeStatus{}, &BindingRevisionConflictError{Expected: request.ExpectedBindingRevision, Current: current}
		}
		if current != request.ExpectedBindingRevision {
			return RuntimeStatus{}, &BindingRevisionConflictError{Expected: request.ExpectedBindingRevision, Current: current}
		}
	}

	event := &runtimeBindingEvent{ExpectedRevision: request.ExpectedBindingRevision, Current: prepared}
	if replay.Status.Binding == nil {
		if legacy != nil {
			event.LegacyImport = &runtimeLegacyBindingImport{SourceDigest: legacyDigest, Binding: *legacy}
		}
	}
	record := runtimeRecord{
		Schema: runtimeRecordSchema, Change: store.Change, PreviousRevision: replay.Status.Revision,
		Operation: runtimeOperationBind, RequestID: request.RequestID, RequestDigest: requestDigest, Binding: event,
	}
	if err := validateRuntimeRecordShape(record); err != nil {
		return RuntimeStatus{}, err
	}
	return store.commitRecordLocked(record)
}

func (store RuntimeStore) mutate(
	ctx context.Context,
	expected, requestID, requestDigest string,
	build func(runtimeReplay) (runtimeRecord, error),
) (RuntimeStatus, error) {
	if err := ctx.Err(); err != nil {
		return RuntimeStatus{}, err
	}
	if err := store.ensureDirectories(); err != nil {
		return RuntimeStatus{}, err
	}
	lock, err := reviewtransaction.AcquireAuthorityFileLock(filepath.Join(store.Dir, "LOCK"))
	if err != nil {
		if errors.Is(err, reviewtransaction.ErrConcurrentUpdate) {
			return RuntimeStatus{}, fmt.Errorf("%w: %v", ErrRuntimeConcurrentUpdate, err)
		}
		return RuntimeStatus{}, err
	}
	defer lock.Release()

	replay, err := store.load()
	if err != nil {
		return RuntimeStatus{}, err
	}
	if receipt, ok := replay.Requests[requestID]; ok {
		if receipt.Digest != requestDigest {
			return RuntimeStatus{}, ErrRuntimeRequestConflict
		}
		if err := store.syncReplay(); err != nil {
			return RuntimeStatus{}, &RuntimePublicationError{Revision: receipt.Revision, Committed: true, Cause: err}
		}
		return replay.Status, nil
	}
	if replay.Status.Revision != expected {
		return RuntimeStatus{}, &RuntimeRevisionConflictError{Expected: expected, Current: replay.Status.Revision}
	}
	record, err := build(replay)
	if err != nil {
		return RuntimeStatus{}, err
	}
	record.Schema = runtimeRecordSchema
	record.Change = store.Change
	record.PreviousRevision = expected
	record.RequestID = requestID
	record.RequestDigest = requestDigest
	if err := validateRuntimeRecordShape(record); err != nil {
		return RuntimeStatus{}, err
	}
	return store.commitRecordLocked(record)
}

func (store RuntimeStore) commitRecordLocked(record runtimeRecord) (RuntimeStatus, error) {
	revision, payload, err := runtimeRecordRevision(record)
	if err != nil {
		return RuntimeStatus{}, err
	}
	if err := store.publishRecord(revision, payload); err != nil {
		return RuntimeStatus{}, err
	}
	if err := store.publishHead(revision); err != nil {
		return RuntimeStatus{}, err
	}
	if err := runtimeSyncDirectory(store.Dir); err != nil {
		return RuntimeStatus{}, &RuntimePublicationError{Revision: revision, Committed: true, Cause: fmt.Errorf("sync SDD runtime HEAD directory: %w", err)}
	}

	committed, err := store.load()
	if err != nil {
		return RuntimeStatus{}, &RuntimePublicationError{Revision: revision, Committed: true, Cause: fmt.Errorf("replay committed SDD runtime HEAD: %w", err)}
	}
	if committed.Status.Revision != revision {
		return RuntimeStatus{}, &RuntimePublicationError{Revision: revision, Committed: true, Cause: errors.New("committed SDD runtime HEAD did not replay to candidate revision")}
	}
	return committed.Status, nil
}

func (store RuntimeStore) load() (runtimeReplay, error) {
	replay := runtimeReplay{
		Status: RuntimeStatus{
			Schema: RuntimeStatusSchema, Change: store.Change, Attempts: []RuntimeAttempt{},
			NextOrdinal: 1, NextAction: RuntimeActionBegin,
		},
		Requests: map[string]runtimeRequestReceipt{},
	}
	head, exists, err := readRuntimeHead(filepath.Join(store.Dir, "HEAD"))
	if err != nil || !exists {
		return replay, err
	}

	type revisionRecord struct {
		revision string
		record   runtimeRecord
	}
	reverse := make([]revisionRecord, 0, 16)
	seen := map[string]struct{}{}
	for revision := head; revision != ""; {
		if len(reverse) >= maximumRuntimeChainRecords {
			return runtimeReplay{}, errors.New("SDD runtime chain exceeds the bounded record count")
		}
		if _, duplicate := seen[revision]; duplicate {
			return runtimeReplay{}, errors.New("SDD runtime record predecessor cycle detected")
		}
		seen[revision] = struct{}{}
		record, err := store.loadRecord(revision)
		if err != nil {
			return runtimeReplay{}, err
		}
		reverse = append(reverse, revisionRecord{revision: revision, record: record})
		revision = record.PreviousRevision
	}
	for index := len(reverse) - 1; index >= 0; index-- {
		entry := reverse[index]
		if err := applyRuntimeRecord(&replay, entry.revision, entry.record); err != nil {
			return runtimeReplay{}, fmt.Errorf("replay SDD runtime revision %s: %w", entry.revision, err)
		}
	}
	if replay.Status.Revision != head {
		return runtimeReplay{}, errors.New("SDD runtime HEAD does not equal replayed revision")
	}
	return replay, nil
}

func applyRuntimeRecord(replay *runtimeReplay, revision string, record runtimeRecord) error {
	if record.PreviousRevision != replay.Status.Revision {
		return errors.New("record predecessor does not equal replay state")
	}
	if _, duplicate := replay.Requests[record.RequestID]; duplicate {
		return errors.New("duplicate runtime request identifier")
	}
	if err := validateRuntimeRecordShape(record); err != nil {
		return err
	}
	switch record.Operation {
	case runtimeOperationBegin:
		event := record.Begin
		generation := event.ObjectiveGeneration
		if generation == 0 {
			generation = replay.Status.ObjectiveGeneration + 1
			if replay.Status.Objective != nil {
				generation = replay.Status.Objective.Generation
			}
		}
		if replay.Status.ActiveAttempt != nil || replay.Status.Complete || replay.Status.DecisionRequired {
			return errors.New("begin record is not a valid successor")
		}
		if replay.Status.Objective == nil {
			expectedObjectiveID := runtimeObjectiveID(record.Change, event.WorkUnit, event.EvidenceGoal, event.BeginCandidateIdentity, generation)
			if event.ObjectiveGeneration == 0 {
				expectedObjectiveID = legacyRuntimeObjectiveID(record.Change, event.EvidenceGoal)
			}
			legacyGeneratedID := runtimeObjectiveIDV1(record.Change, event.EvidenceGoal, event.BeginCandidateIdentity, generation)
			validObjectiveID := event.ObjectiveID == expectedObjectiveID ||
				event.ObjectiveGeneration != 0 && event.ObjectiveID == legacyGeneratedID
			if event.Ordinal != replay.Status.NextOrdinal || generation != replay.Status.ObjectiveGeneration+1 || !validObjectiveID {
				return errors.New("initial objective identity or ordinal is invalid")
			}
			replay.Status.Objective = &RuntimeObjective{
				ID: event.ObjectiveID, Generation: generation, WorkUnit: event.WorkUnit, EvidenceGoal: event.EvidenceGoal,
				InitialCandidateIdentity: event.BeginCandidateIdentity, InitialCandidateTree: event.BeginCandidateTree,
				MaxAttempts: event.MaxAttempts, MaxChangedLines: event.MaxChangedLines,
			}
			replay.Status.ObjectiveGeneration = generation
		} else {
			objective := replay.Status.Objective
			if event.ObjectiveID != objective.ID || generation != objective.Generation || event.EvidenceGoal != objective.EvidenceGoal ||
				event.WorkUnit != objective.WorkUnit ||
				event.MaxAttempts != objective.MaxAttempts || event.MaxChangedLines != objective.MaxChangedLines ||
				event.Ordinal != replay.Status.NextOrdinal {
				return errors.New("begin record changes the active objective or ordinal")
			}
			if len(replay.Status.Attempts) == 0 ||
				event.BeginCandidateTree != replay.Status.Attempts[len(replay.Status.Attempts)-1].FinishCandidateTree {
				return errors.New("begin record does not continue the terminal candidate")
			}
		}
		if replay.Status.CumulativeAttempts >= event.MaxAttempts || replay.Status.CumulativeChangedLines >= event.MaxChangedLines {
			return errors.New("begin record exceeds the persisted objective budget")
		}
		attempt := RuntimeAttempt{
			Ordinal: event.Ordinal, ObjectiveID: event.ObjectiveID, ObjectiveGeneration: generation,
			WorkUnit: event.WorkUnit, BeginCandidateIdentity: event.BeginCandidateIdentity,
			BeginCandidateTree: event.BeginCandidateTree, Outcome: AttemptRunning,
		}
		replay.Status.Attempts = append(replay.Status.Attempts, attempt)
		active := attempt
		replay.Status.ActiveAttempt = &active
		replay.Status.CumulativeAttempts++
		replay.Status.LifetimeAttempts++
		replay.Status.NextOrdinal = event.Ordinal + 1
		replay.Status.NextAction = RuntimeActionFinish

	case runtimeOperationFinish:
		if err := applyRuntimeFinishEvent(replay, record.Finish); err != nil {
			return err
		}

	case runtimeOperationFinishRemediation:
		currentBinding := replay.Status.Binding
		if currentBinding == nil && record.Binding.LegacyImport != nil {
			legacy := record.Binding.LegacyImport.Binding
			currentBinding = &legacy
		}
		if currentBinding == nil || currentBinding.Revision != record.Binding.ExpectedRevision {
			return errors.New("atomic remediation binding does not match replay state")
		}
		if replay.Status.EvidenceRevision != "" && replay.Status.EvidenceRevision != record.Finish.RemediatesEvidenceRevision {
			return errors.New("atomic remediation failed evidence does not match replay state")
		}
		if record.Binding.Current.Lineage == currentBinding.Lineage {
			return errors.New("atomic remediation binding does not select a distinct successor")
		}
		if err := applyRuntimeFinishEvent(replay, record.Finish); err != nil {
			return err
		}
		if !record.Finish.ChangedLineBudgetExceeded {
			if err := applyRuntimeBindingEvent(replay, record.Binding); err != nil {
				return err
			}
		}

	case runtimeOperationReset:
		event := record.Reset
		objective := replay.Status.Objective
		if replay.Status.ActiveAttempt != nil || objective == nil || !replay.Status.DecisionRequired && !replay.Status.Complete {
			return errors.New("objective reset is not a valid successor")
		}
		if event.PreviousObjectiveID != objective.ID || event.PreviousGeneration != objective.Generation ||
			event.PreviousGeneration != replay.Status.ObjectiveGeneration {
			return errors.New("objective reset does not match the terminal objective")
		}
		replay.Status.Objective = nil
		replay.Status.CumulativeAttempts = 0
		replay.Status.CumulativeChangedLines = 0
		replay.Status.EvidenceRevision = ""
		replay.Status.DecisionRequired = false
		replay.Status.Complete = false
		replay.Status.NextAction = RuntimeActionBegin
		replay.Status.LastReset = &RuntimeReset{
			Revision: revision, PreviousObjectiveID: event.PreviousObjectiveID, PreviousGeneration: event.PreviousGeneration,
			ResetCandidateIdentity: event.ResetCandidateIdentity, ResetCandidateTree: event.ResetCandidateTree,
			Reason: event.Reason, Actor: event.Actor,
		}

	case runtimeOperationBind:
		if err := applyRuntimeBindingEvent(replay, record.Binding); err != nil {
			return err
		}
	default:
		return errors.New("unsupported SDD runtime record operation")
	}
	replay.Status.Revision = revision
	replay.Requests[record.RequestID] = runtimeRequestReceipt{Digest: record.RequestDigest, Revision: revision}
	return nil
}

func applyRuntimeFinishEvent(replay *runtimeReplay, event *runtimeFinishEvent) error {
	active := replay.Status.ActiveAttempt
	if active == nil || active.Ordinal != event.Ordinal || len(replay.Status.Attempts) == 0 ||
		replay.Status.Attempts[len(replay.Status.Attempts)-1].Outcome != AttemptRunning {
		return errors.New("finish record does not match the active attempt")
	}
	budgetExceeded := replay.Status.CumulativeChangedLines+event.ChangedLines > replay.Status.Objective.MaxChangedLines
	if event.ChangedLineBudgetExceeded != budgetExceeded {
		return errors.New("finish record changed-line budget decision does not match replay state")
	}
	attempt := &replay.Status.Attempts[len(replay.Status.Attempts)-1]
	attempt.FinishCandidateIdentity = event.FinishCandidateIdentity
	attempt.FinishCandidateTree = event.FinishCandidateTree
	attempt.Outcome = event.Outcome
	attempt.ChangedLines = event.ChangedLines
	attempt.EvidenceRevision = event.EvidenceRevision
	attempt.Diagnosis = event.Diagnosis
	attempt.HarnessDisposition = event.HarnessDisposition
	attempt.CleanupEvidence = event.CleanupEvidence
	attempt.ProcessEvidence = event.ProcessEvidence
	attempt.RemediatesEvidenceRevision = event.RemediatesEvidenceRevision
	attempt.ChangedLineBudgetExceeded = event.ChangedLineBudgetExceeded
	replay.Status.ActiveAttempt = nil
	replay.Status.CumulativeChangedLines += event.ChangedLines
	replay.Status.LifetimeChangedLines += event.ChangedLines
	replay.Status.EvidenceRevision = event.EvidenceRevision
	if event.Outcome == AttemptPassed && !event.ChangedLineBudgetExceeded {
		replay.Status.Complete = true
		replay.Status.NextAction = RuntimeActionComplete
	} else if event.ChangedLineBudgetExceeded || replay.Status.CumulativeAttempts >= replay.Status.Objective.MaxAttempts ||
		replay.Status.CumulativeChangedLines >= replay.Status.Objective.MaxChangedLines {
		replay.Status.DecisionRequired = true
		replay.Status.NextAction = RuntimeActionReset
	} else {
		replay.Status.NextAction = RuntimeActionBegin
	}
	return nil
}

func applyRuntimeBindingEvent(replay *runtimeReplay, event *runtimeBindingEvent) error {
	current := ""
	if replay.Status.Binding != nil {
		if event.LegacyImport != nil {
			return errors.New("native binding successor cannot import legacy authority again")
		}
		current = replay.Status.BindingRevision
	} else if event.LegacyImport != nil {
		current = event.LegacyImport.Binding.Revision
	}
	if current != event.ExpectedRevision {
		return errors.New("binding record expected revision does not equal replay state")
	}
	binding := event.Current
	replay.Status.Binding = &binding
	replay.Status.BindingRevision = binding.Revision
	return nil
}

func validateRuntimeRecordShape(record runtimeRecord) error {
	if record.Schema != runtimeRecordSchema || !validReviewBindingChange(record.Change) ||
		(record.PreviousRevision != "" && !runtimeRevisionPattern.MatchString(record.PreviousRevision)) ||
		!runtimeRequestIDPattern.MatchString(record.RequestID) || !runtimeRevisionPattern.MatchString(record.RequestDigest) {
		return errors.New("invalid SDD runtime record identity")
	}
	switch record.Operation {
	case runtimeOperationBegin:
		if record.Begin == nil || record.Finish != nil || record.Reset != nil || record.Binding != nil {
			return errors.New("invalid SDD runtime begin record shape")
		}
		event := record.Begin
		if !runtimeRevisionPattern.MatchString(event.ObjectiveID) || event.ObjectiveGeneration < 0 || validateRuntimeText(event.WorkUnit, 160) != nil ||
			validateRuntimeText(event.EvidenceGoal, 240) != nil || event.MaxAttempts < 1 || event.MaxAttempts > maximumRuntimeAttemptLimit ||
			event.MaxChangedLines < 1 || event.MaxChangedLines > maximumRuntimeChangedLines || event.Ordinal < 1 ||
			!runtimeRevisionPattern.MatchString(event.BeginCandidateIdentity) || !runtimeGitTreePattern.MatchString(event.BeginCandidateTree) {
			return errors.New("invalid SDD runtime begin event")
		}
		request := BeginAttemptRequest{
			ExpectedRevision: record.PreviousRevision, RequestID: record.RequestID, WorkUnit: event.WorkUnit,
			EvidenceGoal: event.EvidenceGoal, MaxAttempts: event.MaxAttempts, MaxChangedLines: event.MaxChangedLines,
		}
		if runtimeValueHash("gentle-ai.sdd-runtime-begin-request/v1", request) != record.RequestDigest {
			return errors.New("SDD runtime begin request digest does not match record")
		}
	case runtimeOperationFinish:
		if record.Finish == nil || record.Begin != nil || record.Reset != nil || record.Binding != nil {
			return errors.New("invalid SDD runtime finish record shape")
		}
		event := record.Finish
		if event.Ordinal < 1 || !validTerminalAttemptOutcome(event.Outcome) || event.ChangedLines < 0 ||
			event.ChangedLines > maximumRuntimeChangedLines || !runtimeRevisionPattern.MatchString(event.EvidenceRevision) ||
			!runtimeRevisionPattern.MatchString(event.FinishCandidateIdentity) || !runtimeGitTreePattern.MatchString(event.FinishCandidateTree) ||
			validateRuntimeText(event.Diagnosis, 500) != nil || !validHarnessDisposition(event.HarnessDisposition) ||
			validateRuntimeText(event.CleanupEvidence, 500) != nil || validateRuntimeText(event.ProcessEvidence, 500) != nil ||
			event.RemediatesEvidenceRevision != "" {
			return errors.New("invalid SDD runtime finish event")
		}
		request := FinishAttemptRequest{
			ExpectedRevision: record.PreviousRevision, RequestID: record.RequestID, Outcome: event.Outcome,
			EvidenceRevision: event.EvidenceRevision, Diagnosis: event.Diagnosis, HarnessDisposition: event.HarnessDisposition,
			CleanupEvidence: event.CleanupEvidence, ProcessEvidence: event.ProcessEvidence,
		}
		if runtimeValueHash("gentle-ai.sdd-runtime-finish-request/v1", request) != record.RequestDigest {
			return errors.New("SDD runtime finish request digest does not match record")
		}
	case runtimeOperationFinishRemediation:
		if record.Finish == nil || record.Binding == nil || record.Begin != nil || record.Reset != nil {
			return errors.New("invalid atomic SDD runtime remediation record shape")
		}
		finish, binding := record.Finish, record.Binding
		if finish.Ordinal < 1 || finish.Outcome != AttemptPassed || finish.ChangedLines < 0 ||
			finish.ChangedLines > maximumRuntimeChangedLines || !runtimeRevisionPattern.MatchString(finish.EvidenceRevision) ||
			!runtimeRevisionPattern.MatchString(finish.RemediatesEvidenceRevision) ||
			!runtimeRevisionPattern.MatchString(finish.FinishCandidateIdentity) || !runtimeGitTreePattern.MatchString(finish.FinishCandidateTree) ||
			validateRuntimeText(finish.Diagnosis, 500) != nil || !validHarnessDisposition(finish.HarnessDisposition) ||
			validateRuntimeText(finish.CleanupEvidence, 500) != nil || validateRuntimeText(finish.ProcessEvidence, 500) != nil {
			return errors.New("invalid atomic SDD runtime remediation finish event")
		}
		if !runtimeRevisionPattern.MatchString(binding.ExpectedRevision) {
			return errors.New("invalid atomic SDD runtime remediation binding event")
		}
		if _, err := validatePreparedRuntimeBinding(binding.Current, record.Change, binding.Current.Lineage); err != nil {
			return fmt.Errorf("invalid atomic SDD runtime remediation successor: %w", err)
		}
		if binding.LegacyImport != nil {
			legacy, err := validatePreparedRuntimeBinding(binding.LegacyImport.Binding, record.Change, binding.LegacyImport.Binding.Lineage)
			if err != nil {
				return fmt.Errorf("invalid atomic remediation legacy binding import: %w", err)
			}
			payload, _ := bindingBytes(legacy)
			if binding.LegacyImport.SourceDigest != bindingHash(payload) || binding.ExpectedRevision != legacy.Revision {
				return errors.New("atomic remediation legacy binding import does not match its source or expected revision")
			}
		}
		request := FinishAttemptRequest{
			ExpectedRevision: record.PreviousRevision, RequestID: record.RequestID, Outcome: finish.Outcome,
			EvidenceRevision: finish.EvidenceRevision, Diagnosis: finish.Diagnosis, HarnessDisposition: finish.HarnessDisposition,
			CleanupEvidence: finish.CleanupEvidence, ProcessEvidence: finish.ProcessEvidence,
			ExpectedBindingRevision: binding.ExpectedRevision, SuccessorLineageID: binding.Current.Lineage,
			RemediatesEvidenceRevision: finish.RemediatesEvidenceRevision,
		}
		if runtimeValueHash("gentle-ai.sdd-runtime-finish-request/v1", request) != record.RequestDigest {
			return errors.New("atomic SDD runtime remediation request digest does not match record")
		}
	case runtimeOperationReset:
		if record.Reset == nil || record.Begin != nil || record.Finish != nil || record.Binding != nil {
			return errors.New("invalid SDD runtime reset record shape")
		}
		event := record.Reset
		if !runtimeRevisionPattern.MatchString(event.PreviousObjectiveID) || event.PreviousGeneration < 1 ||
			!runtimeRevisionPattern.MatchString(event.ResetCandidateIdentity) || !runtimeGitTreePattern.MatchString(event.ResetCandidateTree) ||
			validateRuntimeText(event.Reason, 500) != nil || validateRuntimeText(event.Actor, 128) != nil {
			return errors.New("invalid SDD runtime reset event")
		}
		request := ResetObjectiveRequest{
			ExpectedRevision: record.PreviousRevision, RequestID: record.RequestID, Reason: event.Reason, Actor: event.Actor,
		}
		if runtimeValueHash("gentle-ai.sdd-runtime-reset-request/v1", request) != record.RequestDigest {
			return errors.New("SDD runtime reset request digest does not match record")
		}
	case runtimeOperationBind:
		if record.Binding == nil || record.Begin != nil || record.Finish != nil || record.Reset != nil {
			return errors.New("invalid SDD runtime binding record shape")
		}
		event := record.Binding
		if event.ExpectedRevision != "" && !runtimeRevisionPattern.MatchString(event.ExpectedRevision) {
			return errors.New("invalid expected SDD review binding revision")
		}
		if _, err := validatePreparedRuntimeBinding(event.Current, record.Change, event.Current.Lineage); err != nil {
			return fmt.Errorf("invalid current SDD review binding: %w", err)
		}
		if event.LegacyImport != nil {
			legacy, err := validatePreparedRuntimeBinding(event.LegacyImport.Binding, record.Change, event.LegacyImport.Binding.Lineage)
			if err != nil {
				return fmt.Errorf("invalid imported legacy SDD review binding: %w", err)
			}
			payload, _ := bindingBytes(legacy)
			if event.LegacyImport.SourceDigest != bindingHash(payload) || event.ExpectedRevision != legacy.Revision {
				return errors.New("legacy SDD review binding import does not match its source or expected revision")
			}
		}
		request := BindReviewRequest{
			ExpectedBindingRevision: event.ExpectedRevision, RequestID: record.RequestID, LineageID: event.Current.Lineage,
		}
		if runtimeValueHash("gentle-ai.sdd-runtime-bind-request/v1", request) != record.RequestDigest {
			return errors.New("SDD runtime binding request digest does not match record")
		}
	default:
		return errors.New("invalid SDD runtime record operation")
	}
	return nil
}

func normalizeBeginAttemptRequest(request BeginAttemptRequest) (BeginAttemptRequest, error) {
	if request.ExpectedRevision != "" && !runtimeRevisionPattern.MatchString(request.ExpectedRevision) {
		return BeginAttemptRequest{}, errors.New("expected runtime revision must be empty or sha256")
	}
	if !runtimeRequestIDPattern.MatchString(request.RequestID) {
		return BeginAttemptRequest{}, errors.New("request_id must be a canonical lowercase identifier")
	}
	if err := validateRuntimeText(request.WorkUnit, 160); err != nil {
		return BeginAttemptRequest{}, fmt.Errorf("invalid work_unit: %w", err)
	}
	if err := validateRuntimeText(request.EvidenceGoal, 240); err != nil {
		return BeginAttemptRequest{}, fmt.Errorf("invalid evidence_goal: %w", err)
	}
	if request.MaxAttempts == 0 {
		request.MaxAttempts = DefaultRuntimeAttemptLimit
	}
	if request.MaxChangedLines == 0 {
		request.MaxChangedLines = DefaultRuntimeChangedLines
	}
	if request.MaxAttempts < 1 || request.MaxAttempts > maximumRuntimeAttemptLimit {
		return BeginAttemptRequest{}, fmt.Errorf("max_attempts must be within 1..%d", maximumRuntimeAttemptLimit)
	}
	if request.MaxChangedLines < 1 || request.MaxChangedLines > maximumRuntimeChangedLines {
		return BeginAttemptRequest{}, fmt.Errorf("max_changed_lines must be within 1..%d", maximumRuntimeChangedLines)
	}
	return request, nil
}

func normalizeFinishAttemptRequest(request FinishAttemptRequest) (FinishAttemptRequest, error) {
	if request.ExpectedRevision == "" || !runtimeRevisionPattern.MatchString(request.ExpectedRevision) {
		return FinishAttemptRequest{}, errors.New("finish requires an exact expected runtime revision")
	}
	if !runtimeRequestIDPattern.MatchString(request.RequestID) {
		return FinishAttemptRequest{}, errors.New("request_id must be a canonical lowercase identifier")
	}
	if !validTerminalAttemptOutcome(request.Outcome) {
		return FinishAttemptRequest{}, errors.New("outcome must be failed, interrupted, or passed")
	}
	if !runtimeRevisionPattern.MatchString(request.EvidenceRevision) {
		return FinishAttemptRequest{}, errors.New("evidence_revision must be sha256")
	}
	if err := validateRuntimeText(request.Diagnosis, 500); err != nil {
		return FinishAttemptRequest{}, fmt.Errorf("invalid diagnosis: %w", err)
	}
	if !validHarnessDisposition(request.HarnessDisposition) {
		return FinishAttemptRequest{}, errors.New("harness_disposition must be reused or invalidated")
	}
	if err := validateRuntimeText(request.CleanupEvidence, 500); err != nil {
		return FinishAttemptRequest{}, fmt.Errorf("invalid cleanup_evidence: %w", err)
	}
	if err := validateRuntimeText(request.ProcessEvidence, 500); err != nil {
		return FinishAttemptRequest{}, fmt.Errorf("invalid process_evidence: %w", err)
	}
	remediationFields := 0
	for _, value := range []string{request.ExpectedBindingRevision, request.SuccessorLineageID, request.RemediatesEvidenceRevision} {
		if value != "" {
			remediationFields++
		}
	}
	if remediationFields != 0 && remediationFields != 3 {
		return FinishAttemptRequest{}, errors.New("remediation successor requires expected_binding_revision, successor_lineage_id, and remediates_evidence_revision together")
	}
	if remediationFields == 3 {
		if request.Outcome != AttemptPassed {
			return FinishAttemptRequest{}, errors.New("an atomic remediation successor is valid only for a passed attempt")
		}
		if !runtimeRevisionPattern.MatchString(request.ExpectedBindingRevision) {
			return FinishAttemptRequest{}, errors.New("expected_binding_revision must be sha256 for atomic remediation")
		}
		if !validReviewBindingLineage(request.SuccessorLineageID) {
			return FinishAttemptRequest{}, errors.New("successor_lineage_id must be a canonical lowercase lineage")
		}
		if !runtimeRevisionPattern.MatchString(request.RemediatesEvidenceRevision) {
			return FinishAttemptRequest{}, errors.New("remediates_evidence_revision must be sha256")
		}
	}
	return request, nil
}

func finishRequestsRemediation(request FinishAttemptRequest) bool {
	return request.ExpectedBindingRevision != "" || request.SuccessorLineageID != "" || request.RemediatesEvidenceRevision != ""
}

func normalizeResetObjectiveRequest(request ResetObjectiveRequest) (ResetObjectiveRequest, error) {
	if request.ExpectedRevision == "" || !runtimeRevisionPattern.MatchString(request.ExpectedRevision) {
		return ResetObjectiveRequest{}, errors.New("reset requires an exact expected runtime revision")
	}
	if !runtimeRequestIDPattern.MatchString(request.RequestID) {
		return ResetObjectiveRequest{}, errors.New("request_id must be a canonical lowercase identifier")
	}
	if err := validateRuntimeText(request.Reason, 500); err != nil {
		return ResetObjectiveRequest{}, fmt.Errorf("invalid reset reason: %w", err)
	}
	if err := validateRuntimeText(request.Actor, 128); err != nil {
		return ResetObjectiveRequest{}, fmt.Errorf("invalid reset actor: %w", err)
	}
	return request, nil
}

func normalizeBindReviewRequest(request BindReviewRequest) (BindReviewRequest, error) {
	// Expected revision syntax is checked only after candidate preparation so
	// an identical-candidate retry remains idempotent even when an old caller
	// repeats a malformed token. A non-idempotent request can never publish it.
	if len(request.ExpectedBindingRevision) > 128 || strings.ContainsAny(request.ExpectedBindingRevision, "\r\n\x00") {
		return BindReviewRequest{}, errors.New("expected binding revision is not a bounded single-line value")
	}
	if !runtimeRequestIDPattern.MatchString(request.RequestID) {
		return BindReviewRequest{}, errors.New("request_id must be a canonical lowercase identifier")
	}
	if !validReviewBindingLineage(request.LineageID) {
		return BindReviewRequest{}, errors.New("lineage_id must be a canonical lowercase lineage")
	}
	return request, nil
}

func validatePreparedRuntimeBinding(binding ReviewBinding, change, lineage string) (ReviewBinding, error) {
	payload, err := bindingBytes(binding)
	if err != nil {
		return ReviewBinding{}, err
	}
	parsed, err := parseBinding(payload)
	if err != nil {
		return ReviewBinding{}, err
	}
	if parsed.Change != change || parsed.Lineage != lineage {
		return ReviewBinding{}, errors.New("prepared SDD review binding does not match selected change and lineage")
	}
	return parsed, nil
}

// readLegacyBinding is the only compatibility read of mutable binding.json.
// Callers invoke it only while the native runtime binding is absent; replay of
// a native import never consults the legacy artifact again.
func (store RuntimeStore) readLegacyBinding() (*ReviewBinding, string, error) {
	path := filepath.Join(store.commonDir, "gentle-ai", "sdd-review-bindings", "v1", store.Change, "binding.json")
	payload, err := readBoundedRuntimeFile(path)
	if os.IsNotExist(err) {
		return nil, "", nil
	}
	if err != nil {
		return nil, "", err
	}
	binding, err := parseBinding(payload)
	if err != nil {
		return nil, "", err
	}
	if binding.Change != store.Change {
		return nil, "", errors.New("legacy SDD review binding change does not match store")
	}
	return &binding, bindingHash(payload), nil
}

func validateRuntimeText(value string, maximum int) error {
	if value == "" || len(value) > maximum || strings.TrimSpace(value) != value || strings.ContainsAny(value, "\r\n\x00") {
		return errors.New("value must be non-empty, trimmed, single-line, and bounded")
	}
	return nil
}

func validTerminalAttemptOutcome(outcome AttemptOutcome) bool {
	return outcome == AttemptFailed || outcome == AttemptInterrupted || outcome == AttemptPassed
}

func validHarnessDisposition(disposition HarnessDisposition) bool {
	return disposition == HarnessReused || disposition == HarnessInvalidated
}

func captureRuntimeCandidate(ctx context.Context, repo string) (reviewtransaction.Snapshot, error) {
	builder := reviewtransaction.SnapshotBuilder{Repo: repo}
	intended, err := builder.DiscoverIntendedUntracked(ctx)
	if err != nil {
		return reviewtransaction.Snapshot{}, err
	}
	return builder.Build(ctx, reviewtransaction.Target{
		Kind: reviewtransaction.TargetCurrentChanges, Projection: reviewtransaction.ProjectionWorkspace,
		IntendedUntracked: intended,
	})
}

func runtimeObjectiveID(change, workUnit, evidenceGoal, candidateIdentity string, generation int) string {
	return runtimeValueHash(runtimeObjectiveSchemaV2, struct {
		Change            string `json:"change"`
		WorkUnit          string `json:"work_unit"`
		EvidenceGoal      string `json:"evidence_goal"`
		CandidateIdentity string `json:"candidate_identity"`
		Generation        int    `json:"generation"`
	}{Change: change, WorkUnit: workUnit, EvidenceGoal: evidenceGoal, CandidateIdentity: candidateIdentity, Generation: generation})
}

func runtimeObjectiveIDV1(change, evidenceGoal, candidateIdentity string, generation int) string {
	return runtimeValueHash(runtimeObjectiveSchema, struct {
		Change            string `json:"change"`
		EvidenceGoal      string `json:"evidence_goal"`
		CandidateIdentity string `json:"candidate_identity"`
		Generation        int    `json:"generation"`
	}{Change: change, EvidenceGoal: evidenceGoal, CandidateIdentity: candidateIdentity, Generation: generation})
}

func legacyRuntimeObjectiveID(change, evidenceGoal string) string {
	return runtimeValueHash(runtimeObjectiveSchema, struct {
		Change       string `json:"change"`
		EvidenceGoal string `json:"evidence_goal"`
	}{Change: change, EvidenceGoal: evidenceGoal})
}

func runtimeValueHash(domain string, value any) string {
	payload, _ := json.Marshal(value)
	sum := sha256.Sum256(append(append([]byte(domain), '\n'), payload...))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func runtimeRecordRevision(record runtimeRecord) (string, []byte, error) {
	payload, err := json.Marshal(record)
	if err != nil {
		return "", nil, err
	}
	payload = append(payload, '\n')
	sum := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(sum[:]), payload, nil
}

func (store RuntimeStore) ensureDirectories() error {
	if filepath.Clean(store.commonDir) == "." || !filepath.IsAbs(store.commonDir) {
		return errors.New("SDD runtime common directory is invalid")
	}
	relative, err := filepath.Rel(store.commonDir, filepath.Join(store.Dir, "records"))
	if err != nil || relative == "." || relative == ".." || filepath.IsAbs(relative) || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return errors.New("SDD runtime authority escapes the Git common directory")
	}
	current := store.commonDir
	segments := strings.Split(relative, string(filepath.Separator))
	created := make([]string, 0, len(segments))
	for index, segment := range segments {
		if segment == "" || segment == "." || segment == ".." {
			return errors.New("SDD runtime authority contains an invalid path segment")
		}
		current = filepath.Join(current, segment)
		info, statErr := os.Lstat(current)
		if os.IsNotExist(statErr) {
			mode := os.FileMode(0o700)
			// The shared gentle-ai container predates this private store and may
			// also hold review authority. New SDD runtime descendants remain 0700.
			if index == 0 && segment == "gentle-ai" {
				mode = 0o755
			}
			if err := os.Mkdir(current, mode); err != nil {
				if !os.IsExist(err) {
					return err
				}
			} else {
				created = append(created, current)
			}
			info, statErr = os.Lstat(current)
		}
		if statErr != nil {
			return statErr
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return errors.New("SDD runtime authority path is not a private directory")
		}
	}
	if filepath.Clean(current) != filepath.Clean(filepath.Join(store.Dir, "records")) {
		return errors.New("SDD runtime authority path resolution is inconsistent")
	}
	for _, path := range created {
		if err := runtimeSyncDirectory(filepath.Dir(path)); err != nil {
			return fmt.Errorf("sync parent of SDD runtime authority directory: %w", err)
		}
	}
	if err := os.Chmod(store.Dir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(filepath.Join(store.Dir, "records"), 0o700); err != nil {
		return err
	}
	return nil
}

func (store RuntimeStore) publishRecord(revision string, payload []byte) error {
	recordsDir := filepath.Join(store.Dir, "records")
	path := filepath.Join(recordsDir, strings.TrimPrefix(revision, "sha256:")+".json")
	temp, err := os.CreateTemp(recordsDir, ".record-*")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)
	if err := temp.Chmod(0o600); err == nil {
		_, err = temp.Write(payload)
	}
	if err == nil {
		err = temp.Sync()
	}
	if closeErr := temp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err := runtimePublishRecord(tempPath, path); err != nil {
		if !os.IsExist(err) {
			return err
		}
		existing, readErr := readBoundedRuntimeFile(path)
		if readErr != nil {
			return readErr
		}
		if !bytes.Equal(existing, payload) {
			return errors.New("existing immutable SDD runtime record differs from its revision")
		}
	}
	if err := runtimeSyncDirectory(recordsDir); err != nil {
		return fmt.Errorf("sync immutable SDD runtime record directory: %w", err)
	}
	return nil
}

func (store RuntimeStore) publishHead(revision string) error {
	temp, err := os.CreateTemp(store.Dir, ".head-*")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)
	if err := temp.Chmod(0o600); err == nil {
		_, err = temp.WriteString(revision + "\n")
	}
	if err == nil {
		err = temp.Sync()
	}
	if closeErr := temp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err := runtimeReplaceHead(tempPath, filepath.Join(store.Dir, "HEAD")); err != nil {
		return fmt.Errorf("publish SDD runtime HEAD: %w", err)
	}
	return nil
}

func (store RuntimeStore) syncReplay() error {
	if err := runtimeSyncDirectory(filepath.Join(store.Dir, "records")); err != nil {
		return fmt.Errorf("sync immutable SDD runtime record directory: %w", err)
	}
	if err := runtimeSyncDirectory(store.Dir); err != nil {
		return fmt.Errorf("sync SDD runtime HEAD directory: %w", err)
	}
	return nil
}

func readRuntimeHead(path string) (string, bool, error) {
	payload, err := readBoundedRuntimeFile(path)
	if os.IsNotExist(err) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	if len(payload) != len("sha256:")+64+1 || payload[len(payload)-1] != '\n' {
		return "", true, errors.New("invalid SDD runtime HEAD encoding")
	}
	revision := strings.TrimSuffix(string(payload), "\n")
	if !runtimeRevisionPattern.MatchString(revision) {
		return "", true, errors.New("invalid SDD runtime HEAD revision")
	}
	return revision, true, nil
}

func (store RuntimeStore) loadRecord(revision string) (runtimeRecord, error) {
	if !runtimeRevisionPattern.MatchString(revision) {
		return runtimeRecord{}, errors.New("invalid SDD runtime record revision")
	}
	path := filepath.Join(store.Dir, "records", strings.TrimPrefix(revision, "sha256:")+".json")
	payload, err := readBoundedRuntimeFile(path)
	if err != nil {
		return runtimeRecord{}, fmt.Errorf("load SDD runtime revision %s: %w", revision, err)
	}
	sum := sha256.Sum256(payload)
	actual := "sha256:" + hex.EncodeToString(sum[:])
	if actual != revision {
		return runtimeRecord{}, fmt.Errorf("SDD runtime record revision mismatch: expected %s, got %s", revision, actual)
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var record runtimeRecord
	if err := decoder.Decode(&record); err != nil {
		return runtimeRecord{}, fmt.Errorf("decode SDD runtime revision %s: %w", revision, err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return runtimeRecord{}, errors.New("SDD runtime record contains multiple JSON values")
	}
	_, canonical, err := runtimeRecordRevision(record)
	if err != nil || !bytes.Equal(payload, canonical) {
		return runtimeRecord{}, errors.New("SDD runtime record is not canonical")
	}
	if record.Change != store.Change {
		return runtimeRecord{}, errors.New("SDD runtime record change does not match store")
	}
	return record, nil
}

func readBoundedRuntimeFile(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() > maximumRuntimeRecordBytes {
		return nil, errors.New("SDD runtime authority artifact is not a bounded regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return io.ReadAll(io.LimitReader(file, maximumRuntimeRecordBytes+1))
}

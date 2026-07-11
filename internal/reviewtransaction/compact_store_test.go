package reviewtransaction

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestCompactStoreReplacesCurrentStateWithCASAndExactRetry(t *testing.T) {
	repo := initSnapshotRepo(t)
	writeSnapshotFile(t, repo, "tracked.txt", "candidate\n")
	state := newCompactTestState(t, repo, "compact-cas")
	store, err := CompactAuthoritativeStore(context.Background(), repo, state.LineageID)
	if err != nil {
		t.Fatal(err)
	}
	first, err := store.Replace("", "review/start", state)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(store.Dir, "events")); !os.IsNotExist(err) {
		t.Fatalf("compact store created event history: %v", err)
	}
	results := make([]LensResult, len(state.SelectedLenses))
	for index, lens := range state.SelectedLenses {
		results[index] = LensResult{Lens: lens, Findings: []Finding{}, Evidence: []string{"review completed"}}
	}
	if err := state.CompleteReview(CompactReviewInput{LensResults: results, Classifications: []FindingEvidence{}, RefuterOutcomes: []EvidenceResult{}}); err != nil {
		t.Fatal(err)
	}
	second, err := store.Replace(first, "review/complete-review", state)
	if err != nil || second == first {
		t.Fatalf("compact replacement = %q, %v", second, err)
	}
	if retry, err := store.Replace(first, "review/complete-review", state); err != nil || retry != second {
		t.Fatalf("exact compact retry = %q, %v", retry, err)
	}
	forged := state
	forged.PolicyHash = hash("f")
	if _, err := store.Replace(first, "review/complete-review", forged); !errors.Is(err, ErrConcurrentUpdate) {
		t.Fatalf("stale expected revision error = %v", err)
	}
	if _, err := store.Replace(second, "review/complete-verification", forged); !errors.Is(err, ErrInvalidSuccessor) {
		t.Fatalf("illegal compact successor error = %v", err)
	}
	loaded, err := store.Load()
	if err != nil || loaded.Revision != second || !compactStateEqual(loaded.State, state) {
		t.Fatalf("loaded compact authority = %#v, %v", loaded, err)
	}
}

func TestCompactStoreFailsClosedForCorruptionAndIgnoresInvalidTempState(t *testing.T) {
	repo := initSnapshotRepo(t)
	writeSnapshotFile(t, repo, "tracked.txt", "candidate\n")
	state := newCompactTestState(t, repo, "compact-corruption")
	store, _ := CompactAuthoritativeStore(context.Background(), repo, state.LineageID)
	revision, err := store.Replace("", "review/start", state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(store.Dir, ".atomic-interrupted"), []byte("not authority"), 0o644); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.Load()
	if err != nil || loaded.Revision != revision {
		t.Fatalf("invalid temp displaced authority: %#v, %v", loaded, err)
	}
	payload, err := os.ReadFile(store.StatePath())
	if err != nil {
		t.Fatal(err)
	}
	var record map[string]any
	if err := json.Unmarshal(payload, &record); err != nil {
		t.Fatal(err)
	}
	record["revision"] = hash("a")
	corrupt, _ := json.Marshal(record)
	if err := os.WriteFile(store.StatePath(), corrupt, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(); err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("corrupt compact state error = %v", err)
	}
}

func TestCompactStateRejectsChecksumValidImpossibleSemantics(t *testing.T) {
	repo := initSnapshotRepo(t)
	valid := correctedCompactTestState(t, repo, "compact-semantic-invalid")
	clean := valid
	clean.LensResults = append([]LensResult(nil), valid.LensResults...)
	clean.LensResults[0].Findings = append([]Finding(nil), valid.LensResults[0].Findings...)
	clean.CurrentSnapshot = clean.InitialSnapshot
	clean.FixDeltaHash = EmptyFixDeltaHash
	clean.FixFindingIDs = []string{}
	clean.Classifications = map[string]FindingEvidence{}
	clean.Outcomes = map[string]EvidenceOutcome{}
	clean.Findings = []Finding{}
	clean.LensResults[0].Findings = []Finding{}
	clean.LensResults[0].ResultHash = LensResultHash(clean.LensResults[0])
	clean.ProposedCorrectionLines = nil
	clean.ActualCorrectionLines = nil
	clean.OriginalCriteria = nil
	clean.CorrectionRegression = nil

	tests := []struct {
		name   string
		mutate func(*CompactState)
	}{
		{name: "findings differ from lens concatenation", mutate: func(state *CompactState) { state.Findings = []Finding{} }},
		{name: "severe classification missing", mutate: func(state *CompactState) { delete(state.Classifications, state.FixFindingIDs[0]) }},
		{name: "severe outcome missing", mutate: func(state *CompactState) { delete(state.Outcomes, state.FixFindingIDs[0]) }},
		{name: "unsupported evidence class", mutate: func(state *CompactState) {
			item := state.Classifications[state.FixFindingIDs[0]]
			item.Class = EvidenceClass("invented")
			state.Classifications[state.FixFindingIDs[0]] = item
		}},
		{name: "unsupported outcome", mutate: func(state *CompactState) { state.Outcomes[state.FixFindingIDs[0]] = EvidenceOutcome("invented") }},
		{name: "corroborated causal finding omitted from fix IDs", mutate: func(state *CompactState) { state.FixFindingIDs = []string{} }},
		{name: "arbitrary fix delta hash", mutate: func(state *CompactState) { state.FixDeltaHash = hash("f") }},
		{name: "approved correction has no completed correction", mutate: func(state *CompactState) {
			state.CurrentSnapshot = state.InitialSnapshot
			state.FixDeltaHash = EmptyFixDeltaHash
			state.ProposedCorrectionLines = nil
			state.ActualCorrectionLines = nil
			state.OriginalCriteria = nil
			state.CorrectionRegression = nil
		}},
		{name: "corrected state uses wrong fix base", mutate: func(state *CompactState) { state.CurrentSnapshot.BaseTree = state.InitialSnapshot.BaseTree }},
		{name: "corrected state uses wrong ledger IDs", mutate: func(state *CompactState) { state.CurrentSnapshot.LedgerIDs = []string{"OTHER"} }},
		{name: "approved correction has failed targeted check", mutate: func(state *CompactState) { state.OriginalCriteria.Passed = false }},
		{name: "unknown causality is not escalated", mutate: func(state *CompactState) {
			*state = clean
			finding := valid.Findings[0]
			state.Findings = []Finding{finding}
			state.LensResults[0].Findings = []Finding{finding}
			state.LensResults[0].ResultHash = LensResultHash(state.LensResults[0])
			state.Classifications = map[string]FindingEvidence{finding.ID: {FindingID: finding.ID, Class: EvidenceDeterministic, Causality: CausalUnknown, Proof: "causality is unresolved"}}
			state.Outcomes = map[string]EvidenceOutcome{finding.ID: OutcomeInconclusive}
		}},
		{name: "insufficient evidence is not escalated", mutate: func(state *CompactState) {
			*state = clean
			finding := valid.Findings[0]
			state.Findings = []Finding{finding}
			state.LensResults[0].Findings = []Finding{finding}
			state.LensResults[0].ResultHash = LensResultHash(state.LensResults[0])
			state.Classifications = map[string]FindingEvidence{finding.ID: {FindingID: finding.ID, Class: EvidenceInsufficient, Causality: CausalIntroduced, Proof: "evidence remains insufficient"}}
			state.Outcomes = map[string]EvidenceOutcome{finding.ID: OutcomeInconclusive}
		}},
		{name: "non-severe finding enters correction", mutate: func(state *CompactState) {
			state.Findings[0].Severity = "INFO"
			state.LensResults[0].Findings[0].Severity = "INFO"
			state.LensResults[0].ResultHash = LensResultHash(state.LensResults[0])
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			state := valid
			state.LensResults = append([]LensResult(nil), valid.LensResults...)
			state.LensResults[0].Findings = append([]Finding(nil), valid.LensResults[0].Findings...)
			state.Findings = append([]Finding(nil), valid.Findings...)
			state.Classifications = cloneClassifications(valid.Classifications)
			state.Outcomes = cloneOutcomes(valid.Outcomes)
			state.FixFindingIDs = append([]string(nil), valid.FixFindingIDs...)
			if valid.OriginalCriteria != nil {
				original, regression := *valid.OriginalCriteria, *valid.CorrectionRegression
				state.OriginalCriteria, state.CorrectionRegression = &original, &regression
			}
			tt.mutate(&state)
			state.InitialSnapshot.Identity = snapshotIdentity(state.InitialSnapshot.Kind, state.InitialSnapshot.BaseTree, state.InitialSnapshot.CandidateTree, state.InitialSnapshot.PathsDigest, state.InitialSnapshot.IntendedUntrackedProof, state.InitialSnapshot.IntendedUntracked, state.InitialSnapshot.LedgerIDs)
			state.CurrentSnapshot.Identity = snapshotIdentity(state.CurrentSnapshot.Kind, state.CurrentSnapshot.BaseTree, state.CurrentSnapshot.CandidateTree, state.CurrentSnapshot.PathsDigest, state.CurrentSnapshot.IntendedUntrackedProof, state.CurrentSnapshot.IntendedUntracked, state.CurrentSnapshot.LedgerIDs)
			record, payload, err := makeCompactRecord(state)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := parseCompactRecord(payload, state.LineageID); err == nil || strings.Contains(err.Error(), "checksum mismatch") {
				t.Fatalf("checksum-valid impossible state parse error = %v", err)
			}
			store, _ := CompactAuthoritativeStore(context.Background(), repo, state.LineageID)
			if err := os.MkdirAll(store.Dir, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(store.StatePath(), payload, 0o644); err != nil {
				t.Fatal(err)
			}
			if _, err := store.Load(); err == nil || strings.Contains(err.Error(), "checksum mismatch") {
				t.Fatalf("checksum-valid impossible current load error = %v", err)
			}
			_ = os.RemoveAll(store.Dir)
			transport := CompactTransport{Schema: CompactTransportSchema, Record: record}
			transport.BundleDigest = compactTransportDigest(transport)
			transportPayload, _ := json.Marshal(transport)
			if _, err := ParseCompactTransport(transportPayload); err == nil || strings.Contains(err.Error(), "checksum mismatch") {
				t.Fatalf("checksum-valid impossible transport parse error = %v", err)
			}
			if _, err := ImportCompactTransport(context.Background(), repo, transport); err == nil || strings.Contains(err.Error(), "checksum mismatch") {
				t.Fatalf("checksum-valid impossible import error = %v", err)
			}
		})
	}
}

func TestCompactStoreRejectsConcurrentLockedWriter(t *testing.T) {
	repo := initSnapshotRepo(t)
	writeSnapshotFile(t, repo, "tracked.txt", "candidate\n")
	state := newCompactTestState(t, repo, "compact-locked")
	store, _ := CompactAuthoritativeStore(context.Background(), repo, state.LineageID)
	lock, err := acquireStoreLock(store.lockPath)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.release()
	if _, err := store.Replace("", "review/start", state); !errors.Is(err, ErrConcurrentUpdate) {
		t.Fatalf("concurrent compact writer error = %v", err)
	}
}

func TestCompactTransportRoundTripRecoversEquivalentCurrentAuthority(t *testing.T) {
	source := initSnapshotRepo(t)
	writeSnapshotFile(t, source, "tracked.txt", "candidate\n")
	gitSnapshot(t, source, "add", "tracked.txt")
	gitSnapshot(t, source, "commit", "-m", "candidate")
	state := newCompactRevisionState(t, source, "compact-transport")
	store, _ := CompactAuthoritativeStore(context.Background(), source, state.LineageID)
	if _, err := store.Replace("", "review/start", state); err != nil {
		t.Fatal(err)
	}
	results := make([]LensResult, len(state.SelectedLenses))
	for index, lens := range state.SelectedLenses {
		results[index] = LensResult{Lens: lens, Findings: []Finding{}, Evidence: []string{"review completed"}}
	}
	if err := state.CompleteReview(CompactReviewInput{LensResults: results, Classifications: []FindingEvidence{}, RefuterOutcomes: []EvidenceResult{}}); err != nil {
		t.Fatal(err)
	}
	record, _ := store.Load()
	if _, err := store.Replace(record.Revision, "review/complete-review", state); err != nil {
		t.Fatal(err)
	}
	if err := state.CompleteVerification([]byte("tests pass\n"), true); err != nil {
		t.Fatal(err)
	}
	record, _ = store.Load()
	if _, err := store.Replace(record.Revision, "review/complete-verification", state); err != nil {
		t.Fatal(err)
	}
	receipt, _ := state.Receipt()
	if err := WriteCompactReceiptAtomic(store.ReceiptPath(), receipt); err != nil {
		t.Fatal(err)
	}
	transport, err := store.ExportTransport()
	if err != nil {
		t.Fatal(err)
	}
	if transport.Receipt == nil {
		t.Fatalf("compact transport = %#v", transport)
	}

	destination := filepath.Join(t.TempDir(), "clone")
	gitSnapshot(t, source, "clone", "--no-local", source, destination)
	imported, err := ImportCompactTransport(context.Background(), destination, transport)
	if err != nil {
		t.Fatal(err)
	}
	destinationStore, _ := CompactAuthoritativeStore(context.Background(), destination, state.LineageID)
	destinationTransport, err := destinationStore.ExportTransport()
	if err != nil {
		t.Fatal(err)
	}
	if imported.Revision != transport.Record.Revision || !reflect.DeepEqual(destinationTransport.Record, transport.Record) || !reflect.DeepEqual(destinationTransport.Receipt, transport.Receipt) {
		t.Fatalf("compact transport round trip changed authority")
	}
	if _, err := os.Stat(filepath.Join(destinationStore.Dir, "events")); !os.IsNotExist(err) {
		t.Fatalf("compact import reconstructed event history: %v", err)
	}
}

func TestCompactTransportImportRejectsWrongDeliveredTreeAndScope(t *testing.T) {
	source := initSnapshotRepo(t)
	state := correctedCompactTestState(t, source, "compact-transport-binding")
	gitSnapshot(t, source, "add", "tracked.txt")
	gitSnapshot(t, source, "commit", "-m", "corrected candidate")
	tests := []struct {
		name   string
		mutate func(*CompactState)
		want   string
	}{
		{name: "wrong delivered tree", want: "delivered tree", mutate: func(candidate *CompactState) {
			candidate.CurrentSnapshot.CandidateTree = candidate.InitialSnapshot.BaseTree
			candidate.FixDeltaHash = FixDeltaHashForSnapshot(candidate.CurrentSnapshot)
		}},
		{name: "wrong delivered path scope", want: "path scope", mutate: func(candidate *CompactState) {
			candidate.InitialSnapshot.Paths = []string{"other.txt"}
			candidate.InitialSnapshot.PathsDigest = digestPaths(candidate.InitialSnapshot.Paths)
			candidate.GenesisPaths = append([]string(nil), candidate.InitialSnapshot.Paths...)
			candidate.CurrentSnapshot.Paths = []string{"other.txt"}
			candidate.CurrentSnapshot.PathsDigest = digestPaths(candidate.CurrentSnapshot.Paths)
			candidate.FixDeltaHash = FixDeltaHashForSnapshot(candidate.CurrentSnapshot)
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			candidate := state
			candidate.InitialSnapshot.Paths = append([]string(nil), state.InitialSnapshot.Paths...)
			candidate.CurrentSnapshot.Paths = append([]string(nil), state.CurrentSnapshot.Paths...)
			candidate.GenesisPaths = append([]string(nil), state.GenesisPaths...)
			tt.mutate(&candidate)
			candidate.InitialSnapshot.Identity = snapshotIdentity(candidate.InitialSnapshot.Kind, candidate.InitialSnapshot.BaseTree, candidate.InitialSnapshot.CandidateTree, candidate.InitialSnapshot.PathsDigest, candidate.InitialSnapshot.IntendedUntrackedProof, candidate.InitialSnapshot.IntendedUntracked, candidate.InitialSnapshot.LedgerIDs)
			candidate.CurrentSnapshot.Identity = snapshotIdentity(candidate.CurrentSnapshot.Kind, candidate.CurrentSnapshot.BaseTree, candidate.CurrentSnapshot.CandidateTree, candidate.CurrentSnapshot.PathsDigest, candidate.CurrentSnapshot.IntendedUntrackedProof, candidate.CurrentSnapshot.IntendedUntracked, candidate.CurrentSnapshot.LedgerIDs)
			candidate.OriginalCriteria.FixDeltaHash = candidate.FixDeltaHash
			candidate.CorrectionRegression.FixDeltaHash = candidate.FixDeltaHash
			if err := candidate.Validate(); err != nil {
				t.Fatalf("test candidate must remain checksum-valid and semantically self-consistent: %v", err)
			}
			record, _, err := makeCompactRecord(candidate)
			if err != nil {
				t.Fatal(err)
			}
			receipt, err := candidate.Receipt()
			if err != nil {
				t.Fatal(err)
			}
			transport := CompactTransport{Schema: CompactTransportSchema, Record: record, Receipt: &receipt}
			transport.BundleDigest = compactTransportDigest(transport)
			clone := filepath.Join(t.TempDir(), "clone")
			gitSnapshot(t, source, "clone", "--no-local", source, clone)
			if _, err := ImportCompactTransport(context.Background(), clone, transport); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("wrong compact delivery import error = %v", err)
			}
		})
	}
}

func TestCompactDiagnosticTraceContainsMetadataOnly(t *testing.T) {
	repo := initSnapshotRepo(t)
	writeSnapshotFile(t, repo, "tracked.txt", "candidate\n")
	state := newCompactTestState(t, repo, "compact-trace")
	store, _ := CompactAuthoritativeStore(context.Background(), repo, state.LineageID)
	store.TracePath = filepath.Join(t.TempDir(), "trace.jsonl")
	if _, err := store.Replace("", "review/start", state); err != nil {
		t.Fatal(err)
	}
	payload, err := os.ReadFile(store.TracePath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(payload), "initial_snapshot") || strings.Contains(string(payload), "findings") || !strings.Contains(string(payload), `"operation":"review/start"`) {
		t.Fatalf("diagnostic trace contains authority snapshot or lacks metadata: %s", payload)
	}
}

func TestCompactLifecycleComplexityMeasurements(t *testing.T) {
	repo := initSnapshotRepo(t)
	writeSnapshotFile(t, repo, "tracked.txt", "candidate\n")
	gitSnapshot(t, repo, "add", "tracked.txt")
	gitSnapshot(t, repo, "commit", "-m", "candidate")
	_, compactStore, _ := approvedCompactRevisionFixture(t, repo, "compact-measurement")
	compactFiles, compactBytes := authorityFileMetrics(t, compactStore.Dir)

	legacyTransaction, legacyReceipt, _ := nativeGateFixture(t, repo, "legacy-measurement")
	legacyStore, err := AuthoritativeStore(context.Background(), repo, legacyTransaction.LineageID)
	if err != nil {
		t.Fatal(err)
	}
	appendApprovedStoreChain(t, legacyStore, legacyTransaction)
	if err := WriteReceiptAtomic(filepath.Join(legacyStore.Dir, "artifacts", "receipt.json"), legacyReceipt); err != nil {
		t.Fatal(err)
	}
	legacyFiles, legacyBytes := authorityFileMetrics(t, legacyStore.Dir)

	if compactFiles != 2 || legacyFiles <= compactFiles || compactBytes >= legacyBytes {
		t.Fatalf("authority metrics legacy=%d files/%d bytes compact=%d files/%d bytes", legacyFiles, legacyBytes, compactFiles, compactBytes)
	}
	t.Logf("authority metrics: legacy v1=%d files/%d bytes; compact v2=%d files/%d bytes; semantic states=12->5; counters=12->0; clean writes=6->3; corrected writes=9->5", legacyFiles, legacyBytes, compactFiles, compactBytes)
}

func authorityFileMetrics(t *testing.T, root string) (int, int64) {
	t.Helper()
	files := 0
	var bytes int64
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || entry.Name() == "LOCK" || strings.HasPrefix(entry.Name(), ".atomic-") {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		files++
		bytes += info.Size()
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return files, bytes
}

func newCompactTestState(t *testing.T, repo, lineage string) CompactState {
	return newCompactTestStateWithIntended(t, repo, lineage, []string{})
}

func newCompactTestStateWithIntended(t *testing.T, repo, lineage string, intended []string) CompactState {
	t.Helper()
	snapshot, err := (SnapshotBuilder{Repo: repo}).Build(context.Background(), Target{Kind: TargetCurrentChanges, IntendedUntracked: intended})
	if err != nil {
		t.Fatal(err)
	}
	risk, lines, err := (SnapshotBuilder{Repo: repo}).ClassifySnapshotRisk(context.Background(), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	lenses := []string{}
	if risk == RiskMedium {
		lenses = []string{LensReliability}
	} else if risk == RiskHigh {
		lenses = append([]string(nil), supportedLenses...)
	}
	state, err := NewCompactState(Start{
		LineageID: lineage, Mode: ModeOrdinaryBounded, Generation: 1, Snapshot: snapshot,
		PolicyHash: hash("1"), RiskLevel: risk, SelectedLenses: lenses, OriginalChangedLines: &lines,
	})
	if err != nil {
		t.Fatal(err)
	}
	return state
}

func correctedCompactTestState(t *testing.T, repo, lineage string) CompactState {
	t.Helper()
	writeSnapshotFile(t, repo, "tracked.txt", "base\none\ntwo\nthree\nfour\n")
	state := newCompactTestState(t, repo, lineage)
	finding := Finding{
		ID: "R3-001", Lens: "reliability", Location: "tracked.txt:5", Severity: "CRITICAL",
		Claim: "candidate returns the wrong terminal value", ProofRefs: []string{"differential test fails only on candidate"},
	}
	result := LensResult{Lens: LensReliability, Findings: []Finding{finding}, Evidence: []string{"focused differential test failed"}}
	if err := state.CompleteReview(CompactReviewInput{
		LensResults:     []LensResult{result},
		Classifications: []FindingEvidence{{FindingID: finding.ID, Class: EvidenceDeterministic, Causality: CausalIntroduced, Proof: "changed hunk causes the failure"}},
		RefuterOutcomes: []EvidenceResult{},
	}); err != nil {
		t.Fatal(err)
	}
	if err := state.BeginCorrection(2); err != nil {
		t.Fatal(err)
	}
	writeSnapshotFile(t, repo, "tracked.txt", "base\none\ntwo\nthree\nfixed\n")
	fix, err := (SnapshotBuilder{Repo: repo}).Build(context.Background(), Target{
		Kind: TargetFixDiff, BaseRef: state.InitialSnapshot.CandidateTree,
		IntendedUntracked: state.InitialSnapshot.IntendedUntracked, LedgerIDs: state.FixFindingIDs,
	})
	if err != nil {
		t.Fatal(err)
	}
	fixHash := FixDeltaHashForSnapshot(fix)
	validation := ScopedValidationResult{
		LedgerIDs: state.FixFindingIDs, FixCausedFindings: []Finding{}, FollowUps: []FollowUp{},
		OriginalCriteria:     ValidationCheck{EvidenceHash: hash("2"), FixDeltaHash: fixHash, Passed: true},
		CorrectionRegression: ValidationCheck{EvidenceHash: hash("3"), FixDeltaHash: fixHash, Passed: true},
	}
	if err := state.CompleteCorrection(fix, 2, validation); err != nil {
		t.Fatal(err)
	}
	if err := state.CompleteVerification([]byte("tests pass\n"), true); err != nil {
		t.Fatal(err)
	}
	return state
}

func newCompactRevisionState(t *testing.T, repo, lineage string) CompactState {
	t.Helper()
	commit := strings.TrimSpace(gitSnapshot(t, repo, "rev-parse", "HEAD"))
	snapshot, err := (SnapshotBuilder{Repo: repo}).Build(context.Background(), Target{Kind: TargetExactRevision, Revision: commit})
	if err != nil {
		t.Fatal(err)
	}
	risk, lines, err := (SnapshotBuilder{Repo: repo}).ClassifySnapshotRisk(context.Background(), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	lenses := []string{}
	if risk == RiskMedium {
		lenses = []string{LensReliability}
	} else if risk == RiskHigh {
		lenses = append([]string(nil), supportedLenses...)
	}
	state, err := NewCompactState(Start{LineageID: lineage, Mode: ModeOrdinaryBounded, Generation: 1, Snapshot: snapshot, PolicyHash: hash("1"), RiskLevel: risk, SelectedLenses: lenses, OriginalChangedLines: &lines})
	if err != nil {
		t.Fatal(err)
	}
	return state
}

package sddstatus

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/gentleman-programming/gentle-ai/internal/reviewtransaction"
)

func TestBindApprovedReviewRejectsInvalidChangeBeforePublishing(t *testing.T) {
	if _, err := BindApprovedReview(context.Background(), t.TempDir(), "../escape", "approved", ""); err == nil {
		t.Fatal("traversal change name was accepted")
	}
}

func TestBindApprovedReviewCASAndLiveEvidence(t *testing.T) {
	root := t.TempDir()
	changeRoot := seedReadyChange(t, root, "thin", "- [x] 1.1 Done\n")
	writeApprovedCompactAuthorityForChange(t, root, changeRoot, "approved-thin")
	binding, err := BindApprovedReview(context.Background(), root, "thin", "approved-thin", "")
	if err != nil {
		t.Fatal(err)
	}
	if binding.Schema != reviewBindingSchema || binding.AuthorityRevision == "" || binding.ReceiptHash == "" || binding.GateContext.Gate != "post-apply" {
		t.Fatalf("binding = %#v", binding)
	}
	if _, err := BindApprovedReview(context.Background(), filepath.Join(root, "openspec", "changes", "thin"), "thin", "approved-thin", ""); err != nil {
		t.Fatalf("exact retry with original empty expected revision: %v", err)
	}
	if _, err := BindApprovedReview(context.Background(), root, "thin", "other", binding.Revision); err == nil {
		t.Fatal("conflicting lineage accepted")
	}
	if _, err := BindApprovedReview(context.Background(), root, "thin", "approved-thin", "sha256:deadbeef"); err != nil {
		t.Fatalf("identical candidate retry must precede expected revision conflict: %v", err)
	}
	runtimeStore := mustRuntimeStore(t, root, "thin")
	assertNativeBinding(t, runtimeStore, binding.Revision)
	corruptNativeRuntimeBinding(t, runtimeStore)
	if _, err := BindApprovedReview(context.Background(), root, "thin", "approved-thin", binding.Revision); err == nil {
		t.Fatal("corrupt binding accepted")
	}
	if err := os.WriteFile(filepath.Join(changeRoot, "tasks.md"), []byte("- [x] 1.1 Done\n# drift\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := BindApprovedReview(context.Background(), root, "thin", "approved-thin", ""); err == nil {
		t.Fatal("working-tree drift bound authority")
	}
}

func TestBindApprovedReviewUsesNestedOpenSpecPlanningWorkspace(t *testing.T) {
	root := t.TempDir()
	planningRoot := filepath.Join(root, "packages", "app")
	changeRoot := seedReadyChange(t, planningRoot, "thin", "- [x] 1.1 Done\n")
	writeApprovedCompactAuthorityForChange(t, root, changeRoot, "approved-thin")

	binding, err := BindApprovedReview(context.Background(), planningRoot, "thin", "approved-thin", "")
	if err != nil {
		t.Fatal(err)
	}
	deeperPath := filepath.Join(planningRoot, "src", "feature")
	if err := os.MkdirAll(deeperPath, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := BindApprovedReview(context.Background(), deeperPath, "thin", "approved-thin", binding.Revision); err != nil {
		t.Fatalf("bind from deeper package path: %v", err)
	}
	runtimeStore := mustRuntimeStore(t, root, "thin")
	assertNativeBinding(t, runtimeStore, binding.Revision)
	status, err := Resolve(ResolveOptions{CWD: planningRoot, ChangeName: "thin"})
	if err != nil {
		t.Fatal(err)
	}
	if status.PlanningHome.Path != filepath.Join(planningRoot, "openspec") || status.ReviewGate == nil || status.ReviewGate.Result != reviewtransaction.GateAllow {
		t.Fatalf("nested planning status did not consume canonical binding: %#v", status)
	}
}

func TestBindApprovedReviewRejectsAmbiguousPlanningChanges(t *testing.T) {
	for _, tt := range []struct {
		name string
		seed func(t *testing.T, root, planningRoot string)
	}{
		{name: "ancestor collision", seed: func(t *testing.T, root, planningRoot string) {
			seedReadyChange(t, root, "thin", "- [x] 1.1 Root\n")
			seedReadyChange(t, planningRoot, "thin", "- [x] 1.1 Package\n")
		}},
		{name: "sibling collision", seed: func(t *testing.T, root, planningRoot string) {
			seedReadyChange(t, planningRoot, "thin", "- [x] 1.1 App\n")
			seedReadyChange(t, filepath.Join(root, "packages", "api"), "thin", "- [x] 1.1 API\n")
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			planningRoot := filepath.Join(root, "packages", "app")
			tt.seed(t, root, planningRoot)
			runSDDStatusGit(t, root, "init", "-q")

			if _, err := BindApprovedReview(context.Background(), planningRoot, "thin", "approved-thin", ""); err == nil || !strings.Contains(err.Error(), "ambiguous") {
				t.Fatalf("ambiguous planning changes error = %v", err)
			}
		})
	}
}

func TestBindApprovedReviewRejectsOpenSpecSymlinkEscape(t *testing.T) {
	root := t.TempDir()
	planningRoot := filepath.Join(root, "packages", "app")
	if err := os.MkdirAll(planningRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	seedReadyChange(t, outside, "thin", "- [x] 1.1 Outside\n")
	if err := os.Symlink(filepath.Join(outside, "openspec"), filepath.Join(planningRoot, "openspec")); err != nil {
		t.Fatal(err)
	}
	runSDDStatusGit(t, root, "init", "-q")

	if _, err := BindApprovedReview(context.Background(), planningRoot, "thin", "approved-thin", ""); err == nil || !strings.Contains(err.Error(), "outside repository") {
		t.Fatalf("OpenSpec symlink escape error = %v", err)
	}
}

func TestBindApprovedReviewDoesNotFallBackPastNestedPlanningWorkspace(t *testing.T) {
	root := t.TempDir()
	planningRoot := filepath.Join(root, "packages", "app")
	seedReadyChange(t, root, "thin", "- [x] 1.1 Root\n")
	seedReadyChange(t, planningRoot, "other", "- [x] 1.1 Package\n")
	runSDDStatusGit(t, root, "init", "-q")

	if _, err := BindApprovedReview(context.Background(), planningRoot, "thin", "approved-thin", ""); err == nil || !strings.Contains(err.Error(), "does not exist") {
		t.Fatalf("nested planning workspace fallback error = %v", err)
	}
}

func TestBindApprovedReviewChecksNestedPlanningLedger(t *testing.T) {
	root := t.TempDir()
	planningRoot := filepath.Join(root, "packages", "app")
	changeRoot := seedReadyChange(t, planningRoot, "thin", "- [x] 1.1 Done\n")
	writeApprovedCompactAuthorityForChange(t, root, changeRoot, "approved-thin")
	write(t, filepath.Join(changeRoot, "reviews", "ledger.json"), `{"schema":"gentle-ai.review-ledger/v1","findings":[{"id":"wrong"}]}`)

	if _, err := BindApprovedReview(context.Background(), planningRoot, "thin", "approved-thin", ""); err == nil || !strings.Contains(err.Error(), "ledger does not equal") {
		t.Fatalf("nested planning ledger error = %v", err)
	}
	runtimeStore := mustRuntimeStore(t, root, "thin")
	if _, err := os.Stat(filepath.Join(runtimeStore.Dir, "HEAD")); !os.IsNotExist(err) {
		t.Fatalf("failed nested bind mutated native binding authority: %v", err)
	}
}

func TestResolveConsumesOnlyAnExplicitValidBinding(t *testing.T) {
	root := t.TempDir()
	changeRoot := seedReadyChange(t, root, "thin", "- [x] 1.1 Done\n")
	writeApprovedCompactAuthorityForChange(t, root, changeRoot, "approved-thin")

	withoutBinding, err := Resolve(ResolveOptions{CWD: root, ChangeName: "thin"})
	if err != nil {
		t.Fatal(err)
	}
	if withoutBinding.NextRecommended != "verify" || withoutBinding.Dependencies.Verify != DependencyReady {
		t.Fatalf("unbound authority status = %#v", withoutBinding)
	}

	if _, err := BindApprovedReview(context.Background(), root, "thin", "approved-thin", ""); err != nil {
		t.Fatal(err)
	}
	bound, err := Resolve(ResolveOptions{CWD: root, ChangeName: "thin"})
	if err != nil {
		t.Fatal(err)
	}
	if bound.NextRecommended != "verify" || bound.Dependencies.Verify != DependencyReady || bound.Dependencies.Archive != DependencyBlocked || bound.ReviewGate == nil || bound.ReviewGate.Result != reviewtransaction.GateAllow {
		t.Fatalf("bound authority status = %#v", bound)
	}
}

func TestBindApprovedReviewRequiresTheSelectedCanonicalChange(t *testing.T) {
	for _, change := range []string{"../escape", "thin-", "thin--binding", strings.Repeat("a", 129)} {
		if _, err := BindApprovedReview(context.Background(), t.TempDir(), change, "approved", ""); err == nil {
			t.Fatalf("invalid change %q was accepted", change)
		}
	}
}

func TestValidateBoundReviewFailsClosedWhenFinalGateChanges(t *testing.T) {
	root := t.TempDir()
	changeRoot := seedReadyChange(t, root, "thin", "- [x] 1.1 Done\n")
	writeApprovedCompactAuthorityForChange(t, root, changeRoot, "approved-thin")
	if _, err := BindApprovedReview(context.Background(), root, "thin", "approved-thin", ""); err != nil {
		t.Fatal(err)
	}
	original := bindingFinalAuthorizationHook
	bindingFinalAuthorizationHook = func() { write(t, filepath.Join(changeRoot, "tasks.md"), "- [x] 1.1 Done\n# final gate drift\n") }
	t.Cleanup(func() { bindingFinalAuthorizationHook = original })
	if _, _, err := validateBoundReview(context.Background(), root, "thin"); err == nil {
		t.Fatal("final live gate mutation was accepted")
	}
}

func TestValidateBoundReviewFailsClosedForFinalAuthorityArtifacts(t *testing.T) {
	for _, tt := range []struct {
		name   string
		mutate func(t *testing.T, root string, store reviewtransaction.CompactStore)
	}{
		{name: "receipt bytes", mutate: func(t *testing.T, _ string, store reviewtransaction.CompactStore) {
			if err := os.WriteFile(store.ReceiptPath(), []byte("{}\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "authority state", mutate: func(t *testing.T, _ string, store reviewtransaction.CompactStore) {
			if err := os.WriteFile(store.StatePath(), []byte("{}\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "binding bytes", mutate: func(t *testing.T, root string, _ reviewtransaction.CompactStore) {
			corruptNativeRuntimeBinding(t, mustRuntimeStore(t, root, "thin"))
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			changeRoot := seedReadyChange(t, root, "thin", "- [x] 1.1 Done\n")
			writeApprovedCompactAuthorityForChange(t, root, changeRoot, "approved-thin")
			if _, err := BindApprovedReview(context.Background(), root, "thin", "approved-thin", ""); err != nil {
				t.Fatal(err)
			}
			store, err := reviewtransaction.CompactAuthoritativeStore(context.Background(), root, "approved-thin")
			if err != nil {
				t.Fatal(err)
			}
			original := bindingFinalAuthorizationHook
			bindingFinalAuthorizationHook = func() { tt.mutate(t, root, store) }
			t.Cleanup(func() { bindingFinalAuthorizationHook = original })
			if _, _, err := validateBoundReview(context.Background(), root, "thin"); err == nil {
				t.Fatal("final artifact mutation was accepted")
			}
		})
	}
}

func TestBindApprovedReviewPreservesAuthorityAcrossBindingPublicationFailures(t *testing.T) {
	for _, name := range []string{"HEAD replace", "directory sync"} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			changeRoot := seedReadyChange(t, root, "thin", "- [x] 1.1 Done\n")
			writeApprovedCompactAuthorityForChange(t, root, changeRoot, "approved-thin")
			store, err := reviewtransaction.CompactAuthoritativeStore(context.Background(), root, "approved-thin")
			if err != nil {
				t.Fatal(err)
			}
			before, err := store.Load()
			if err != nil {
				t.Fatal(err)
			}
			runtimeStore := mustRuntimeStore(t, root, "thin")
			if err := runtimeStore.ensureDirectories(); err != nil {
				t.Fatal(err)
			}

			originalReplace, originalSync := runtimeReplaceHead, runtimeSyncDirectory
			t.Cleanup(func() { runtimeReplaceHead, runtimeSyncDirectory = originalReplace, originalSync })
			want := "replace native binding HEAD"
			if name == "HEAD replace" {
				runtimeReplaceHead = func(string, string) error { return errors.New(want) }
			} else {
				want = "sync native binding"
				runtimeSyncDirectory = func(path string) error {
					if filepath.Clean(path) == filepath.Clean(runtimeStore.Dir) {
						return errors.New(want)
					}
					return originalSync(path)
				}
			}
			_, err = BindApprovedReview(context.Background(), root, "thin", "approved-thin", "")
			runtimeReplaceHead, runtimeSyncDirectory = originalReplace, originalSync
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("binding publication error = %v, want %q", err, want)
			}
			after, loadErr := store.Load()
			if loadErr != nil || after.Revision != before.Revision || !reflect.DeepEqual(after.State, before.State) {
				t.Fatalf("binding publication changed authority: before=%#v after=%#v error=%v", before, after, loadErr)
			}

			if name == "HEAD replace" {
				if _, statErr := os.Stat(filepath.Join(runtimeStore.Dir, "HEAD")); !os.IsNotExist(statErr) {
					t.Fatalf("failed HEAD replace published binding: %v", statErr)
				}
				if _, retryErr := BindApprovedReview(context.Background(), root, "thin", "approved-thin", ""); retryErr != nil {
					t.Fatalf("HEAD replace retry did not reuse immutable record: %v", retryErr)
				}
				return
			}

			assertNativeBinding(t, runtimeStore, mustBindingRevision(t, root, "thin"))
			runtimeSyncDirectory = func(path string) error {
				if filepath.Clean(path) == filepath.Clean(runtimeStore.Dir) {
					return errors.New("sync native binding again")
				}
				return originalSync(path)
			}
			_, retryErr := BindApprovedReview(context.Background(), root, "thin", "approved-thin", "")
			var publicationErr *ReviewBindingPublicationError
			if !errors.As(retryErr, &publicationErr) {
				t.Fatalf("repeated sync failure = %T %v, want ReviewBindingPublicationError", retryErr, retryErr)
			}
			syncs := 0
			runtimeSyncDirectory = func(path string) error {
				if filepath.Clean(path) == filepath.Clean(runtimeStore.Dir) {
					syncs++
				}
				return originalSync(path)
			}
			_, retryErr = BindApprovedReview(context.Background(), root, "thin", "approved-thin", "")
			runtimeSyncDirectory = originalSync
			if retryErr != nil || syncs != 1 {
				t.Fatalf("binding retry did not repeat native directory sync: syncs=%d err=%v", syncs, retryErr)
			}
		})
	}
}

func TestBindingFailsClosedForLedgerDriftAndChangedLiveEvidence(t *testing.T) {
	for _, tt := range []struct {
		name   string
		mutate func(t *testing.T, root, changeRoot string)
	}{
		{name: "mismatched external ledger", mutate: func(t *testing.T, _ string, changeRoot string) {
			if err := os.MkdirAll(filepath.Join(changeRoot, "reviews"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(changeRoot, "reviews", "ledger.json"), []byte(`{"schema":"gentle-ai.review-ledger/v1","findings":[{"id":"wrong"}]}`), 0o644); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "staged candidate drift", mutate: func(t *testing.T, root, changeRoot string) {
			if err := os.WriteFile(filepath.Join(changeRoot, "tasks.md"), []byte("- [x] 1.1 Done\n# staged drift\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			runSDDStatusGit(t, root, "add", "openspec/changes/thin/tasks.md")
		}},
		{name: "committed candidate drift", mutate: func(t *testing.T, root, changeRoot string) {
			if err := os.WriteFile(filepath.Join(changeRoot, "tasks.md"), []byte("- [x] 1.1 Done\n# committed drift\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			runSDDStatusGit(t, root, "add", "openspec/changes/thin/tasks.md")
			runSDDStatusGit(t, root, "commit", "-qm", "drift")
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			changeRoot := seedReadyChange(t, root, "thin", "- [x] 1.1 Done\n")
			writeApprovedCompactAuthorityForChange(t, root, changeRoot, "approved-thin")
			tt.mutate(t, root, changeRoot)
			if _, err := BindApprovedReview(context.Background(), root, "thin", "approved-thin", ""); err == nil {
				t.Fatal("changed live evidence created a binding")
			}
			runtimeStore := mustRuntimeStore(t, root, "thin")
			if _, err := os.Stat(filepath.Join(runtimeStore.Dir, "HEAD")); !os.IsNotExist(err) {
				t.Fatalf("failed bind mutated native binding authority: %v", err)
			}
		})
	}
}

func TestResolveRejectsCorruptOrChangedBoundEvidence(t *testing.T) {
	for _, tt := range []struct {
		name     string
		wantNext string
		mutate   func(t *testing.T, root string, store reviewtransaction.CompactStore, binding ReviewBinding)
	}{
		{name: "corrupt binding", wantNext: "resolve-blockers", mutate: func(t *testing.T, root string, _ reviewtransaction.CompactStore, _ ReviewBinding) {
			corruptNativeRuntimeBinding(t, mustRuntimeStore(t, root, "thin"))
		}},
		{name: "changed receipt", wantNext: "resolve-review", mutate: func(t *testing.T, _ string, store reviewtransaction.CompactStore, _ ReviewBinding) {
			if err := os.WriteFile(store.ReceiptPath(), []byte("{}\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			changeRoot := seedReadyChange(t, root, "thin", "- [x] 1.1 Done\n")
			writeApprovedCompactAuthorityForChange(t, root, changeRoot, "approved-thin")
			binding, err := BindApprovedReview(context.Background(), root, "thin", "approved-thin", "")
			if err != nil {
				t.Fatal(err)
			}
			store, _ := reviewtransaction.CompactAuthoritativeStore(context.Background(), root, "approved-thin")
			tt.mutate(t, root, store, binding)
			status, err := Resolve(ResolveOptions{CWD: root, ChangeName: "thin"})
			if err != nil {
				t.Fatal(err)
			}
			if status.NextRecommended != tt.wantNext || status.Dependencies.Verify != DependencyBlocked {
				t.Fatalf("%s status = %#v", tt.name, status)
			}
		})
	}
}

func TestBoundReviewUsesNormalVerifyThenArchiveRouting(t *testing.T) {
	root := t.TempDir()
	changeRoot := seedReadyChange(t, root, "thin", "- [x] 1.1 Done\n")
	write(t, filepath.Join(changeRoot, "specs", "auth", "spec.md"), "### Requirement: Binding\n#### Scenario: Exact authority\n")
	writeApprovedCompactAuthorityForChange(t, root, changeRoot, "approved-thin")
	if _, err := BindApprovedReview(context.Background(), root, "thin", "approved-thin", ""); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(changeRoot, "verify-report.md"), boundedVerifyEnvelope(shaID("a"), "pass"))

	status, err := Resolve(ResolveOptions{CWD: root, ChangeName: "thin"})
	if err != nil {
		t.Fatal(err)
	}
	if status.Dependencies.Verify != DependencyAllDone || status.Dependencies.Archive != DependencyReady || status.NextRecommended != "archive" || status.ReviewGate == nil || status.ReviewGate.Result != reviewtransaction.GateAllow {
		t.Fatalf("bound completed verification status = %#v", status)
	}
	corruptNativeRuntimeBinding(t, mustRuntimeStore(t, root, "thin"))
	status, err = Resolve(ResolveOptions{CWD: root, ChangeName: "thin"})
	if err != nil {
		t.Fatal(err)
	}
	if status.Dependencies.Archive != DependencyBlocked || status.NextRecommended != "resolve-blockers" {
		t.Fatalf("corrupt completed binding status = %#v", status)
	}
}

func TestBoundReviewRoutesStaleVerifyEvidenceToVerify(t *testing.T) {
	root := t.TempDir()
	changeRoot := seedReadyChange(t, root, "thin", "- [x] 1.1 Done\n")
	write(t, filepath.Join(changeRoot, "specs", "auth", "spec.md"), "### Requirement: Binding\n#### Scenario: Exact authority\n#### Scenario: Added after verification\n")
	writeApprovedCompactAuthorityForChange(t, root, changeRoot, "approved-thin")
	if _, err := BindApprovedReview(context.Background(), root, "thin", "approved-thin", ""); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(changeRoot, "verify-report.md"), boundedVerifyEnvelope(shaID("a"), "pass"))

	status, err := Resolve(ResolveOptions{CWD: root, ChangeName: "thin"})
	if err != nil {
		t.Fatal(err)
	}
	if status.ReviewGate == nil || status.ReviewGate.Result != reviewtransaction.GateAllow {
		t.Fatalf("ReviewGate = %#v, want allow", status.ReviewGate)
	}
	if len(status.BlockedReasons) != 0 {
		t.Fatalf("BlockedReasons = %v, want empty", status.BlockedReasons)
	}
	if status.Dependencies.Verify != DependencyReady || status.Dependencies.Archive != DependencyBlocked || status.NextRecommended != "verify" {
		t.Fatalf("verify=%q archive=%q next=%q, want ready/blocked/verify", status.Dependencies.Verify, status.Dependencies.Archive, status.NextRecommended)
	}
	if status.RemediationState != (RemediationState{}) {
		t.Fatalf("RemediationState = %#v, want empty for stale evidence", status.RemediationState)
	}
}

func TestBoundReviewGrantsCompactRemediationBudgetForFailedVerdictWithIncompleteScenarios(t *testing.T) {
	root := t.TempDir()
	changeRoot := seedReadyChange(t, root, "thin", "- [x] 1.1 Done\n")
	write(t, filepath.Join(changeRoot, "specs", "auth", "spec.md"), "### Requirement: Binding\n#### Scenario: Exact authority\n#### Scenario: Added after verification\n")
	writeApprovedCompactAuthorityForChange(t, root, changeRoot, "approved-thin")
	if _, err := BindApprovedReview(context.Background(), root, "thin", "approved-thin", ""); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(changeRoot, "verify-report.md"), boundedVerifyEnvelope(shaID("a"), "fail"))

	status, err := Resolve(ResolveOptions{CWD: root, ChangeName: "thin"})
	if err != nil {
		t.Fatal(err)
	}
	if status.Dependencies.Verify != DependencyBlocked || status.NextRecommended != "remediate" {
		t.Fatalf("verify=%q next=%q, want blocked/remediate for failed verdict", status.Dependencies.Verify, status.NextRecommended)
	}
	if !status.RemediationState.Required || status.RemediationState.CorrectionBudget <= 0 || status.RemediationState.LineageID != "approved-thin" || status.RemediationState.FailedEvidenceRevision != shaID("a") {
		t.Fatalf("RemediationState = %#v, want transaction-bound nonzero compact budget", status.RemediationState)
	}
}

func TestSelectedBindingSupersedesOnlyItsLegacyReviewAuthority(t *testing.T) {
	root := t.TempDir()
	changeRoot := seedReadyChange(t, root, "thin", "- [x] 1.1 Done\n")
	write(t, filepath.Join(changeRoot, "specs", "auth", "spec.md"), "### Requirement: Binding\n#### Scenario: Exact authority\n")
	write(t, filepath.Join(changeRoot, "verify-report.md"), boundedVerifyEnvelope(shaID("a"), "pass"))
	writeApprovedReviewArtifacts(t, changeRoot)
	if err := os.Remove(filepath.Join(changeRoot, "verify-report.md")); err != nil {
		t.Fatal(err)
	}
	writeApprovedCompactAuthorityForChange(t, root, changeRoot, "approved-thin")
	if _, err := BindApprovedReview(context.Background(), root, "thin", "approved-thin", ""); err != nil {
		t.Fatal(err)
	}
	legacy, err := reviewtransaction.AuthoritativeStore(context.Background(), root, "thin-lineage")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := legacy.LoadChain(); err != nil {
		t.Fatalf("binding removed or changed legacy authority: %v", err)
	}
	status, err := Resolve(ResolveOptions{CWD: root, ChangeName: "thin"})
	if err != nil {
		t.Fatal(err)
	}
	if status.NextRecommended != "verify" || status.Dependencies.Verify != DependencyReady || status.ReviewGate == nil || status.ReviewGate.Result != reviewtransaction.GateAllow {
		t.Fatalf("selected binding did not supersede only the selected legacy authority: %#v", status)
	}
}

func TestValidBindingDoesNotAdvanceIncompleteApply(t *testing.T) {
	root := t.TempDir()
	changeRoot := seedReadyChange(t, root, "thin", "- [ ] 1.1 Pending\n")
	writeApprovedCompactAuthorityForChangeWithTasks(t, root, changeRoot, "approved-thin", "- [ ] 1.1 Pending\n# approved compact scope\n")
	if _, err := BindApprovedReview(context.Background(), root, "thin", "approved-thin", ""); err != nil {
		t.Fatal(err)
	}
	status, err := Resolve(ResolveOptions{CWD: root, ChangeName: "thin"})
	if err != nil {
		t.Fatal(err)
	}
	if status.ApplyState != ApplyReady || status.Dependencies.Apply != DependencyReady || status.Dependencies.Verify != DependencyBlocked || status.Dependencies.Archive != DependencyBlocked || status.NextRecommended != "apply" {
		t.Fatalf("incomplete bound status = %#v", status)
	}
}

func TestBindApprovedReviewSanitizesHostileGitEnvironmentFromSubdirectory(t *testing.T) {
	root := t.TempDir()
	changeRoot := seedReadyChange(t, root, "thin", "- [x] 1.1 Done\n")
	writeApprovedCompactAuthorityForChange(t, root, changeRoot, "approved-thin")
	subdirectory := filepath.Join(root, "nested")
	if err := os.MkdirAll(subdirectory, 0o755); err != nil {
		t.Fatal(err)
	}
	hostile := t.TempDir()
	runSDDStatusGit(t, hostile, "init", "-q")
	for name, value := range map[string]string{
		"GIT_DIR":        filepath.Join(hostile, ".git"),
		"GIT_WORK_TREE":  hostile,
		"GIT_COMMON_DIR": filepath.Join(hostile, ".git"),
		"GIT_INDEX_FILE": filepath.Join(hostile, ".git", "index"),
	} {
		t.Setenv(name, value)
	}
	t.Chdir(root)
	if _, err := BindApprovedReview(context.Background(), "nested", "thin", "approved-thin", ""); err != nil {
		t.Fatal(err)
	}
	assertNativeBinding(t, mustRuntimeStore(t, root, "thin"), mustBindingRevision(t, root, "thin"))
}

func mustRuntimeStore(t *testing.T, repo, change string) RuntimeStore {
	t.Helper()
	store, err := OpenRuntimeStore(context.Background(), repo, change)
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func mustBindingRevision(t *testing.T, repo, change string) string {
	t.Helper()
	status, err := mustRuntimeStore(t, repo, change).Status()
	if err != nil || status.Binding == nil {
		t.Fatalf("native binding status = %#v, err=%v", status, err)
	}
	return status.BindingRevision
}

func assertNativeBinding(t *testing.T, store RuntimeStore, want string) {
	t.Helper()
	status, err := store.Status()
	if err != nil || status.Binding == nil || status.Binding.Revision != want || status.BindingRevision != want {
		t.Fatalf("native binding status = %#v, err=%v, want=%q", status, err, want)
	}
	legacyPath := filepath.Join(store.commonDir, "gentle-ai", "sdd-review-bindings", "v1", store.Change, "binding.json")
	if _, statErr := os.Stat(legacyPath); !os.IsNotExist(statErr) {
		t.Fatalf("native bind unexpectedly dual-wrote legacy compatibility artifact: %v", statErr)
	}
}

func corruptNativeRuntimeBinding(t *testing.T, store RuntimeStore) {
	t.Helper()
	status, err := store.Status()
	if err != nil || status.Revision == "" {
		t.Fatalf("load native binding before corruption: status=%#v err=%v", status, err)
	}
	path := filepath.Join(store.Dir, "records", strings.TrimPrefix(status.Revision, "sha256:")+".json")
	if err := os.WriteFile(path, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

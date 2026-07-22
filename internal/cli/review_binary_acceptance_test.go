package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/gentleman-programming/gentle-ai/internal/reviewtransaction"
)

func TestWindowsPowerShell51ArtifactManifestFileFinalize(t *testing.T) {
	if testing.Short() {
		t.Skip("requires a real binary and Windows PowerShell 5.1")
	}
	if runtime.GOOS != "windows" {
		t.Skip("Windows-only PowerShell 5.1 acceptance test")
	}
	binary := os.Getenv("GENTLE_AI_TEST_BINARY")
	if binary == "" {
		t.Skip("requires GENTLE_AI_TEST_BINARY built from the branch under test")
	}
	if _, err := os.Stat(binary); err != nil {
		t.Fatalf("GENTLE_AI_TEST_BINARY: %v", err)
	}
	powershell, err := exec.LookPath("powershell.exe")
	if err != nil {
		t.Skip("Windows PowerShell is not installed")
	}
	version, err := exec.Command(powershell, "-NoProfile", "-NonInteractive", "-Command", `$PSVersionTable.PSEdition + '|' + $PSVersionTable.PSVersion.ToString()`).CombinedOutput()
	if err != nil {
		t.Skipf("Windows PowerShell version probe unavailable: %v", err)
	}
	if got := strings.TrimSpace(string(version)); !strings.HasPrefix(got, "Desktop|5.1") {
		t.Skipf("requires Windows PowerShell 5.1, got %q", got)
	}

	repo := initReviewCLIRepo(t)
	if err := os.WriteFile(filepath.Join(repo, "tracked.txt"), []byte("candidate\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var started ReviewFacadeStartResult
	decodeBinaryJSON(t, runReviewBinary(t, binary, true, "start", "--cwd", repo), &started)
	store, err := reviewtransaction.CompactAuthoritativeStore(context.Background(), repo, started.LineageID)
	if err != nil {
		t.Fatal(err)
	}
	record, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(record.State.SelectedLenses) != 1 {
		t.Fatalf("selected lenses = %v, want one", record.State.SelectedLenses)
	}

	temp := t.TempDir()
	input := filepath.Join(temp, "reviewer.json")
	evidence := filepath.Join(temp, "evidence.txt")
	manifest := filepath.Join(temp, "manifest.json")
	script := filepath.Join(temp, "finalize.ps1")
	if err := os.WriteFile(input, powerShell51ReviewerPayloadForTest(t, repo, record, record.State.SelectedLenses[0], 0), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(evidence, []byte("focused artifact transport acceptance passed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	const source = `param(
    [string]$Binary, [string]$Repo, [string]$Lineage, [string]$Target,
    [string]$Lens, [string]$Order, [string]$ResultPath, [string]$EvidencePath, [string]$Manifest
)
$captured = & $Binary review capture-result --cwd $Repo --lineage $Lineage --target $Target --lens $Lens --order $Order --input $ResultPath
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
$manifestText = [string]::Join([Environment]::NewLine, [string[]]$captured)
[System.IO.File]::WriteAllText($Manifest, $manifestText, (New-Object System.Text.UTF8Encoding($true)))
& $Binary review finalize --cwd $Repo --lineage $Lineage --result-artifact-file $Manifest --evidence $EvidencePath
exit $LASTEXITCODE
`
	if err := os.WriteFile(script, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(powershell, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", script,
		"-Binary", binary, "-Repo", repo, "-Lineage", started.LineageID, "-Target", record.State.InitialSnapshot.Identity,
		"-Lens", record.State.SelectedLenses[0], "-Order", "0", "-ResultPath", input, "-EvidencePath", evidence, "-Manifest", manifest)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("PowerShell 5.1 artifact-file finalize: %v\n%s", err, output)
	}
	manifestBytes, err := os.ReadFile(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if len(manifestBytes) < 3 || string(manifestBytes[:3]) != "\xef\xbb\xbf" {
		t.Fatal("PowerShell manifest file does not contain a UTF-8 BOM")
	}
	var finalized ReviewFacadeFinalizeResult
	decodeBinaryJSON(t, output, &finalized)
	status := binaryReviewStatus(t, binary, repo, started.LineageID)
	if finalized.State != reviewtransaction.StateApproved || status.Authority == nil || status.Authority.State != reviewtransaction.StateApproved || status.Receipt.Status != ReviewReceiptPresent || status.Receipt.Identity == "" {
		t.Fatalf("approved status = %#v, finalize = %#v", status, finalized)
	}
}

func TestPowerShell51ReviewerPayloadBindsProviderArtifactSubject(t *testing.T) {
	repo, started, _, record := newArtifactReview(t, false)
	lens := record.State.SelectedLenses[0]
	input := filepath.Join(t.TempDir(), "reviewer.json")
	if err := os.WriteFile(input, powerShell51ReviewerPayloadForTest(t, repo, record, lens, 0), 0o600); err != nil {
		t.Fatal(err)
	}

	var output bytes.Buffer
	if err := RunReviewCaptureResult([]string{
		"--cwd", repo,
		"--lineage", started.LineageID,
		"--target", record.State.InitialSnapshot.Identity,
		"--lens", lens,
		"--order", "0",
		"--input", input,
	}, &output); err != nil {
		t.Fatalf("PowerShell reviewer fixture omitted its provider-owned artifact subject: %v", err)
	}
	var artifact reviewResultArtifact
	decodeStrictReviewJSON(t, output.Bytes(), &artifact)
	if artifact.SubjectHash == "" {
		t.Fatal("captured PowerShell reviewer fixture has no provider-owned artifact subject")
	}
}

func powerShell51ReviewerPayloadForTest(t *testing.T, repo string, record reviewtransaction.CompactRecord, lens string, order int) []byte {
	t.Helper()
	return admittedReviewerPayloadForTest(t, repo, record, lens, order,
		"checked exact target through Windows PowerShell 5.1")
}

func TestMainBinaryAcceptsCorrectedCandidateFromLinkedWorktree(t *testing.T) {
	binary := os.Getenv("GENTLE_AI_TEST_BINARY")
	if binary == "" {
		t.Skip("requires GENTLE_AI_TEST_BINARY built from the branch under test")
	}
	if _, err := os.Stat(binary); err != nil {
		t.Fatalf("GENTLE_AI_TEST_BINARY: %v", err)
	}

	t.Run("approves corrected linked worktree", func(t *testing.T) {
		_, corrected, started := prepareBinaryCorrection(t, binary)
		writeBinaryCandidate(t, corrected, "fixed")
		validation := filepath.Join(t.TempDir(), "validation.json")
		writeReviewCLIJSON(t, validation, facadeValidationResult{
			OriginalCriteria:     facadeValidationCheck{Passed: true, Evidence: []string{"original acceptance passed"}},
			CorrectionRegression: facadeValidationCheck{Passed: true, Evidence: []string{"targeted regression passed"}},
			FollowUps:            []reviewtransaction.FollowUp{},
		})
		var validating ReviewFacadeFinalizeResult
		decodeBinaryJSON(t, runReviewBinary(t, binary, true, "finalize", "--cwd", corrected, "--validation", validation), &validating)
		if validating.State != reviewtransaction.StateValidating {
			t.Fatalf("validation state = %q", validating.State)
		}
		status := binaryReviewStatus(t, binary, corrected, started.LineageID)
		if status.Projection.InitialReviewTree == status.Projection.CurrentCandidateTree {
			t.Fatal("corrected candidate tree remained unchanged")
		}
		evidence := filepath.Join(t.TempDir(), "evidence.txt")
		if err := os.WriteFile(evidence, []byte("focused and full tests pass\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		var approved ReviewFacadeFinalizeResult
		decodeBinaryJSON(t, runReviewBinary(t, binary, true, "finalize", "--cwd", corrected, "--evidence", evidence), &approved)
		status = binaryReviewStatus(t, binary, corrected, started.LineageID)
		if approved.State != reviewtransaction.StateApproved || status.Authority == nil || status.Authority.State != reviewtransaction.StateApproved || status.Receipt.Status != ReviewReceiptPresent || status.Receipt.Identity == "" {
			t.Fatalf("approved status = %#v, finalize = %#v", status, approved)
		}
		var validated ReviewValidateResult
		decodeBinaryJSON(t, runReviewBinary(t, binary, true,
			"validate", "--cwd", corrected, "--lineage", started.LineageID, "--gate", string(reviewtransaction.GatePostApply)), &validated)
		if !validated.Allowed || validated.Result != reviewtransaction.GateAllow {
			t.Fatalf("post-apply validation = %#v", validated)
		}
		var binding map[string]any
		decodeBinaryJSON(t, runReviewBinary(t, binary, true,
			"bind-sdd", "--cwd", corrected, "--change", "binary-review", "--lineage", started.LineageID, "--expected-binding-revision="), &binding)
		if binding["schema"] != "gentle-ai.sdd-review-binding/v1" {
			t.Fatalf("SDD review binding = %#v", binding)
		}
	})

	for _, test := range []struct {
		name   string
		mutate func(*testing.T, string)
	}{
		{name: "rejects unchanged candidate", mutate: func(t *testing.T, repo string) { writeBinaryCandidate(t, repo, "wrong") }},
		{name: "rejects path expansion", mutate: func(t *testing.T, repo string) {
			writeBinaryCandidate(t, repo, "fixed")
			if err := os.WriteFile(filepath.Join(repo, "expanded.txt"), []byte("outside frozen scope\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			repo, corrected, started := prepareBinaryCorrection(t, binary)
			test.mutate(t, corrected)
			validation := filepath.Join(t.TempDir(), "validation.json")
			writeReviewCLIJSON(t, validation, facadeValidationResult{
				OriginalCriteria:     facadeValidationCheck{Passed: true, Evidence: []string{"original acceptance passed"}},
				CorrectionRegression: facadeValidationCheck{Passed: true, Evidence: []string{"targeted regression passed"}},
				FollowUps:            []reviewtransaction.FollowUp{},
			})
			runReviewBinary(t, binary, false, "finalize", "--cwd", corrected, "--validation", validation)
			status := binaryReviewStatus(t, binary, repo, started.LineageID)
			if status.Authority == nil || status.Authority.State != reviewtransaction.StateCorrectionRequired || status.Receipt.Status != ReviewReceiptExpectedMissing {
				t.Fatalf("rejected correction mutated public authority: %#v", status)
			}
		})
	}
}

func prepareBinaryCorrection(t *testing.T, binary string) (string, string, ReviewFacadeStartResult) {
	t.Helper()
	repo := initReviewCLIRepo(t)
	change := filepath.Join(repo, "openspec", "changes", "binary-review")
	for path, content := range map[string]string{
		"tasks.md":    "- [x] 1.1 Exercise the native review lifecycle\n",
		"proposal.md": "# Binary review acceptance\n",
	} {
		fullPath := filepath.Join(change, path)
		if err := os.MkdirAll(filepath.Dir(fullPath), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(fullPath, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	runReviewCLIGit(t, repo, "add", "openspec")
	runReviewCLIGit(t, repo, "commit", "-qm", "add binary review fixture")
	writeBinaryCandidate(t, repo, "wrong")
	var started ReviewFacadeStartResult
	decodeBinaryJSON(t, runReviewBinary(t, binary, true, "start", "--cwd", repo), &started)
	reviewer := filepath.Join(t.TempDir(), "reviewer.json")
	writeReviewCLIJSON(t, reviewer, facadeReviewerResult{Findings: []facadeFinding{{
		Location: "tracked.txt:5", Severity: "CRITICAL", Claim: "candidate returns the wrong terminal value",
		ProofRefs: []string{"differential test fails only on candidate"}, EvidenceClass: reviewtransaction.EvidenceDeterministic, CausalDisposition: reviewtransaction.CausalIntroduced,
	}}, Evidence: []string{"focused differential test failed"}})
	var correction ReviewFacadeFinalizeResult
	decodeBinaryJSON(t, runReviewBinary(t, binary, true, "finalize", "--cwd", repo, "--result", reviewer), &correction)
	if correction.State != reviewtransaction.StateCorrectionRequired {
		t.Fatalf("review state = %q", correction.State)
	}
	runReviewBinary(t, binary, true, "finalize", "--cwd", repo, "--correction-lines", "2")
	corrected := filepath.Join(t.TempDir(), "corrected")
	runReviewCLIGit(t, repo, "worktree", "add", "--detach", corrected, "HEAD")
	return repo, corrected, started
}

func writeBinaryCandidate(t *testing.T, repo, value string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(repo, "tracked.txt"), []byte("base\none\ntwo\nthree\n"+value+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func runReviewBinary(t *testing.T, binary string, wantSuccess bool, args ...string) []byte {
	t.Helper()
	command := exec.Command(binary, append([]string{"review"}, args...)...)
	output, err := command.CombinedOutput()
	if (err == nil) != wantSuccess {
		t.Fatalf("gentle-ai review %v: %v\n%s", args, err, output)
	}
	return output
}

func decodeBinaryJSON(t *testing.T, payload []byte, target any) {
	t.Helper()
	if err := json.Unmarshal(payload, target); err != nil {
		t.Fatalf("decode binary output: %v\n%s", err, payload)
	}
}

func binaryReviewStatus(t *testing.T, binary, repo, lineage string) ReviewTargetStatusResult {
	t.Helper()
	var status ReviewTargetStatusResult
	decodeBinaryJSON(t, runReviewBinary(t, binary, true, "status", "--contract", ReviewIntegrationContractV1, "--cwd", repo, "--lineage", lineage), &status)
	return status
}

package reviewtransaction

import (
	"strings"
	"testing"
)

func admittedArtifactFixture(t *testing.T) (ArtifactSubject, FrozenCandidateContext, ArtifactAdmissionRequest) {
	t.Helper()
	state, revision, context := artifactSubjectFixture(t)
	subject, err := NewArtifactSubject(state, revision, context, LensReliability, 0, "")
	if err != nil {
		t.Fatal(err)
	}
	result := LensResult{
		Lens: LensReliability,
		Findings: []Finding{{
			ID: "R3-001", Lens: "reliability", Location: "internal/a.go:7", Severity: "WARNING",
			Claim: "the candidate loses the retry error", ProofRefs: []string{"diff: internal/a.go:7"},
		}},
		Evidence: []string{"inspection: internal/a.go:7 and internal/b.go:1", "test: go test ./internal/reviewtransaction"},
	}
	request := ArtifactAdmissionRequest{
		ExpectedSubject:   subject,
		FrozenContext:     context,
		EchoedSubjectHash: subject.SubjectHash,
		Inspection:        ArtifactInspection{Status: ArtifactInspectionCompleted, Paths: []string{"internal/a.go", "internal/b.go"}},
		Result:            result,
		RawPayload:        []byte("review complete\n{\"subject_hash\":\"" + subject.SubjectHash + "\"}"),
		CanonicalPayload:  []byte("{\"findings\":[],\"evidence\":[\"inspection\"]}\n"),
	}
	return subject, context, request
}

func TestExtractBoundedSingleJSONObject(t *testing.T) {
	payload := []byte("I inspected the frozen candidate.\n{\"findings\":[],\"evidence\":[\"brace } inside string\"]}\nDone.")
	extracted, decision, err := ExtractBoundedSingleJSONObject(payload, 4096)
	if err != nil || decision != ArtifactAdmissionCompleted {
		t.Fatalf("ExtractBoundedSingleJSONObject() = %q, %q, %v", extracted, decision, err)
	}
	if got := string(extracted); got != `{"findings":[],"evidence":["brace } inside string"]}` {
		t.Fatalf("extracted = %q", got)
	}

	_, decision, err = ExtractBoundedSingleJSONObject([]byte(`before {"findings":[]} between {"evidence":[]} after`), 4096)
	if err == nil || decision != ArtifactAdmissionAmbiguous {
		t.Fatalf("multiple objects = %q, %v; want ambiguous", decision, err)
	}
	_, decision, err = ExtractBoundedSingleJSONObject([]byte("no JSON here"), 4096)
	if err == nil || decision != ArtifactAdmissionIncomplete {
		t.Fatalf("missing object = %q, %v; want incomplete", decision, err)
	}
}

func TestAdmitArtifactRequiresCompletedBoundInScopeInspection(t *testing.T) {
	_, _, request := admittedArtifactFixture(t)
	canonical, admission, err := AdmitArtifact(request)
	if err != nil {
		t.Fatalf("AdmitArtifact() error = %v", err)
	}
	if admission.Decision != ArtifactAdmissionCompleted || admission.RawSHA256 == "" ||
		admission.CanonicalSHA256 == "" || admission.ResultHash != canonical.ResultHash {
		t.Fatalf("admission = %#v, canonical = %#v", admission, canonical)
	}
	if err := admission.Validate(request.ExpectedSubject); err != nil {
		t.Fatalf("admission.Validate() error = %v", err)
	}

	tests := []struct {
		name     string
		mutate   func(*ArtifactAdmissionRequest)
		decision ArtifactAdmissionDecision
	}{
		{name: "legacy subject omitted", mutate: func(r *ArtifactAdmissionRequest) { r.EchoedSubjectHash = "" }, decision: ArtifactAdmissionIncomplete},
		{name: "binding mismatch", mutate: func(r *ArtifactAdmissionRequest) { r.EchoedSubjectHash = "sha256:" + strings.Repeat("9", 64) }, decision: ArtifactAdmissionBindingMismatch},
		{name: "inspection unavailable", mutate: func(r *ArtifactAdmissionRequest) {
			r.Result.Findings = []Finding{}
			r.Result.Evidence = []string{"Inspection blocked: read access denied; no candidate contents were available."}
		}, decision: ArtifactAdmissionIncomplete},
		{name: "partial inspection", mutate: func(r *ArtifactAdmissionRequest) { r.Inspection.Paths = []string{"internal/a.go"} }, decision: ArtifactAdmissionIncomplete},
		{name: "out of scope finding", mutate: func(r *ArtifactAdmissionRequest) { r.Result.Findings[0].Location = "unrelated/old.go:3" }, decision: ArtifactAdmissionOutOfScope},
		{name: "out of scope proof", mutate: func(r *ArtifactAdmissionRequest) {
			r.Result.Findings[0].ProofRefs = []string{"diff: unrelated/old.go:3"}
		}, decision: ArtifactAdmissionOutOfScope},
		{name: "root path evidence outside scope", mutate: func(r *ArtifactAdmissionRequest) {
			r.Result.Evidence = append(r.Result.Evidence, "diff: secret.go:42")
		}, decision: ArtifactAdmissionOutOfScope},
		{name: "root path proof outside scope", mutate: func(r *ArtifactAdmissionRequest) {
			r.Result.Findings[0].ProofRefs = []string{"diff: secret.go:42"}
		}, decision: ArtifactAdmissionOutOfScope},
		{name: "non ASCII finding id", mutate: func(r *ArtifactAdmissionRequest) {
			r.Result.Findings[0].ID = "R3-é"
		}, decision: ArtifactAdmissionBindingMismatch},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, _, candidate := admittedArtifactFixture(t)
			tc.mutate(&candidate)
			_, admission, err := AdmitArtifact(candidate)
			if err == nil || admission.Decision != tc.decision {
				t.Fatalf("AdmitArtifact() decision = %q, error = %v; want %q", admission.Decision, err, tc.decision)
			}
		})
	}
}

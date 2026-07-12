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
	"reflect"
	"regexp"

	"github.com/gentleman-programming/gentle-ai/internal/reviewtransaction"
)

const reviewBindingSchema = "gentle-ai.sdd-review-binding/v1"

var reviewBindingChange = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)
var reviewBindingHash = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
var bindingFinalAuthorizationHook = func() {}

type ReviewBinding struct {
	Schema            string                        `json:"schema"`
	Revision          string                        `json:"revision"`
	Change            string                        `json:"change"`
	Lineage           string                        `json:"lineage"`
	AuthorityRevision string                        `json:"authority_revision"`
	ReceiptHash       string                        `json:"receipt_hash"`
	GateContext       reviewtransaction.GateContext `json:"gate_context"`
}

func BindApprovedReview(ctx context.Context, repo, change, lineage, expected string) (ReviewBinding, error) {
	if !validReviewBindingChange(change) {
		return ReviewBinding{}, errors.New("invalid OpenSpec change name")
	}
	root, err := (reviewtransaction.SnapshotBuilder{Repo: repo}).ResolveRepositoryRoot(ctx)
	if err != nil {
		return ReviewBinding{}, err
	}
	if info, statErr := os.Stat(filepath.Join(root, "openspec", "changes", change)); statErr != nil || !info.IsDir() {
		return ReviewBinding{}, errors.New("selected OpenSpec change does not exist")
	}
	store, err := reviewtransaction.CompactAuthoritativeStore(ctx, root, lineage)
	if err != nil {
		return ReviewBinding{}, err
	}
	record, err := store.Load()
	if err != nil || record.State.State != reviewtransaction.StateApproved {
		return ReviewBinding{}, errors.New("explicit compact authority is not approved")
	}
	payload, err := os.ReadFile(store.ReceiptPath())
	if err != nil {
		return ReviewBinding{}, err
	}
	receipt, err := reviewtransaction.ParseCompactReceipt(payload)
	authoritative, receiptErr := record.State.Receipt()
	if err != nil || receiptErr != nil || !reflect.DeepEqual(receipt, authoritative) {
		return ReviewBinding{}, errors.New("compact receipt does not match approved authority")
	}
	if err := verifyBindingLedger(root, change, record.State.Findings); err != nil {
		return ReviewBinding{}, err
	}
	input := reviewtransaction.NativeGateRequestInput{Gate: reviewtransaction.GatePostApply, LineageID: lineage}
	gate := reviewtransaction.EvaluateCompactGate(ctx, root, receipt, input)
	if gate.Result != reviewtransaction.GateAllow {
		return ReviewBinding{}, errors.New("compact post-apply gate is not allow")
	}
	binding := ReviewBinding{Schema: reviewBindingSchema, Change: change, Lineage: lineage, AuthorityRevision: record.Revision, ReceiptHash: bindingHash(payload), GateContext: gate.Context}
	binding.Revision = bindingDigest(binding)
	final, finalErr := store.Load()
	finalPayload, readErr := os.ReadFile(store.ReceiptPath())
	finalGate := reviewtransaction.EvaluateCompactGate(ctx, root, receipt, input)
	if finalErr != nil || readErr != nil || final.Revision != record.Revision || !bytes.Equal(payload, finalPayload) || finalGate.Result != reviewtransaction.GateAllow || !reflect.DeepEqual(gate.Context, finalGate.Context) {
		return ReviewBinding{}, errors.New("authority or live gate changed before binding publish")
	}
	return binding, writeBinding(bindingPath(store, change), expected, binding)
}

func validateBoundReview(ctx context.Context, repo, change string) (ReviewBinding, reviewtransaction.NativeGateEvaluation, error) {
	if !validReviewBindingChange(change) {
		return ReviewBinding{}, reviewtransaction.NativeGateEvaluation{}, errors.New("invalid OpenSpec change name")
	}
	root, err := (reviewtransaction.SnapshotBuilder{Repo: repo}).ResolveRepositoryRoot(ctx)
	if err != nil {
		return ReviewBinding{}, reviewtransaction.NativeGateEvaluation{}, err
	}
	probe, err := reviewtransaction.CompactAuthoritativeStore(ctx, root, "binding-probe")
	if err != nil {
		return ReviewBinding{}, reviewtransaction.NativeGateEvaluation{}, err
	}
	payload, err := os.ReadFile(bindingPath(probe, change))
	if err != nil {
		return ReviewBinding{}, reviewtransaction.NativeGateEvaluation{}, fmt.Errorf("approved review binding is missing: %w", err)
	}
	binding, err := parseBinding(payload)
	if err != nil {
		return ReviewBinding{}, reviewtransaction.NativeGateEvaluation{}, fmt.Errorf("approved review binding is invalid: %w", err)
	}
	if binding.Change != change {
		return ReviewBinding{}, reviewtransaction.NativeGateEvaluation{}, errors.New("approved review binding change does not match selected change")
	}
	store, err := reviewtransaction.CompactAuthoritativeStore(ctx, root, binding.Lineage)
	if err != nil {
		return ReviewBinding{}, reviewtransaction.NativeGateEvaluation{}, err
	}
	record, err := store.Load()
	if err != nil || record.Revision != binding.AuthorityRevision || record.State.State != reviewtransaction.StateApproved {
		return ReviewBinding{}, reviewtransaction.NativeGateEvaluation{}, errors.New("bound compact authority is stale or not approved")
	}
	receiptPayload, err := os.ReadFile(store.ReceiptPath())
	if err != nil || bindingHash(receiptPayload) != binding.ReceiptHash {
		return ReviewBinding{}, reviewtransaction.NativeGateEvaluation{}, errors.New("bound compact receipt changed")
	}
	receipt, err := reviewtransaction.ParseCompactReceipt(receiptPayload)
	authoritative, receiptErr := record.State.Receipt()
	if err != nil || receiptErr != nil || !reflect.DeepEqual(receipt, authoritative) {
		return ReviewBinding{}, reviewtransaction.NativeGateEvaluation{}, errors.New("bound compact receipt does not match approved authority")
	}
	if err := verifyBindingLedger(root, change, record.State.Findings); err != nil {
		return ReviewBinding{}, reviewtransaction.NativeGateEvaluation{}, err
	}
	evaluation := reviewtransaction.EvaluateCompactGate(ctx, root, receipt, reviewtransaction.NativeGateRequestInput{Gate: reviewtransaction.GatePostApply, LineageID: binding.Lineage})
	if evaluation.Result != reviewtransaction.GateAllow || !reflect.DeepEqual(evaluation.Context, binding.GateContext) {
		return ReviewBinding{}, reviewtransaction.NativeGateEvaluation{}, errors.New("bound compact post-apply gate context changed")
	}
	bindingFinalAuthorizationHook()
	finalBinding, bindingErr := os.ReadFile(bindingPath(probe, change))
	finalRecord, recordErr := store.Load()
	finalReceipt, receiptErr := os.ReadFile(store.ReceiptPath())
	if bindingErr != nil || recordErr != nil || receiptErr != nil || !bytes.Equal(finalBinding, payload) || finalRecord.Revision != record.Revision || !reflect.DeepEqual(finalRecord.State, record.State) || finalRecord.State.State != reviewtransaction.StateApproved || !bytes.Equal(finalReceipt, receiptPayload) || bindingHash(finalReceipt) != binding.ReceiptHash {
		return ReviewBinding{}, reviewtransaction.NativeGateEvaluation{}, errors.New("bound authority, receipt, or binding changed during final read")
	}
	finalReceiptValue, parseErr := reviewtransaction.ParseCompactReceipt(finalReceipt)
	finalAuthoritative, authorityErr := finalRecord.State.Receipt()
	if parseErr != nil || authorityErr != nil || !reflect.DeepEqual(finalReceiptValue, finalAuthoritative) {
		return ReviewBinding{}, reviewtransaction.NativeGateEvaluation{}, errors.New("bound compact receipt does not match final authority")
	}
	finalGate := reviewtransaction.EvaluateCompactGate(ctx, root, finalReceiptValue, reviewtransaction.NativeGateRequestInput{Gate: reviewtransaction.GatePostApply, LineageID: binding.Lineage})
	if finalGate.Result != reviewtransaction.GateAllow || !reflect.DeepEqual(finalGate.Context, binding.GateContext) {
		return ReviewBinding{}, reviewtransaction.NativeGateEvaluation{}, errors.New("bound compact post-apply gate changed during final authorization")
	}
	return binding, finalGate, nil
}

func bindingExists(ctx context.Context, repo, change string) (bool, error) {
	root, err := (reviewtransaction.SnapshotBuilder{Repo: repo}).ResolveRepositoryRoot(ctx)
	if err != nil {
		return false, nil
	}
	probe, err := reviewtransaction.CompactAuthoritativeStore(ctx, root, "binding-probe")
	if err != nil {
		return false, err
	}
	_, err = os.Stat(bindingPath(probe, change))
	if os.IsNotExist(err) {
		return false, nil
	}
	return err == nil, err
}

func verifyBindingLedger(root, change string, findings []reviewtransaction.Finding) error {
	payload, err := os.ReadFile(filepath.Join(root, "openspec", "changes", change, "reviews", "ledger.json"))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	want, err := reviewtransaction.CanonicalLedger(findings)
	if err != nil || !bytes.Equal(payload, want) {
		return errors.New("SDD review ledger does not equal compact findings")
	}
	return nil
}
func bindingPath(store reviewtransaction.CompactStore, change string) string {
	return filepath.Join(filepath.Dir(filepath.Dir(filepath.Dir(filepath.Dir(store.Dir)))), "gentle-ai", "sdd-review-bindings", "v1", change, "binding.json")
}
func bindingHash(payload []byte) string {
	sum := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(sum[:])
}
func bindingDigest(b ReviewBinding) string {
	b.Revision = ""
	payload, _ := json.Marshal(b)
	return bindingHash(payload)
}

func validReviewBindingChange(change string) bool {
	return len(change) <= 96 && reviewBindingChange.MatchString(change)
}

func bindingBytes(binding ReviewBinding) ([]byte, error) {
	payload, err := json.Marshal(binding)
	if err != nil {
		return nil, err
	}
	return append(payload, '\n'), nil
}

func parseBinding(payload []byte) (ReviewBinding, error) {
	var binding ReviewBinding
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&binding); err != nil {
		return ReviewBinding{}, err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return ReviewBinding{}, errors.New("multiple binding values")
	}
	canonical, err := bindingBytes(binding)
	if err != nil || !bytes.Equal(payload, canonical) || binding.Schema != reviewBindingSchema || !validReviewBindingChange(binding.Change) || !reviewBindingHash.MatchString(binding.Revision) || !reviewBindingHash.MatchString(binding.AuthorityRevision) || !reviewBindingHash.MatchString(binding.ReceiptHash) || binding.Revision != bindingDigest(binding) || binding.GateContext.Gate != reviewtransaction.GatePostApply || binding.GateContext.LineageID != binding.Lineage || binding.GateContext.StoreRevision != binding.AuthorityRevision {
		return ReviewBinding{}, errors.New("invalid binding")
	}
	return binding, nil
}

func writeBinding(path, expected string, binding ReviewBinding) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	lock, err := acquireBindingLock(filepath.Join(filepath.Dir(path), "LOCK"))
	if err != nil {
		return err
	}
	defer lock.release()
	current := ""
	if payload, err := os.ReadFile(path); err == nil {
		old, parseErr := parseBinding(payload)
		if parseErr != nil || old.Change != binding.Change {
			return errors.New("invalid existing binding")
		}
		current = old.Revision
		if current == binding.Revision {
			return nil
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	if current != expected {
		return fmt.Errorf("binding revision conflict: expected %q, current %q", expected, current)
	}
	payload, err := bindingBytes(binding)
	if err != nil {
		return err
	}
	temp, err := os.CreateTemp(filepath.Dir(path), ".binding-")
	if err != nil {
		return err
	}
	if _, err = temp.Write(payload); err == nil {
		err = temp.Sync()
	}
	if closeErr := temp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		_ = os.Remove(temp.Name())
		return err
	}
	return os.Rename(temp.Name(), path)
}

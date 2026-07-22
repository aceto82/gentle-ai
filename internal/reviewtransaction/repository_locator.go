package reviewtransaction

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

const (
	ReviewRepositoryContextCapability = "review.opaque_repository_context"
	ReviewRepositoryContextSchema     = "gentle-ai.review-repository-context/v1"

	reviewRepositoryContextHandlePrefix = "rctx1_"
	reviewRepositoryLocatorMaxBytes     = 64 << 10
)

// ReviewRepositoryContextBinding is the public, path-free portion of a
// provider-issued repository context. The handle is discovery only: current
// compact authority remains the sole authorization source.
type ReviewRepositoryContextBinding struct {
	LineageID      string `json:"lineage_id"`
	TargetIdentity string `json:"target_identity"`
	Revision       string `json:"revision"`
}

type reviewRepositoryIdentityRecord struct {
	RepositoryRoot     string `json:"repository_root"`
	GitCommonDir       string `json:"git_common_dir"`
	GitDir             string `json:"git_dir"`
	RepositoryIdentity string `json:"repository_identity"`
}

type reviewRepositoryContextFile struct {
	Schema             string `json:"schema"`
	Handle             string `json:"handle"`
	LineageID          string `json:"lineage_id"`
	TargetIdentity     string `json:"target_identity"`
	Revision           string `json:"revision"`
	RepositoryIdentity string `json:"repository_identity"`
	RepositoryRoot     string `json:"repository_root"`
	GitCommonDir       string `json:"git_common_dir"`
	GitDir             string `json:"git_dir"`
}

// DeriveReviewRepositoryContextHandle derives the path-free handle that START
// will publish after compact authority creation. It performs no filesystem
// publication and does not treat the handle as authorization.
func DeriveReviewRepositoryContextHandle(ctx context.Context, repo string, binding ReviewRepositoryContextBinding) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if err := validateReviewRepositoryContextBinding(binding); err != nil {
		return "", err
	}
	identity, err := reviewRepositoryIdentity(ctx, repo)
	if err != nil {
		return "", err
	}
	return reviewRepositoryContextHandle(binding, identity), nil
}

// ValidateReviewRepositoryContextHandle validates only the opaque transport
// shape. Resolution still performs repository and authority validation.
func ValidateReviewRepositoryContextHandle(handle string) error {
	if !validReviewRepositoryContextHandle(handle) {
		return errors.New("invalid review repository context handle")
	}
	return nil
}

// PublishReviewRepositoryContext publishes a private immutable locator and
// returns its opaque, deterministic handle. The record contains paths only in
// provider-private storage and is not authority.
func PublishReviewRepositoryContext(ctx context.Context, repo string, binding ReviewRepositoryContextBinding) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if err := validateReviewRepositoryContextBinding(binding); err != nil {
		return "", err
	}
	identity, err := reviewRepositoryIdentity(ctx, repo)
	if err != nil {
		return "", err
	}
	if err := validateLiveReviewRepositoryContext(ctx, identity.RepositoryRoot, binding); err != nil {
		return "", err
	}
	handle := reviewRepositoryContextHandle(binding, identity)
	path, err := reviewRepositoryContextPath(handle)
	if err != nil {
		return "", err
	}
	home, err := reviewRepositoryContextHome()
	if err != nil {
		return "", err
	}
	storageRoot, err := ensureReviewRepositoryContextStorageRoot(home, true)
	if err != nil {
		return "", err
	}
	if err := ensurePrivateLocatorDirectory(storageRoot, filepath.Dir(path)); err != nil {
		return "", err
	}
	record := reviewRepositoryContextFile{
		Schema: ReviewRepositoryContextSchema, Handle: handle,
		LineageID: binding.LineageID, TargetIdentity: binding.TargetIdentity, Revision: binding.Revision,
		RepositoryIdentity: identity.RepositoryIdentity, RepositoryRoot: identity.RepositoryRoot,
		GitCommonDir: identity.GitCommonDir, GitDir: identity.GitDir,
	}
	payload, err := json.Marshal(record)
	if err != nil {
		return "", err
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if err := publishReviewRepositoryContext(path, append(payload, '\n')); err != nil {
		return "", err
	}
	return handle, nil
}

// ResolveReviewRepositoryContext resolves one provider-issued handle from any
// process cwd, then revalidates its repository and current compact authority.
func ResolveReviewRepositoryContext(ctx context.Context, handle string, binding ReviewRepositoryContextBinding) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if err := ValidateReviewRepositoryContextHandle(handle); err != nil {
		return "", err
	}
	if err := validateReviewRepositoryContextBinding(binding); err != nil {
		return "", err
	}
	path, err := reviewRepositoryContextPath(handle)
	if err != nil {
		return "", err
	}
	home, err := reviewRepositoryContextHome()
	if err != nil {
		return "", err
	}
	storageRoot, err := ensureReviewRepositoryContextStorageRoot(home, false)
	if err != nil {
		return "", err
	}
	if err := validatePrivateLocatorDirectory(storageRoot, filepath.Dir(path)); err != nil {
		return "", err
	}
	payload, err := readReviewRepositoryContext(path)
	if err != nil {
		return "", err
	}
	var record reviewRepositoryContextFile
	if err := decodeReviewRepositoryContext(payload, &record); err != nil {
		return "", err
	}
	if record.Handle != handle || record.LineageID != binding.LineageID ||
		record.TargetIdentity != binding.TargetIdentity || record.Revision != binding.Revision {
		return "", errors.New("review repository context binding is invalid")
	}
	stored := reviewRepositoryIdentityRecord{
		RepositoryRoot: record.RepositoryRoot, GitCommonDir: record.GitCommonDir,
		GitDir: record.GitDir, RepositoryIdentity: record.RepositoryIdentity,
	}
	if reviewRepositoryIdentityHash(stored) != stored.RepositoryIdentity ||
		reviewRepositoryContextHandle(binding, stored) != handle {
		return "", errors.New("review repository context identity is invalid")
	}
	live, err := reviewRepositoryIdentity(ctx, stored.RepositoryRoot)
	if err != nil || !sameLocatorDirectory(stored.RepositoryRoot, live.RepositoryRoot) ||
		!sameLocatorDirectory(stored.GitCommonDir, live.GitCommonDir) ||
		!sameLocatorDirectory(stored.GitDir, live.GitDir) || live.RepositoryIdentity != stored.RepositoryIdentity {
		return "", errors.New("review repository context identity changed")
	}
	if err := validateLiveReviewRepositoryContext(ctx, live.RepositoryRoot, binding); err != nil {
		return "", err
	}
	return live.RepositoryRoot, nil
}

func validateLiveReviewRepositoryContext(ctx context.Context, repo string, binding ReviewRepositoryContextBinding) error {
	store, err := CompactAuthoritativeStore(ctx, repo, binding.LineageID)
	if err != nil {
		return err
	}
	record, err := store.Load()
	if err != nil {
		return err
	}
	if record.Revision != binding.Revision || record.State.State != StateReviewing ||
		record.State.LineageID != binding.LineageID || record.State.InitialSnapshot.Identity != binding.TargetIdentity {
		return errors.New("review repository context is stale or has no live matching authority")
	}
	return nil
}

func validateReviewRepositoryContextBinding(binding ReviewRepositoryContextBinding) error {
	if validateLineageID(binding.LineageID) != nil || !validSHA256(binding.TargetIdentity) || !validSHA256(binding.Revision) {
		return errors.New("invalid review repository context binding")
	}
	return nil
}

func reviewRepositoryContextHandle(binding ReviewRepositoryContextBinding, identity reviewRepositoryIdentityRecord) string {
	preimage := struct {
		Schema             string `json:"schema"`
		LineageID          string `json:"lineage_id"`
		TargetIdentity     string `json:"target_identity"`
		Revision           string `json:"revision"`
		RepositoryIdentity string `json:"repository_identity"`
	}{
		Schema: ReviewRepositoryContextSchema, LineageID: binding.LineageID,
		TargetIdentity: binding.TargetIdentity, Revision: binding.Revision,
		RepositoryIdentity: identity.RepositoryIdentity,
	}
	payload, _ := json.Marshal(preimage)
	return reviewRepositoryContextHandlePrefix + identityHash(string(payload))
}

func validReviewRepositoryContextHandle(handle string) bool {
	if !strings.HasPrefix(handle, reviewRepositoryContextHandlePrefix) || len(handle) != len(reviewRepositoryContextHandlePrefix)+64 {
		return false
	}
	suffix := strings.TrimPrefix(handle, reviewRepositoryContextHandlePrefix)
	if suffix != strings.ToLower(suffix) {
		return false
	}
	_, err := hex.DecodeString(suffix)
	return err == nil
}

func reviewRepositoryContextPath(handle string) (string, error) {
	if err := ValidateReviewRepositoryContextHandle(handle); err != nil {
		return "", err
	}
	home, err := reviewRepositoryContextHome()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".gentle-ai", "review-contexts", "v1", handle+".json"), nil
}

func reviewRepositoryContextHome() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return canonicalLocatorDirectory(home)
}

func ensureReviewRepositoryContextStorageRoot(home string, create bool) (string, error) {
	root := filepath.Join(home, ".gentle-ai")
	if !locatorPathWithin(home, root) {
		return "", errors.New("review repository context storage root escapes HOME")
	}
	info, err := os.Lstat(root)
	if os.IsNotExist(err) && create {
		if err := os.Mkdir(root, 0o700); err != nil && !os.IsExist(err) {
			return "", err
		}
		info, err = os.Lstat(root)
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return "", errors.New("review repository context storage root is unsafe")
	}
	if create {
		if err := SyncReviewDirectory(home); err != nil {
			return "", err
		}
	}
	return root, nil
}

func publishReviewRepositoryContext(path string, payload []byte) error {
	existing, err := readReviewRepositoryContext(path)
	if err == nil {
		if !reviewRepositoryContextPayloadEqual(existing, payload) {
			return errors.New("existing review repository context differs")
		}
		return SyncReviewDirectory(filepath.Dir(path))
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	temp, err := os.CreateTemp(filepath.Dir(path), ".repository-context-")
	if err != nil {
		return err
	}
	defer os.Remove(temp.Name())
	if err = temp.Chmod(0o600); err == nil {
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
	if err = PublishFileNoReplace(temp.Name(), path); err != nil && !errors.Is(err, fs.ErrExist) {
		return err
	}
	existing, err = readReviewRepositoryContext(path)
	if err != nil || !reviewRepositoryContextPayloadEqual(existing, payload) {
		return errors.New("concurrent review repository context differs")
	}
	return SyncReviewDirectory(filepath.Dir(path))
}

func reviewRepositoryContextPayloadEqual(left, right []byte) bool {
	leftHash, rightHash := sha256.Sum256(left), sha256.Sum256(right)
	return leftHash == rightHash && bytes.Equal(left, right)
}

func readReviewRepositoryContext(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || !privateLocatorFileModeSafe(info.Mode()) {
		return nil, errors.New("review repository context is not a private regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !privateLocatorFileModeSafe(opened.Mode()) || !os.SameFile(info, opened) {
		return nil, errors.New("review repository context changed while opening")
	}
	payload, err := io.ReadAll(io.LimitReader(file, reviewRepositoryLocatorMaxBytes+1))
	if err != nil || len(payload) > reviewRepositoryLocatorMaxBytes {
		return nil, errors.New("review repository context is oversized")
	}
	var record reviewRepositoryContextFile
	if err := decodeReviewRepositoryContext(payload, &record); err != nil {
		return nil, err
	}
	return payload, nil
}

func decodeReviewRepositoryContext(payload []byte, target *reviewRepositoryContextFile) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) ||
		target.Schema != ReviewRepositoryContextSchema || !validReviewRepositoryContextHandle(target.Handle) ||
		validateReviewRepositoryContextBinding(ReviewRepositoryContextBinding{
			LineageID: target.LineageID, TargetIdentity: target.TargetIdentity, Revision: target.Revision,
		}) != nil || !validSHA256(target.RepositoryIdentity) || !filepath.IsAbs(target.RepositoryRoot) ||
		!filepath.IsAbs(target.GitCommonDir) || !filepath.IsAbs(target.GitDir) {
		return fs.ErrInvalid
	}
	return nil
}

func reviewRepositoryIdentity(ctx context.Context, repo string) (reviewRepositoryIdentityRecord, error) {
	if err := ctx.Err(); err != nil {
		return reviewRepositoryIdentityRecord{}, err
	}
	root, err := (SnapshotBuilder{Repo: repo}).ResolveRepositoryRoot(ctx)
	if err != nil {
		return reviewRepositoryIdentityRecord{}, err
	}
	root, err = canonicalLocatorDirectory(root)
	if err != nil {
		return reviewRepositoryIdentityRecord{}, err
	}
	topPayload, err := runGit(ctx, root, nil, nil, "rev-parse", "--path-format=absolute", "--show-toplevel")
	if err != nil {
		return reviewRepositoryIdentityRecord{}, err
	}
	top, err := canonicalLocatorDirectory(strings.TrimSpace(string(topPayload)))
	if err != nil || !sameLocatorDirectory(root, top) {
		return reviewRepositoryIdentityRecord{}, errors.New("repository root identity changed")
	}
	commonPayload, err := runGit(ctx, root, nil, nil, "rev-parse", "--path-format=absolute", "--git-common-dir")
	if err != nil {
		return reviewRepositoryIdentityRecord{}, err
	}
	commonDir, err := canonicalLocatorDirectory(strings.TrimSpace(string(commonPayload)))
	if err != nil {
		return reviewRepositoryIdentityRecord{}, err
	}
	gitPayload, err := runGit(ctx, root, nil, nil, "rev-parse", "--path-format=absolute", "--git-dir")
	if err != nil {
		return reviewRepositoryIdentityRecord{}, err
	}
	gitDir, err := canonicalLocatorDirectory(strings.TrimSpace(string(gitPayload)))
	if err != nil {
		return reviewRepositoryIdentityRecord{}, err
	}
	if !sameLocatorDirectory(gitDir, commonDir) && !locatorPathWithin(commonDir, gitDir) {
		return reviewRepositoryIdentityRecord{}, errors.New("Git directory escapes its common directory")
	}
	identity := reviewRepositoryIdentityRecord{RepositoryRoot: root, GitCommonDir: commonDir, GitDir: gitDir}
	identity.RepositoryIdentity = reviewRepositoryIdentityHash(identity)
	return identity, nil
}

func reviewRepositoryIdentityHash(identity reviewRepositoryIdentityRecord) string {
	preimage := struct {
		RepositoryRoot string `json:"repository_root"`
		GitCommonDir   string `json:"git_common_dir"`
		GitDir         string `json:"git_dir"`
	}{RepositoryRoot: filepath.Clean(identity.RepositoryRoot), GitCommonDir: filepath.Clean(identity.GitCommonDir), GitDir: filepath.Clean(identity.GitDir)}
	payload, _ := json.Marshal(preimage)
	return "sha256:" + identityHash(string(payload))
}

func canonicalLocatorDirectory(path string) (string, error) {
	absolute, err := filepath.Abs(strings.TrimSpace(path))
	if err != nil {
		return "", err
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return "", err
	}
	info, err := os.Stat(resolved)
	if err != nil || !info.IsDir() {
		return "", errors.New("review repository identity path is not a directory")
	}
	return filepath.Clean(resolved), nil
}

func ensurePrivateLocatorDirectory(base, dir string) error {
	return walkPrivateLocatorDirectory(base, dir, true)
}

func validatePrivateLocatorDirectory(base, dir string) error {
	return walkPrivateLocatorDirectory(base, dir, false)
}

func walkPrivateLocatorDirectory(base, dir string, create bool) error {
	baseAbs, err := filepath.Abs(base)
	if err != nil {
		return err
	}
	dirAbs, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	relative, err := filepath.Rel(filepath.Clean(baseAbs), filepath.Clean(dirAbs))
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || filepath.IsAbs(relative) {
		return errors.New("review repository context directory escapes its private root")
	}
	baseInfo, err := os.Lstat(baseAbs)
	if err != nil || baseInfo.Mode()&os.ModeSymlink != 0 || !baseInfo.IsDir() {
		return errors.New("review repository context private root is unsafe")
	}
	current := filepath.Clean(baseAbs)
	if relative == "." {
		return nil
	}
	for _, part := range strings.Split(relative, string(filepath.Separator)) {
		if part == "" || part == "." || part == ".." {
			return errors.New("review repository context directory is invalid")
		}
		parent := current
		current = filepath.Join(current, part)
		info, statErr := os.Lstat(current)
		if os.IsNotExist(statErr) && create {
			if err := os.Mkdir(current, 0o700); err != nil && !os.IsExist(err) {
				return err
			}
			info, statErr = os.Lstat(current)
		}
		if statErr != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || !privateLocatorDirectoryModeSafe(info.Mode()) {
			return errors.New("review repository context directory is unsafe")
		}
		if create {
			if err := SyncReviewDirectory(parent); err != nil {
				return err
			}
		}
	}
	return nil
}

func privateLocatorDirectoryModeSafe(mode fs.FileMode) bool {
	return runtime.GOOS == "windows" || mode.Perm()&0o077 == 0
}

func privateLocatorFileModeSafe(mode fs.FileMode) bool {
	return runtime.GOOS == "windows" || mode.Perm() == 0o600
}

func locatorPathWithin(base, candidate string) bool {
	relative, err := filepath.Rel(filepath.Clean(base), filepath.Clean(candidate))
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) && !filepath.IsAbs(relative)
}

func sameLocatorDirectory(left, right string) bool {
	leftInfo, leftErr := os.Stat(left)
	rightInfo, rightErr := os.Stat(right)
	return leftErr == nil && rightErr == nil && leftInfo.IsDir() && rightInfo.IsDir() && os.SameFile(leftInfo, rightInfo)
}

func identityHash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

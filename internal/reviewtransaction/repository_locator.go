package reviewtransaction

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

const (
	reviewRepositoryLocatorSchema   = "gentle-ai.review-repository-locator/v1"
	reviewRepositoryLocatorMaxBytes = 64 << 10
)

// ReviewRepositoryLocator keeps the unchanged four-field reviewer binding.
type ReviewRepositoryLocator struct {
	Lineage string `json:"lineage"`
	Target  string `json:"target"`
	Lens    string `json:"lens"`
	Order   int    `json:"order"`
}

type reviewRepositoryLocatorFile struct {
	Schema         string `json:"schema"`
	Lineage        string `json:"lineage"`
	Target         string `json:"target"`
	Lens           string `json:"lens"`
	Order          int    `json:"order"`
	RepositoryRoot string `json:"repository_root"`
	GitCommonDir   string `json:"git_common_dir"`
}

// PublishReviewRepositoryLocators writes private, immutable discovery hints.
// Hints are not authority and are revalidated by the deferred resolver.
func PublishReviewRepositoryLocators(ctx context.Context, repo string, locators []ReviewRepositoryLocator) error {
	root, commonDir, err := reviewRepositoryIdentity(ctx, repo)
	if err != nil {
		return err
	}
	for _, locator := range locators {
		if err := validateReviewRepositoryLocator(locator); err != nil {
			return err
		}
		path, err := reviewRepositoryLocatorPath(locator, root, commonDir)
		if err != nil {
			return err
		}
		if err := ensurePrivateLocatorDirectory(filepath.Dir(path)); err != nil {
			return err
		}
		payload, err := json.Marshal(reviewRepositoryLocatorFile{reviewRepositoryLocatorSchema, locator.Lineage, locator.Target, locator.Lens, locator.Order, root, commonDir})
		if err != nil {
			return err
		}
		if err := publishReviewRepositoryLocator(path, append(payload, '\n')); err != nil {
			return err
		}
	}
	return nil
}

// ResolveReviewRepository returns the sole repository whose untrusted locator
// and live compact authority both match the exact four-field binding.
func ResolveReviewRepository(ctx context.Context, locator ReviewRepositoryLocator) (string, error) {
	if err := validateReviewRepositoryLocator(locator); err != nil {
		return "", err
	}
	dir, err := reviewRepositoryLocatorBucket(locator)
	if err != nil {
		return "", err
	}
	entries, err := readReviewRepositoryLocatorBucket(dir)
	if err != nil {
		return "", err
	}
	valid := make([]string, 0, 1)
	for _, entry := range entries {
		if entry.IsDir() || entry.Type()&os.ModeSymlink != 0 || filepath.Ext(entry.Name()) != ".json" {
			return "", errors.New("review repository locator bucket is unsafe")
		}
		root, err := resolveReviewRepositoryCandidate(ctx, filepath.Join(dir, entry.Name()), locator)
		if err != nil {
			return "", err
		}
		valid = append(valid, root)
	}
	if len(valid) != 1 {
		return "", errors.New("review repository locator resolution requires exactly one candidate")
	}
	return valid[0], nil
}

func resolveReviewRepositoryCandidate(ctx context.Context, path string, want ReviewRepositoryLocator) (string, error) {
	payload, err := readReviewRepositoryLocator(path)
	if err != nil {
		return "", err
	}
	var candidate reviewRepositoryLocatorFile
	if err := decodeReviewRepositoryLocator(payload, &candidate); err != nil ||
		candidate.Lineage != want.Lineage || candidate.Target != want.Target || candidate.Lens != want.Lens || candidate.Order != want.Order ||
		filepath.Base(path) != identityHash(candidate.RepositoryRoot+"\x00"+candidate.GitCommonDir)+".json" {
		return "", errors.New("review repository locator binding is invalid")
	}
	root, commonDir, err := reviewRepositoryIdentity(ctx, candidate.RepositoryRoot)
	if err != nil || !sameLocatorDirectory(root, candidate.RepositoryRoot) || !sameLocatorDirectory(commonDir, candidate.GitCommonDir) {
		return "", errors.New("review repository locator identity changed")
	}
	store, err := CompactAuthoritativeStore(ctx, root, want.Lineage)
	if err != nil {
		return "", err
	}
	record, err := store.Load()
	if err != nil || record.State.State != StateReviewing || record.State.LineageID != want.Lineage ||
		record.State.InitialSnapshot.Identity != want.Target || want.Order >= len(record.State.SelectedLenses) ||
		record.State.SelectedLenses[want.Order] != want.Lens || len(record.State.LensResults) != want.Order {
		return "", errors.New("review repository locator has no live matching authority")
	}
	return root, nil
}

func reviewRepositoryLocatorBucket(locator ReviewRepositoryLocator) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".gentle-ai", "review-locators", "v1", locatorHash(locator)), nil
}

func readReviewRepositoryLocatorBucket(path string) ([]fs.DirEntry, error) {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return nil, errors.New("review repository locator bucket is unsafe")
	}
	dir, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	opened, err := dir.Stat()
	if err != nil || !opened.IsDir() || !os.SameFile(info, opened) {
		return nil, errors.New("review repository locator bucket changed while opening")
	}
	return dir.ReadDir(-1)
}

func publishReviewRepositoryLocator(path string, payload []byte) error {
	existing, err := readReviewRepositoryLocator(path)
	if err == nil {
		if !bytes.Equal(existing, payload) {
			return errors.New("existing review repository locator differs")
		}
		return nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	temp, err := os.CreateTemp(filepath.Dir(path), ".locator-")
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
	if err = PublishFileNoReplace(temp.Name(), path); !errors.Is(err, fs.ErrExist) {
		return err
	}
	existing, err = readReviewRepositoryLocator(path)
	if err != nil || !bytes.Equal(existing, payload) {
		return errors.New("concurrent review repository locator differs")
	}
	return nil
}

func readReviewRepositoryLocator(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, errors.New("review repository locator is not a regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		return nil, errors.New("review repository locator changed while opening")
	}
	payload, err := io.ReadAll(io.LimitReader(file, reviewRepositoryLocatorMaxBytes+1))
	if err != nil || len(payload) > reviewRepositoryLocatorMaxBytes {
		return nil, errors.New("review repository locator is oversized")
	}
	var locator reviewRepositoryLocatorFile
	if err := decodeReviewRepositoryLocator(payload, &locator); err != nil {
		return nil, err
	}
	return payload, nil
}

func decodeReviewRepositoryLocator(payload []byte, target *reviewRepositoryLocatorFile) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) || target.Schema != reviewRepositoryLocatorSchema ||
		validateReviewRepositoryLocator(ReviewRepositoryLocator{target.Lineage, target.Target, target.Lens, target.Order}) != nil ||
		!filepath.IsAbs(target.RepositoryRoot) || !filepath.IsAbs(target.GitCommonDir) {
		return fs.ErrInvalid
	}
	return nil
}

func reviewRepositoryIdentity(ctx context.Context, repo string) (string, string, error) {
	root, err := (SnapshotBuilder{Repo: repo}).ResolveRepositoryRoot(ctx)
	if err != nil {
		return "", "", err
	}
	common, err := runGit(ctx, root, nil, nil, "rev-parse", "--path-format=absolute", "--git-common-dir")
	if err != nil {
		return "", "", err
	}
	commonDir, err := filepath.EvalSymlinks(strings.TrimSpace(string(common)))
	if err != nil {
		return "", "", err
	}
	if !sameLocatorDirectory(root, root) || !sameLocatorDirectory(commonDir, commonDir) {
		return "", "", errors.New("repository identity is not a directory")
	}
	return root, filepath.Clean(commonDir), nil
}

func reviewRepositoryLocatorPath(locator ReviewRepositoryLocator, root, commonDir string) (string, error) {
	dir, err := reviewRepositoryLocatorBucket(locator)
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, identityHash(root+"\x00"+commonDir)+".json"), nil
}

func locatorHash(locator ReviewRepositoryLocator) string {
	return identityHash(locator.Lineage + "\x00" + locator.Target + "\x00" + locator.Lens + "\x00" + fmt.Sprint(locator.Order))
}

func identityHash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func validateReviewRepositoryLocator(locator ReviewRepositoryLocator) error {
	if validateLineageID(locator.Lineage) != nil || !validSHA256(locator.Target) || !isSupportedLens(locator.Lens) || locator.Order < 0 {
		return errors.New("invalid review repository locator binding")
	}
	return nil
}

func ensurePrivateLocatorDirectory(dir string) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	base := filepath.Join(home, ".gentle-ai")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	for current := dir; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return errors.New("review repository locator directory is unsafe")
		}
		if err := os.Chmod(current, 0o700); err != nil {
			return err
		}
		if current == base {
			return nil
		}
	}
}

func sameLocatorDirectory(left, right string) bool {
	leftInfo, leftErr := os.Stat(left)
	rightInfo, rightErr := os.Stat(right)
	return leftErr == nil && rightErr == nil && leftInfo.IsDir() && rightInfo.IsDir() && os.SameFile(leftInfo, rightInfo)
}

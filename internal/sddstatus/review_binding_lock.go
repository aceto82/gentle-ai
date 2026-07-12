package sddstatus

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

type bindingLock struct{ file *os.File }

func acquireBindingLock(path string) (*bindingLock, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	locked, err := tryLockBindingFile(file)
	if err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("lock SDD review binding: %w", err)
	}
	if !locked {
		_ = file.Close()
		return nil, errors.New("SDD review binding is concurrently updated")
	}
	return &bindingLock{file: file}, nil
}

func (lock *bindingLock) release() error {
	if lock == nil || lock.file == nil {
		return nil
	}
	err := unlockBindingFile(lock.file)
	closeErr := lock.file.Close()
	lock.file = nil
	if err != nil {
		return err
	}
	return closeErr
}

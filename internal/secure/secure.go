// Package secure contains Linux filesystem and process safeguards.
package secure

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
)

func Wipe(b []byte) { clear(b); runtime.KeepAlive(b) }

func Harden() error {
	if err := syscall.Setrlimit(syscall.RLIMIT_CORE, &syscall.Rlimit{}); err != nil {
		return err
	}
	// PR_SET_DUMPABLE prevents ordinary same-user ptrace and core dumps.
	_, _, errno := syscall.Syscall6(syscall.SYS_PRCTL, 4, 0, 0, 0, 0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}

func Check(path string, directory bool) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Getuid()) || info.Mode()&os.ModeSymlink != 0 || info.IsDir() != directory || (!directory && !info.Mode().IsRegular()) || info.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("%s must be owned by you, not a symlink, and accessible only to you", path)
	}
	return nil
}

func Dir(path string) error {
	if err := os.MkdirAll(path, 0700); err != nil {
		return err
	}
	return Check(path, true)
}

func NewFile(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
}

func SyncDir(path string) error {
	f, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

func Lock(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	if err = Check(path, false); err == nil {
		err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	}
	if err != nil {
		f.Close()
		return nil, errors.New("another daemon is running or the lock file is unsafe")
	}
	return f, nil
}

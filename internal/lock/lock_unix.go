//go:build !windows

package lock

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// Acquire 在 path 上创建锁文件并通过 flock 获取排他锁；已被持有时返回错误。
func Acquire(path string) (*Lock, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("打开锁文件失败: %w", err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, fmt.Errorf("目录已被另一个写端锁定: %w", err)
		}
		return nil, fmt.Errorf("获取文件锁失败: %w", err)
	}
	return &Lock{f: f}, nil
}

// Release 解除 flock 并关闭文件。
func (l *Lock) Release() error {
	if l == nil || l.f == nil {
		return nil
	}
	flockErr := syscall.Flock(int(l.f.Fd()), syscall.LOCK_UN)
	closeErr := l.f.Close()
	l.f = nil
	if flockErr != nil {
		return fmt.Errorf("释放锁失败: %w", flockErr)
	}
	return closeErr
}

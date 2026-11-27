//go:build windows

package lock

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

var (
	kernel32                = syscall.NewLazyDLL("kernel32.dll")
	procLockFileEx          = kernel32.NewProc("LockFileEx")
	procUnlockFileEx        = kernel32.NewProc("UnlockFileEx")
	lockfileFailImmediately = 0x00000001
	lockfileExclusiveLock   = 0x00000002
)

// Acquire 在 path 上创建锁文件并获取排他字节锁；已被持有时返回错误。
func Acquire(path string) (*Lock, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("打开锁文件失败: %w", err)
	}
	const reserved = 0
	r1, _, errno := procLockFileEx.Call(
		f.Fd(),
		uintptr(lockfileExclusiveLock|lockfileFailImmediately),
		uintptr(reserved),
		uintptr(1), // 锁 1 个字节
		uintptr(0),
		uintptr(unsafe.Pointer(&syscall.Overlapped{})),
	)
	if r1 == 0 {
		_ = f.Close()
		return nil, fmt.Errorf("目录已被另一个写端锁定: %w", errno)
	}
	return &Lock{f: f}, nil
}

// Release 释放字节锁并关闭文件。
func (l *Lock) Release() error {
	if l == nil || l.f == nil {
		return nil
	}
	r1, _, errno := procUnlockFileEx.Call(l.f.Fd(), 0, 1, 0, uintptr(unsafe.Pointer(&syscall.Overlapped{})))
	closeErr := l.f.Close()
	l.f = nil
	if r1 == 0 {
		return fmt.Errorf("释放锁失败: %w", errno)
	}
	return closeErr
}

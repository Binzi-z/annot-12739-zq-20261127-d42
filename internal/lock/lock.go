// Package lock 提供写端目录级跨进程排他锁。
// Windows 使用 LockFileEx（进程退出由 OS 自动释放），Unix 使用 flock。
package lock

import "os"

// Lock 是持有的排他锁句柄。
type Lock struct {
	f *os.File
}

// File 返回底层句柄，供平台实现复用。
func (l *Lock) File() *os.File { return l.f }

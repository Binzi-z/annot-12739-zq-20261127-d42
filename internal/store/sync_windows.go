//go:build windows

package store

import "os"

// syncDir 在 Windows 上是空操作：NTFS 元数据日志保证 rename 的崩溃原子性，
// Go 的 os.Rename 在 Windows 上通过 MoveFileEx(MOVEFILE_REPLACE_EXISTING) 实现。
func syncDir(_ string) error { return nil }

// removeStaleTemp 由调用方直接 os.Remove，Windows 上同名临时文件可直接覆盖写。
func removeStaleTemp(path string) error {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

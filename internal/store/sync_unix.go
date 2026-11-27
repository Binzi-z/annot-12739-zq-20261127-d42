//go:build !windows

package store

import "os"

// syncDir 在 Unix 上 fsync 目录，保证 rename 与新建目录项在崩溃前落盘。
func syncDir(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

func removeStaleTemp(path string) error {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

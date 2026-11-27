package log

import "os"

func openAppend(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
}

func readBytes(path string) ([]byte, error)  { return os.ReadFile(path) }
func writeBytes(path string, b []byte) error { return os.WriteFile(path, b, 0o600) }

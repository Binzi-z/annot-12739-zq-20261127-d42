package store

import (
	"encoding/json"
	"strconv"

	"example.invalid/local-fixture/internal/merkle"
)

func jsonString(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		return strconv.Quote(s)
	}
	return string(b)
}

func itoa(v int) string     { return strconv.Itoa(v) }
func itoa64(v int64) string { return strconv.FormatInt(v, 10) }

func leafHashOf(data []byte) []byte { return merkle.LeafHash(data) }

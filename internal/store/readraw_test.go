package store_test

import (
	"encoding/hex"
	"encoding/json"
	"path/filepath"

	"example.invalid/local-fixture/internal/log"
	"example.invalid/local-fixture/internal/store"
)

func mustDecodeHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// readRaw 绕过 store 内存状态，直接从磁盘日志读出全部信封，验证“原始前缀不丢”。
func readRaw(dir, partition string) ([]store.Envelope, error) {
	recs, err := log.ReadAll(filepath.Join(dir, "part-"+partition+".log"))
	if err != nil {
		return nil, err
	}
	out := make([]store.Envelope, 0, len(recs))
	for _, rec := range recs {
		var env store.Envelope
		if err := json.Unmarshal(rec.Body, &env); err != nil {
			return nil, err
		}
		out = append(out, env)
	}
	return out, nil
}

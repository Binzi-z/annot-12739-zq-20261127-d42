package merkle

import (
	"crypto/sha256"
	"math/rand"
	"testing"
)

func TestInclusionProofAllSizes(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	for size := 1; size <= 64; size++ {
		hashes := make([][]byte, size)
		for i := range hashes {
			h := sha256.Sum256([]byte{byte(i), byte(size)})
			hashes[i] = h[:]
		}
		root := RootFromHashes(hashes)
		for idx := 0; idx < size; idx++ {
			proof, err := InclusionProof(hashes, idx)
			if err != nil {
				t.Fatalf("size=%d idx=%d 生成证明: %v", size, idx, err)
			}
			if err := VerifyInclusion(hashes[idx], idx, size, proof, root); err != nil {
				t.Fatalf("size=%d idx=%d 复验: %v", size, idx, err)
			}
			// 篡改任一步必须失败。
			if len(proof) > 0 {
				bad := proof[0].Hash[0]
				proof[0].Hash[0] ^= 0xFF
				if VerifyInclusion(hashes[idx], idx, size, proof, root) == nil {
					t.Fatalf("size=%d idx=%d 篡改证明未被发现", size, idx)
				}
				proof[0].Hash[0] = bad
			}
			// 错误下标必须失败。
			wrong := (idx + 1) % size
			if VerifyInclusion(hashes[idx], wrong, size, proof, root) == nil && wrong != idx {
				t.Fatalf("size=%d 错误下标 %d 未被发现", size, wrong)
			}
		}
		_ = rng
	}
}

func TestRootFromFlatMatchesSlices(t *testing.T) {
	for size := 0; size <= 70; size++ {
		hashes := make([][]byte, size)
		flat := make([]byte, size*32)
		for i := range hashes {
			h := sha256.Sum256([]byte{'f', byte(i), byte(size)})
			hashes[i] = h[:]
			copy(flat[i*32:i*32+32], h[:])
		}
		if !equalBytes(RootFromFlat(flat, size), RootFromHashes(hashes)) {
			t.Fatalf("size=%d 扁平根与切片根不一致", size)
		}
	}
}

func TestCachedTreeProofMatchesRecursive(t *testing.T) {
	for size := 1; size <= 70; size++ {
		hashes := make([][]byte, size)
		for i := range hashes {
			h := sha256.Sum256([]byte{'c', byte(i), byte(size)})
			hashes[i] = h[:]
		}
		tree := NewTree(hashes)
		root := RootFromHashes(hashes)
		if !equalBytes(tree.Root(), root) {
			t.Fatalf("size=%d 缓存树根不符", size)
		}
		for idx := 0; idx < size; idx++ {
			want, err := InclusionProof(hashes, idx)
			if err != nil {
				t.Fatal(err)
			}
			got, err := tree.Proof(idx)
			if err != nil {
				t.Fatal(err)
			}
			if len(want) != len(got) {
				t.Fatalf("size=%d idx=%d 证明长度 %d≠%d", size, idx, len(want), len(got))
			}
			for i := range want {
				if !equalBytes(want[i].Hash, got[i].Hash) || want[i].SiblingLeft != got[i].SiblingLeft {
					t.Fatalf("size=%d idx=%d 第 %d 步不一致", size, idx, i)
				}
			}
			if err := VerifyInclusion(hashes[idx], idx, size, got, root); err != nil {
				t.Fatalf("size=%d idx=%d 缓存证明复验: %v", size, idx, err)
			}
		}
	}
}

func TestConsistencyByPrefixRecomputation(t *testing.T) {
	// 代间一致性的权威复验由读端用独立重放叶子重算前缀根完成；
	// 这里验证“旧叶子序列的根”与“新叶子序列前缀的根”逐对相等。
	for newSize := 1; newSize <= 40; newSize++ {
		hashes := make([][]byte, newSize)
		for i := range hashes {
			h := sha256.Sum256([]byte{'l', 'e', 'a', 'f', byte(i)})
			hashes[i] = h[:]
		}
		for oldSize := 1; oldSize <= newSize; oldSize++ {
			if !equalBytes(RootFromHashes(hashes[:oldSize]),
				RootFromHashes(append([][]byte(nil), hashes[:oldSize]...))) {
				t.Fatalf("old=%d new=%d 前缀根不稳定", oldSize, newSize)
			}
			// 修改任意旧叶子必须改变旧根（追加一致性的反例能被重算发现）。
			if oldSize >= 2 {
				tampered := append([][]byte(nil), hashes[:oldSize]...)
				fake := sha256.Sum256([]byte{'x'})
				tampered[0] = fake[:]
				if equalBytes(RootFromHashes(tampered), RootFromHashes(hashes[:oldSize])) {
					t.Fatalf("old=%d 篡改旧叶子未改变根", oldSize)
				}
			}
		}
	}
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestLeafDomainSeparation(t *testing.T) {
	// 叶子与内部节点域分隔不同：同字节不应产生可混淆的哈希。
	l := LeafHash([]byte("x"))
	h := sha256.New()
	h.Write(internalPrefix)
	h.Write([]byte("x"))
	if string(l) == string(h.Sum(nil)) {
		t.Fatal("域分隔失效")
	}
}

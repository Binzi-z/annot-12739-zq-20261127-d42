// Package merkle 实现 RFC 9162 风格的仅追加 Merkle 树：
// 叶子哈希带 0x00 域分隔，内部节点带 0x01 域分隔，
// 提供包含证明、代间一致性证明及其独立验证函数。
package merkle

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"math/bits"
)

var (
	leafPrefix     = []byte{0x00}
	internalPrefix = []byte{0x01}
)

// EmptyRoot 是空树（零个叶子）的根。
var EmptyRoot = sha256.New().Sum(nil)

// LeafHash 计算原始叶子数据的叶子哈希。
func LeafHash(data []byte) []byte {
	h := sha256.New()
	h.Write(leafPrefix)
	h.Write(data)
	return h.Sum(nil)
}

func nodeHash(left, right []byte) []byte {
	h := sha256.New()
	h.Write(internalPrefix)
	h.Write(left)
	h.Write(right)
	return h.Sum(nil)
}

// Root 由全部叶子数据计算 Merkle 根。
func Root(leaves [][]byte) []byte {
	if len(leaves) == 0 {
		return append([]byte(nil), EmptyRoot...)
	}
	hashes := make([][]byte, len(leaves))
	for i, l := range leaves {
		hashes[i] = LeafHash(l)
	}
	for len(hashes) > 1 {
		var next [][]byte
		for i := 0; i < len(hashes); i += 2 {
			if i+1 == len(hashes) {
				next = append(next, hashes[i]) // 奇数节点上提
				continue
			}
			next = append(next, nodeHash(hashes[i], hashes[i+1]))
		}
		hashes = next
	}
	return hashes[0]
}

// RootFromHashes 由叶子哈希（而非原始数据）计算根。
func RootFromHashes(leafHashes [][]byte) []byte {
	if len(leafHashes) == 0 {
		return append([]byte(nil), EmptyRoot...)
	}
	hashes := append([][]byte(nil), leafHashes...)
	for len(hashes) > 1 {
		var next [][]byte
		for i := 0; i < len(hashes); i += 2 {
			if i+1 == len(hashes) {
				next = append(next, hashes[i])
				continue
			}
			next = append(next, nodeHash(hashes[i], hashes[i+1]))
		}
		hashes = next
	}
	return hashes[0]
}

// RootFromFlat 由连续存储的叶子哈希（每 32 字节一个叶子）计算根，
// 避免十万级叶子各自分配切片造成的堆碎片；n 为叶子数。
func RootFromFlat(flat []byte, n int) []byte {
	if n == 0 {
		return append([]byte(nil), EmptyRoot...)
	}
	if len(flat) < n*32 {
		return nil
	}
	// 逐层在两个扁平缓冲之间归约，每层最多 n*32 字节且仅两块内存。
	cur := append([]byte(nil), flat[:n*32]...)
	for count := n; count > 1; {
		nextCount := (count + 1) / 2
		next := make([]byte, nextCount*32)
		for i := 0; i < nextCount; i++ {
			left := cur[i*64 : i*64+32]
			if i*2+1 < count {
				right := cur[i*64+32 : i*64+64]
				copy(next[i*32:i*32+32], nodeHash(left, right))
			} else {
				copy(next[i*32:i*32+32], left) // 奇数末尾上提
			}
		}
		cur = next
		count = nextCount
	}
	return cur
}

// Tree 缓存全部层级节点哈希，使包含证明生成为 O(log n) 而非重复重算子树。
type Tree struct {
	levels [][][]byte // levels[0] 为叶子哈希，逐层向上
}

// NewTree 由叶子哈希构建缓存树。
func NewTree(leafHashes [][]byte) *Tree {
	t := &Tree{levels: [][][]byte{append([][]byte(nil), leafHashes...)}}
	for len(t.levels[len(t.levels)-1]) > 1 {
		cur := t.levels[len(t.levels)-1]
		var next [][]byte
		for i := 0; i < len(cur); i += 2 {
			if i+1 == len(cur) {
				next = append(next, cur[i]) // 奇数节点上提
				continue
			}
			next = append(next, nodeHash(cur[i], cur[i+1]))
		}
		t.levels = append(t.levels, next)
	}
	return t
}

// Size 返回叶子数。
func (t *Tree) Size() int { return len(t.levels[0]) }

// Root 返回树根（空树返回 EmptyRoot）。
func (t *Tree) Root() []byte {
	if t.Size() == 0 {
		return append([]byte(nil), EmptyRoot...)
	}
	return append([]byte(nil), t.levels[len(t.levels)-1][0]...)
}

// LeafHashAt 返回第 index 个叶子哈希。
func (t *Tree) LeafHashAt(index int) []byte {
	return append([]byte(nil), t.levels[0][index]...)
}

// Proof 生成 O(log n) 包含证明，步序与 InclusionProof 完全一致（叶→根）。
func (t *Tree) Proof(index int) ([]Step, error) {
	if index < 0 || index >= t.Size() {
		return nil, errors.New("merkle: 叶子下标越界")
	}
	var proof []Step
	idx := index
	for level := 0; level < len(t.levels)-1; level++ {
		cur := t.levels[level]
		switch {
		case idx%2 == 1:
			proof = append(proof, Step{Hash: append([]byte(nil), cur[idx-1]...), SiblingLeft: true})
		case idx+1 < len(cur):
			proof = append(proof, Step{Hash: append([]byte(nil), cur[idx+1]...), SiblingLeft: false})
		default:
			// 奇数末尾节点被上提，本层无兄弟；与递归建树的“无此步”一致。
		}
		idx >>= 1
	}
	return proof, nil
}

// Step 是包含证明中的一个兄弟节点；SiblingLeft 为 true 表示兄弟在当前节点左侧。
type Step struct {
	Hash        []byte
	SiblingLeft bool
}

// InclusionProof 返回 index 处叶子在大小为 size 的树中的包含证明路径。
func InclusionProof(leafHashes [][]byte, index int) ([]Step, error) {
	size := len(leafHashes)
	if index < 0 || index >= size {
		return nil, errors.New("merkle: 叶子下标越界")
	}
	var proof []Step
	var build func(lo, n, idx int)
	// 与 verifyRec 同构的递归：每一步追加对侧完整子树的根及其方向。
	build = func(lo, n, idx int) {
		if n == 1 {
			return
		}
		k := 1 << (bits.Len(uint(n-1)) - 1) // 小于 n 的最大 2 的幂
		if idx < k {
			build(lo, k, idx)
			proof = append(proof, Step{Hash: RootFromHashes(leafHashes[lo+k : lo+n]), SiblingLeft: false})
		} else {
			build(lo+k, n-k, idx-k)
			proof = append(proof, Step{Hash: RootFromHashes(leafHashes[lo : lo+k]), SiblingLeft: true})
		}
	}
	build(0, size, index)
	return proof, nil
}

// VerifyInclusion 独立复验包含证明，不依赖建树过程或原始叶子数组。
// 验证器与生成器使用同一套 (n, k, index) 分解，因此方向、步数均可交叉核对。
func VerifyInclusion(leafHash []byte, index, size int, proof []Step, root []byte) error {
	if index < 0 || size <= 0 || index >= size {
		return errors.New("merkle: 包含证明参数非法")
	}
	got, err := verifyRec(leafHash, index, size, proof)
	if err != nil {
		return err
	}
	if !bytes.Equal(got, root) {
		return errors.New("merkle: 包含证明根不匹配")
	}
	return nil
}

// verifyRec 递归消费证明：每棵子树只携带对侧子树根，叶子端无需任何额外信息。
func verifyRec(leafHash []byte, index, size int, proof []Step) ([]byte, error) {
	if size == 1 {
		if len(proof) != 0 {
			return nil, errors.New("merkle: 单子树证明非空")
		}
		return append([]byte(nil), leafHash...), nil
	}
	if len(proof) == 0 {
		return nil, errors.New("merkle: 包含证明过短")
	}
	last := proof[len(proof)-1]
	k := 1 << (bits.Len(uint(size-1)) - 1)
	if index < k {
		// 对侧子树在右。
		if last.SiblingLeft {
			return nil, errors.New("merkle: 证明方向与下标不符")
		}
		sub, err := verifyRec(leafHash, index, k, proof[:len(proof)-1])
		if err != nil {
			return nil, err
		}
		return nodeHash(sub, last.Hash), nil
	}
	// 对侧子树在左。
	if !last.SiblingLeft {
		return nil, errors.New("merkle: 证明方向与下标不符")
	}
	sub, err := verifyRec(leafHash, index-k, size-k, proof[:len(proof)-1])
	if err != nil {
		return nil, err
	}
	return nodeHash(last.Hash, sub), nil
}

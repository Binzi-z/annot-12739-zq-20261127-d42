// Package log 实现崩溃安全的仅追加记录日志：
// 定长二进制帧 + 记录哈希链，每条记录落盘后 fsync，
// 尾部截断（torn write）在打开时可被发现并裁剪。
package log

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
)

const (
	magic    = uint32(0x414C4731)  // "ALG1"
	recHdr   = 8 + 4 + 4 + 32 + 32 // 序号/长度/类型/前链/本记录链哈希
	frameHdr = 4 + 4               // magic + 帧长
)

// Record 是日志中的一条记录；Prev 是上一条记录的链哈希。
type Record struct {
	Seq   uint64
	Type  uint32
	Body  []byte
	Prev  []byte
	Chain []byte // 本条记录链哈希，读回时填充
}

func chainHash(prev []byte, r Record) []byte {
	h := sha256.New()
	h.Write(prev)
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], r.Seq)
	h.Write(buf[:])
	binary.BigEndian.PutUint32(buf[:4], r.Type)
	h.Write(buf[:4])
	var lbuf [4]byte
	binary.BigEndian.PutUint32(lbuf[:], uint32(len(r.Body)))
	h.Write(lbuf[:])
	h.Write(r.Body)
	return h.Sum(nil)
}

// Log 是一个仅追加二进制日志文件句柄。
type Log struct {
	f       *os.File
	path    string
	seq     uint64
	tail    []byte // 最后一条记录的链哈希
	records int
}

// Open 打开日志；不存在则创建并写入文件头。尾部残缺帧会被安全裁剪。
func Open(path string) (*Log, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	l := &Log{f: f, path: path, tail: bytes.Repeat([]byte{0}, 32)}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	if info.Size() == 0 {
		if err := l.writeFileHeader(); err != nil {
			_ = f.Close()
			return nil, err
		}
		return l, nil
	}
	if err := l.replay(); err != nil {
		_ = f.Close()
		return nil, err
	}
	return l, nil
}

func (l *Log) writeFileHeader() error {
	var hdr [8]byte
	binary.BigEndian.PutUint32(hdr[0:4], magic)
	binary.BigEndian.PutUint32(hdr[4:8], 1) // 版本
	if _, err := l.f.Write(hdr[:]); err != nil {
		return err
	}
	return l.f.Sync()
}

func (l *Log) replay() error {
	if _, err := l.f.Seek(0, io.SeekStart); err != nil {
		return err
	}
	r := newFrameReader(l.f)
	var hdr [8]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return fmt.Errorf("日志头损坏: %w", err)
	}
	if binary.BigEndian.Uint32(hdr[0:4]) != magic {
		return errors.New("日志魔数不匹配")
	}
	var validEnd int64 = 8
	for {
		frame, err := r.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			// 尾部残缺：裁剪到最后一个完整帧之后，保证崩溃后可打开。
			if truncErr := l.f.Truncate(validEnd); truncErr != nil {
				return truncErr
			}
			if _, seekErr := l.f.Seek(0, io.SeekEnd); seekErr != nil {
				return seekErr
			}
			break
		}
		rec, err := decodeRecord(frame)
		if err != nil {
			if truncErr := l.f.Truncate(validEnd); truncErr != nil {
				return truncErr
			}
			break
		}
		want := chainHash(l.tail, rec)
		if !bytes.Equal(want, rec.Chain) {
			return fmt.Errorf("记录 %d 哈希链断裂", rec.Seq)
		}
		if rec.Seq != l.seq {
			return fmt.Errorf("记录序号不连续: 期望 %d 实际 %d", l.seq, rec.Seq)
		}
		l.tail = rec.Chain
		l.seq++
		l.records++
		validEnd = r.FrameEnd()
	}
	if _, err := l.f.Seek(0, io.SeekEnd); err != nil {
		return err
	}
	return nil
}

// Append 追加一条记录并 fsync；序号由日志分配，链哈希自动计算。
func (l *Log) Append(recType uint32, body []byte) (Record, error) {
	recs, err := l.AppendBatch([]BatchItem{{Type: recType, Body: body}})
	if err != nil {
		return Record{}, err
	}
	return recs[0], nil
}

// BatchItem 是批量追加中的一条记录。
type BatchItem struct {
	Type uint32
	Body []byte
}

// AppendBatch 在一次 fsync 屏障内追加多条记录（组提交）：
// 全部帧先写入并连续落盘，之后才推进内存水位；崩溃时残缺尾帧由重放裁剪。
func (l *Log) AppendBatch(items []BatchItem) ([]Record, error) {
	if len(items) == 0 {
		return nil, nil
	}
	recs := make([]Record, 0, len(items))
	var frames []byte
	tail := l.tail
	seq := l.seq
	for _, it := range items {
		rec := Record{Seq: seq, Type: it.Type, Body: append([]byte(nil), it.Body...), Prev: append([]byte(nil), tail...)}
		rec.Chain = chainHash(tail, rec)
		frames = append(frames, encodeRecord(rec)...)
		recs = append(recs, rec)
		tail = rec.Chain
		seq++
	}
	if _, err := l.f.Write(frames); err != nil {
		return nil, err
	}
	// 崩溃屏障：整批帧字节先到盘，再更新内存水位。
	if err := l.f.Sync(); err != nil {
		return nil, err
	}
	l.seq = seq
	l.tail = tail
	l.records += len(items)
	return recs, nil
}

// Seq 返回下一条记录的序号（即当前记录数）。
func (l *Log) Seq() uint64 { return l.seq }

// Tail 返回最后一条记录的链哈希（空日志为全零）。
func (l *Log) Tail() []byte { return append([]byte(nil), l.tail...) }

// Close 关闭句柄。
func (l *Log) Close() error { return l.f.Close() }

// Path 返回日志文件路径。
func (l *Log) Path() string { return l.path }

// ReadAll 顺序读回全部完整记录（独立读端使用，不需要写句柄）。
func ReadAll(path string) ([]Record, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	r := newFrameReader(f)
	var hdr [8]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, fmt.Errorf("日志头损坏: %w", err)
	}
	if binary.BigEndian.Uint32(hdr[0:4]) != magic {
		return nil, errors.New("日志魔数不匹配")
	}
	var out []Record
	prev := bytes.Repeat([]byte{0}, 32)
	for {
		frame, err := r.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err // 读端不裁剪，只接受完整日志
		}
		rec, err := decodeRecord(frame)
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(chainHash(prev, rec), rec.Chain) {
			return nil, fmt.Errorf("记录 %d 哈希链断裂", rec.Seq)
		}
		prev = rec.Chain
		out = append(out, rec)
	}
	return out, nil
}

// frameReader 按“4 字节魔数 + 4 字节帧长 + 帧体”切帧，记录每帧结束偏移。
type frameReader struct {
	r        io.Reader
	frameEnd int64
	pos      int64
}

func newFrameReader(r io.Reader) *frameReader {
	return &frameReader{r: r}
}

// Read 委托给底层 reader 并推进位置，使 frameReader 自身满足 io.Reader。
func (fr *frameReader) Read(p []byte) (int, error) {
	n, err := fr.r.Read(p)
	fr.pos += int64(n)
	return n, err
}

func (fr *frameReader) Next() ([]byte, error) {
	var head [frameHdr]byte
	n, err := io.ReadFull(fr.r, head[:])
	fr.pos += int64(n)
	if err != nil {
		return nil, err
	}
	if binary.BigEndian.Uint32(head[0:4]) != magic {
		return nil, errors.New("帧魔数不匹配")
	}
	length := binary.BigEndian.Uint32(head[4:8])
	if length > 64*1024*1024 {
		return nil, fmt.Errorf("帧长异常: %d", length)
	}
	buf := make([]byte, length)
	n, err = io.ReadFull(fr.r, buf)
	fr.pos += int64(n)
	if err != nil {
		return nil, err
	}
	fr.frameEnd = fr.pos
	return buf, nil
}

func (fr *frameReader) FrameEnd() int64 { return fr.frameEnd }

func encodeRecord(r Record) []byte {
	bodyLen := len(r.Body)
	total := frameHdr + recHdr + bodyLen
	out := make([]byte, total)
	binary.BigEndian.PutUint32(out[0:4], magic)
	binary.BigEndian.PutUint32(out[4:8], uint32(recHdr+bodyLen))
	off := frameHdr
	binary.BigEndian.PutUint64(out[off:off+8], r.Seq)
	binary.BigEndian.PutUint32(out[off+8:off+12], uint32(bodyLen))
	binary.BigEndian.PutUint32(out[off+12:off+16], r.Type)
	copy(out[off+16:off+48], r.Prev)
	copy(out[off+48:off+80], r.Chain)
	copy(out[off+80:off+80+bodyLen], r.Body)
	return out
}

func decodeRecord(frame []byte) (Record, error) {
	if len(frame) < recHdr {
		return Record{}, errors.New("记录帧过短")
	}
	off := 0
	seq := binary.BigEndian.Uint64(frame[off : off+8])
	bodyLen := binary.BigEndian.Uint32(frame[off+8 : off+12])
	recType := binary.BigEndian.Uint32(frame[off+12 : off+16])
	prev := append([]byte(nil), frame[off+16:off+48]...)
	storedChain := append([]byte(nil), frame[off+48:off+80]...)
	if int(recHdr+bodyLen) != len(frame) {
		return Record{}, fmt.Errorf("记录体长度不匹配: 头声明 %d 实际 %d", bodyLen, len(frame)-recHdr)
	}
	body := append([]byte(nil), frame[off+80:off+80+int(bodyLen)]...)
	rec := Record{Seq: seq, Type: recType, Body: body, Prev: prev, Chain: storedChain}
	// 重算并与持久化链哈希逐字节比对：任何字节被改写都会在此暴露。
	want := chainHash(prev, rec)
	if !bytes.Equal(want, storedChain) {
		return Record{}, fmt.Errorf("记录 %d 链哈希校验失败", seq)
	}
	return rec, nil
}

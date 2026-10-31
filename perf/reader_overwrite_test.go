//go:build !windows

package perf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"testing"

	"github.com/cilium/ebpf/internal/unix"
)

func TestReadRecordFromRingOverwriteEOF(t *testing.T) {
	payload := []byte{1, 2, 3, 4}
	sample := func(size uint32, data []byte) []byte {
		buf := make([]byte, perfEventHeaderSize+perfEventSampleSize+len(data))
		binary.NativeEndian.PutUint32(buf, unix.PERF_RECORD_SAMPLE)
		binary.NativeEndian.PutUint16(buf[6:], uint16(perfEventHeaderSize+perfEventSampleSize)+uint16(size))
		binary.NativeEndian.PutUint32(buf[perfEventHeaderSize:], size)
		copy(buf[perfEventHeaderSize+perfEventSampleSize:], data)
		return buf
	}

	fault := errors.New("injected read failure")
	for _, overwritable := range []bool{false, true} {
		for _, test := range []struct {
			name    string
			data    []byte
			readErr error
			want    error
		}{
			{"complete", sample(4, payload), nil, nil},
			{"empty ring", nil, nil, errEOR},
			{"missing size", sample(4, nil)[:perfEventHeaderSize], nil, io.EOF},
			{"truncated size", sample(4, nil)[:perfEventHeaderSize+1], nil, io.ErrUnexpectedEOF},
			{"missing sample", sample(4, nil), nil, io.EOF},
			{"truncated sample", sample(4, payload[:1]), nil, io.ErrUnexpectedEOF},
			{"direct EOF", sample(4, nil), io.EOF, io.EOF},
			{"wrapped EOF", sample(4, nil), fmt.Errorf("ring: %w", io.EOF), io.EOF},
			{"direct unexpected EOF", sample(4, nil), io.ErrUnexpectedEOF, io.ErrUnexpectedEOF},
			{"wrapped unexpected EOF", sample(4, nil), fmt.Errorf("ring: %w", io.ErrUnexpectedEOF), io.ErrUnexpectedEOF},
			{"other error", sample(4, nil), fault, fault},
			{"wrapped other error", sample(4, nil), fmt.Errorf("ring: %w", fault), fault},
		} {
			t.Run(fmt.Sprintf("overwritable=%t/%s", overwritable, test.name), func(t *testing.T) {
				var input io.Reader = bytes.NewReader(test.data)
				if test.readErr != nil {
					input = io.MultiReader(input, perfReadError{test.readErr})
				}
				// Read a valid record before reaching the possibly truncated oldest record.
				input = io.MultiReader(bytes.NewReader(sample(4, payload)), input)
				rr := &syntheticPerfRingReader{Reader: input}
				ring := &perfEventRing{cpu: 7, ringReader: rr}
				pr := Reader{eventHeader: make([]byte, perfEventHeaderSize), overwritable: overwritable}
				var first Record
				if err := pr.readRecordFromRing(&first, ring); err != nil {
					t.Fatalf("read first record: %v", err)
				}
				var rec Record
				err := pr.readRecordFromRing(&rec, ring)
				want := test.want
				if overwritable && (errors.Is(want, io.EOF) || errors.Is(want, io.ErrUnexpectedEOF)) {
					want = errEOR
				}
				if (want == errEOR && err != errEOR) || !errors.Is(err, want) {
					t.Fatalf("readRecordFromRing() = %v, want %v", err, want)
				}
				if err == nil && !bytes.Equal(rec.RawSample, payload) {
					t.Errorf("sample = %v, want %v", rec.RawSample, payload)
				}
				if !bytes.Equal(first.RawSample, payload) {
					t.Errorf("first sample = %v, want %v", first.RawSample, payload)
				}
				if rec.CPU != ring.cpu || rr.tailWrites != 2 {
					t.Errorf("CPU = %d, tail writes = %d", rec.CPU, rr.tailWrites)
				}
			})
		}
	}
}

// These test readers do not create perf events, mappings or BPF objects.
type syntheticPerfRingReader struct {
	io.Reader
	tailWrites int
}

func (*syntheticPerfRingReader) loadHead()      {}
func (*syntheticPerfRingReader) size() int      { return 0 }
func (*syntheticPerfRingReader) remaining() int { return 0 }
func (r *syntheticPerfRingReader) writeTail()   { r.tailWrites++ }

type perfReadError struct{ err error }

func (r perfReadError) Read([]byte) (int, error) { return 0, r.err }

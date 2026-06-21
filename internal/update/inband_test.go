package update

import (
	"bytes"
	"testing"

	"github.com/atlanteg/supervpn/internal/proto"
)

// serverFrame builds a FrameUpdateData frame exactly as the server's sendData does.
func serverFrame(status byte, data []byte) []byte {
	hdr := make([]byte, proto.HeaderSize)
	proto.Header{Type: proto.FrameUpdateData}.Marshal(hdr)
	f := append([]byte{}, hdr...)
	f = append(f, status)
	return append(f, data...)
}

func TestInBandReassembly(t *testing.T) {
	// A payload spanning several chunks, then EOF — the wire format the server emits.
	want := bytes.Repeat([]byte("supervpn-binary-"), 5000) // ~80 KB
	var out bytes.Buffer
	for i := 0; i < len(want); i += 16384 {
		end := i + 16384
		if end > len(want) {
			end = len(want)
		}
		done, err := processUpdateFrame(serverFrame(proto.UpdateChunk, want[i:end]), &out)
		if err != nil || done {
			t.Fatalf("chunk: done=%v err=%v", done, err)
		}
	}
	done, err := processUpdateFrame(serverFrame(proto.UpdateEOF, nil), &out)
	if err != nil || !done {
		t.Fatalf("eof: done=%v err=%v", done, err)
	}
	if !bytes.Equal(out.Bytes(), want) {
		t.Fatalf("reassembled %d bytes, want %d", out.Len(), len(want))
	}

	// Server error frame must surface as an error.
	var e bytes.Buffer
	if _, err := processUpdateFrame(serverFrame(proto.UpdateErr, []byte("unknown asset")), &e); err == nil {
		t.Fatal("expected error from UpdateErr frame")
	}
}

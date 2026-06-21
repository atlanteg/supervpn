package update

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"math/rand"
	"strings"
	"time"

	"github.com/atlanteg/supervpn/internal/proto"
	"github.com/atlanteg/supervpn/internal/transport"
)

// maxInBandAsset caps an in-band download so a misbehaving/hostile peer cannot
// stream an unbounded amount of data into memory.
const maxInBandAsset = 64 << 20 // 64 MB

// fetchInBand downloads asset from one peer over the DPI-resistant Reality
// transport — the last-resort update source when GitHub and the HTTP mirrors are
// blocked (e.g. aggressive DPI). It connects to the peer's Reality endpoint on
// :443 (looking like ordinary TLS to www.gstatic.com), sends a FrameUpdateGet,
// and reassembles the FrameUpdateData stream into the asset bytes.
func fetchInBand(ctx context.Context, peerIP, asset string) ([]byte, error) {
	pub := transport.RandomPoolPublicKey()
	if pub == "" {
		return nil, fmt.Errorf("inband: no reality key pool embedded")
	}

	dctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	tr, err := transport.DialReality(dctx, transport.RealityClientParams{
		Addr:        peerIP + ":443",
		SNI:         "www.gstatic.com",
		PublicKey:   pub,
		Fingerprint: "chrome",
	})
	if err != nil {
		return nil, fmt.Errorf("inband: dial reality %s: %w", peerIP, err)
	}
	defer tr.Close()

	req := make([]byte, proto.HeaderSize)
	proto.Header{Type: proto.FrameUpdateGet}.Marshal(req)
	req = append(req, []byte(asset)...)
	if err := tr.Send(transport.Frame{Data: req}); err != nil {
		return nil, fmt.Errorf("inband: send request: %w", err)
	}

	rctx, rcancel := context.WithTimeout(ctx, 8*time.Minute)
	defer rcancel()
	var out bytes.Buffer
	for {
		f, err := tr.Recv(rctx)
		if err != nil {
			return nil, fmt.Errorf("inband: recv: %w", err)
		}
		done, err := processUpdateFrame(f.Data, &out)
		if err != nil {
			return nil, err
		}
		if done {
			return out.Bytes(), nil
		}
	}
}

// processUpdateFrame handles one received frame of the in-band update stream:
// appends a chunk to out, reports done on EOF, or returns the peer's error.
// Frames that are not FrameUpdateData (or are empty) are ignored.
func processUpdateFrame(frame []byte, out *bytes.Buffer) (done bool, err error) {
	hdr, ok := proto.ParseHeader(frame)
	if !ok || hdr.Type != proto.FrameUpdateData {
		return false, nil
	}
	body := frame[proto.HeaderSize:]
	if len(body) == 0 {
		return false, nil
	}
	status, data := body[0], body[1:]
	switch status {
	case proto.UpdateChunk:
		if out.Len()+len(data) > maxInBandAsset {
			return false, fmt.Errorf("inband: asset exceeds %d bytes", maxInBandAsset)
		}
		out.Write(data)
	case proto.UpdateEOF:
		return true, nil
	case proto.UpdateErr:
		return false, fmt.Errorf("inband: peer refused: %s", string(data))
	}
	return false, nil
}

// latestTagInBand resolves the latest version tag by asking peers for "version"
// over Reality — the last-resort version check when GitHub's API and the HTTP
// mirror /version endpoints are all blocked. Returns the first peer's tag.
func latestTagInBand() (string, error) {
	peers := make([]string, len(knownServerIPs))
	copy(peers, knownServerIPs)
	rand.Shuffle(len(peers), func(i, j int) { peers[i], peers[j] = peers[j], peers[i] })

	var lastErr error
	for _, ip := range peers {
		data, err := fetchInBand(context.Background(), ip, "version")
		if err != nil {
			lastErr = err
			continue
		}
		if tag := strings.TrimSpace(string(data)); tag != "" {
			return tag, nil
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("inband: no peers")
	}
	return "", lastErr
}

// downloadInBand tries to fetch asset from each known peer over Reality (random
// order) and apply it to exe. Used as the final fallback when GitHub and the
// HTTP mirrors are unreachable. Returns errBinaryUnchanged if a peer served a
// byte-identical binary.
func downloadInBand(asset, exe string) error {
	peers := make([]string, len(knownServerIPs))
	copy(peers, knownServerIPs)
	rand.Shuffle(len(peers), func(i, j int) { peers[i], peers[j] = peers[j], peers[i] })

	var lastErr error
	for _, ip := range peers {
		data, err := fetchInBand(context.Background(), ip, asset)
		if err != nil {
			log.Printf("update: in-band Reality fetch from %s failed: %v", ip, err)
			lastErr = err
			continue
		}
		if err := applyBinary(bytes.NewReader(data), exe); err != nil {
			if err == errBinaryUnchanged {
				return errBinaryUnchanged
			}
			log.Printf("update: apply in-band binary from %s failed: %v", ip, err)
			lastErr = err
			continue
		}
		log.Printf("update: applied %s via in-band Reality from %s (%d bytes)", asset, ip, len(data))
		return nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("inband: no peers")
	}
	return lastErr
}

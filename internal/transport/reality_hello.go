package transport

// Minimal server-side TLS ClientHello parser.  We only need three fields to
// run the Reality auth check: the client random (used as the GCM nonce), the
// session_id (carries the auth blob), and the X25519 key_share (the client's
// TLS ephemeral public key).  Anything malformed or unexpected yields ok=false,
// which the caller treats as "prober" and routes to the dest fallback.
//
// Only the first TLS record is parsed.  A ClientHello fragmented across records
// (very rare for browser-sized hellos) returns ok=false and falls back — safe.

import "encoding/binary"

const tlsGroupX25519 = 0x001d // RFC 8446 "x25519" named group

type parsedClientHello struct {
	random     []byte // 32 bytes
	sessionID  []byte // 0..32 bytes
	x25519Pub  []byte // 32 bytes from the key_share extension, or nil
	serverName string // SNI host, or "" if absent
}

// parseClientHelloRecord parses one TLS handshake record containing a
// ClientHello.  rec is the full record including the 5-byte record header.
func parseClientHelloRecord(rec []byte) (parsedClientHello, bool) {
	var ch parsedClientHello
	// Record header: type(1)=22, version(2), length(2).
	if len(rec) < 5 || rec[0] != 0x16 {
		return ch, false
	}
	recLen := int(binary.BigEndian.Uint16(rec[3:5]))
	body := rec[5:]
	if len(body) < recLen {
		return ch, false // ClientHello spans multiple records — fall back
	}
	body = body[:recLen]

	// Handshake header: type(1)=1 (ClientHello), length(3).
	if len(body) < 4 || body[0] != 0x01 {
		return ch, false
	}
	hsLen := int(body[1])<<16 | int(body[2])<<8 | int(body[3])
	hs := body[4:]
	if len(hs) < hsLen {
		return ch, false
	}
	hs = hs[:hsLen]

	r := byteReader{b: hs}
	if _, ok := r.skip(2); !ok { // legacy_version
		return ch, false
	}
	random, ok := r.take(32)
	if !ok {
		return ch, false
	}
	ch.random = random
	sid, ok := r.takeU8Vec()
	if !ok {
		return ch, false
	}
	ch.sessionID = sid
	if _, ok := r.takeU16Vec(); !ok { // cipher_suites
		return ch, false
	}
	if _, ok := r.takeU8Vec(); !ok { // compression_methods
		return ch, false
	}
	ext, ok := r.takeU16Vec() // extensions block
	if !ok {
		return ch, false
	}
	parseExtensions(ext, &ch)
	return ch, true
}

func parseExtensions(ext []byte, ch *parsedClientHello) {
	er := byteReader{b: ext}
	for er.remaining() >= 4 {
		etype, _ := er.takeU16()
		edata, ok := er.takeU16Vec()
		if !ok {
			return
		}
		switch etype {
		case 0x0000: // server_name
			ch.serverName = parseSNI(edata)
		case 0x0033: // key_share
			ch.x25519Pub = parseKeyShareX25519(edata)
		}
	}
}

// parseSNI extracts the first host_name from a server_name extension body.
func parseSNI(data []byte) string {
	r := byteReader{b: data}
	list, ok := r.takeU16Vec() // server_name_list
	if !ok {
		return ""
	}
	lr := byteReader{b: list}
	for lr.remaining() >= 3 {
		nameType, _ := lr.takeU8()
		name, ok := lr.takeU16Vec()
		if !ok {
			return ""
		}
		if nameType == 0 { // host_name
			return string(name)
		}
	}
	return ""
}

// parseKeyShareX25519 returns the 32-byte X25519 key from a key_share extension,
// or nil if absent.
func parseKeyShareX25519(data []byte) []byte {
	r := byteReader{b: data}
	shares, ok := r.takeU16Vec() // client_shares
	if !ok {
		return nil
	}
	sr := byteReader{b: shares}
	for sr.remaining() >= 4 {
		group, _ := sr.takeU16()
		key, ok := sr.takeU16Vec()
		if !ok {
			return nil
		}
		if group == tlsGroupX25519 && len(key) == 32 {
			return key
		}
	}
	return nil
}

// byteReader is a tiny bounds-checked sequential reader over a byte slice.
type byteReader struct {
	b   []byte
	off int
}

func (r *byteReader) remaining() int { return len(r.b) - r.off }

func (r *byteReader) take(n int) ([]byte, bool) {
	if n < 0 || r.remaining() < n {
		return nil, false
	}
	out := r.b[r.off : r.off+n]
	r.off += n
	return out, true
}

func (r *byteReader) skip(n int) (struct{}, bool) {
	if _, ok := r.take(n); !ok {
		return struct{}{}, false
	}
	return struct{}{}, true
}

func (r *byteReader) takeU8() (byte, bool) {
	v, ok := r.take(1)
	if !ok {
		return 0, false
	}
	return v[0], true
}

func (r *byteReader) takeU16() (uint16, bool) {
	v, ok := r.take(2)
	if !ok {
		return 0, false
	}
	return binary.BigEndian.Uint16(v), true
}

// takeU8Vec reads a 1-byte-length-prefixed vector.
func (r *byteReader) takeU8Vec() ([]byte, bool) {
	n, ok := r.takeU8()
	if !ok {
		return nil, false
	}
	return r.take(int(n))
}

// takeU16Vec reads a 2-byte-length-prefixed vector.
func (r *byteReader) takeU16Vec() ([]byte, bool) {
	n, ok := r.takeU16()
	if !ok {
		return nil, false
	}
	return r.take(int(n))
}

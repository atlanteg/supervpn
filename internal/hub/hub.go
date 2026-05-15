// Package hub implements the server-side L2 Hub.
//
// A Hub is an isolated L2 broadcast domain. The server runs N independent hubs.
// Each hub maintains a MAC address table and forwards Ethernet frames between
// connected clients — transparent L2 bridging, exactly like a network switch.
//
// Topology:
//
//	Client A ──┐
//	Client B ──┤── Hub (L2 switch) ── (isolated per hub)
//	Client C ──┘
package hub

import (
	"context"
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"
)

const macTableTTL = 5 * time.Minute

// Client represents a connected VPN client session.
type Client struct {
	SessionID uint32
	Send      func(frame []byte) error
	Login     string
}

// Hub is a single L2 broadcast domain.
type Hub struct {
	mu       sync.RWMutex
	id       uint16
	name     string
	clients  map[uint32]*Client // sessionID → client
	macTable map[[6]byte]macEntry
	fwdLog   atomic.Uint64 // frame counter for throttled diagnostic logging
}

type macEntry struct {
	sessionID uint32
	expires   time.Time
}

func New(id uint16, name string) *Hub {
	return &Hub{
		id:       id,
		name:     name,
		clients:  make(map[uint32]*Client),
		macTable: make(map[[6]byte]macEntry),
	}
}

func (h *Hub) ID() uint16   { return h.id }
func (h *Hub) Name() string { return h.name }

// Join adds a client to the hub.
func (h *Hub) Join(c *Client) {
	h.mu.Lock()
	h.clients[c.SessionID] = c
	h.mu.Unlock()
}

// Leave removes a client from the hub.
func (h *Hub) Leave(sessionID uint32) {
	h.mu.Lock()
	delete(h.clients, sessionID)
	h.mu.Unlock()
}

// Forward delivers an Ethernet frame received from srcSession to the correct destination(s).
// It learns the source MAC address and does unicast/broadcast forwarding.
func (h *Hub) Forward(srcSession uint32, frame []byte) {
	if len(frame) < 12 {
		return
	}
	var dst, src [6]byte
	copy(dst[:], frame[0:6])
	copy(src[:], frame[6:12])

	h.mu.Lock()
	// learn source MAC
	h.macTable[src] = macEntry{sessionID: srcSession, expires: time.Now().Add(macTableTTL)}
	// look up destination
	dstEntry, known := h.macTable[dst]
	h.mu.Unlock()

	isBroadcast := dst == ([6]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	isMulticast := dst[0]&0x01 != 0

	n := h.fwdLog.Add(1)
	verbose := n%50 == 1 // log every 50th frame

	if known && !isBroadcast && !isMulticast {
		// Unicast to known destination.
		h.mu.RLock()
		c, ok := h.clients[dstEntry.sessionID]
		h.mu.RUnlock()
		if ok && c.SessionID == srcSession {
			// Self-loop: dst MAC is our own entry. Drop silently.
			return
		}
		if ok {
			if verbose {
				log.Printf("hub%d fwd unicast src=%d dst=%d mac=%s", h.id, srcSession, c.SessionID, fmtMAC(dst))
			}
			_ = c.Send(frame)
			return
		}
		// Stale MAC entry: the client that owned this MAC reconnected with a new
		// session ID. Fall through to flood so the frame is not silently dropped.
		if verbose {
			log.Printf("hub%d fwd stale MAC dst=%s sess=%d gone, flooding", h.id, fmtMAC(dst), dstEntry.sessionID)
		}
	}

	// Broadcast / multicast / unknown unicast / stale unicast → flood to all except source.
	h.mu.RLock()
	targets := make([]*Client, 0, len(h.clients))
	for _, c := range h.clients {
		if c.SessionID != srcSession {
			targets = append(targets, c)
		}
	}
	h.mu.RUnlock()
	if verbose {
		ids := make([]uint32, len(targets))
		for i, c := range targets {
			ids[i] = c.SessionID
		}
		log.Printf("hub%d fwd flood src=%d targets=%v known=%v multicast=%v broadcast=%v dst=%s", h.id, srcSession, ids, known, isMulticast, isBroadcast, fmtMAC(dst))
	}
	for _, c := range targets {
		_ = c.Send(frame)
	}
}

func fmtMAC(m [6]byte) string {
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5])
}

// ClientCount returns number of connected clients.
func (h *Hub) ClientCount() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.clients)
}

// purgeMACTable removes stale entries. Call periodically.
func (h *Hub) purgeMACTable() {
	now := time.Now()
	h.mu.Lock()
	for mac, e := range h.macTable {
		if now.After(e.expires) {
			delete(h.macTable, mac)
		}
	}
	h.mu.Unlock()
}

// StartMACPurge runs a background goroutine that purges stale MAC table entries
// every minute. It stops when ctx is cancelled.
func (h *Hub) StartMACPurge(ctx context.Context) {
	go func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				h.purgeMACTable()
			}
		}
	}()
}

// Manager holds a set of hubs indexed by ID.
type Manager struct {
	mu   sync.RWMutex
	hubs map[uint16]*Hub
}

// NewManager creates an empty Manager.
func NewManager() *Manager {
	return &Manager{hubs: make(map[uint16]*Hub)}
}

// Add registers a hub with the manager. Overwrites any existing hub with the same ID.
func (m *Manager) Add(h *Hub) {
	m.mu.Lock()
	m.hubs[h.id] = h
	m.mu.Unlock()
}

// Get looks up a hub by ID.
func (m *Manager) Get(id uint16) (*Hub, bool) {
	m.mu.RLock()
	h, ok := m.hubs[id]
	m.mu.RUnlock()
	return h, ok
}

// List returns all registered hubs in an unspecified order.
func (m *Manager) List() []*Hub {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*Hub, 0, len(m.hubs))
	for _, h := range m.hubs {
		out = append(out, h)
	}
	return out
}

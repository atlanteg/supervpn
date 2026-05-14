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
	"net"
	"sync"
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

	if known && !isBroadcast && !isMulticast {
		// unicast to known destination
		h.mu.RLock()
		c, ok := h.clients[dstEntry.sessionID]
		h.mu.RUnlock()
		if ok && c.SessionID != srcSession {
			_ = c.Send(frame)
		}
		return
	}

	// broadcast / multicast / unknown unicast → flood to all except source
	h.mu.RLock()
	targets := make([]*Client, 0, len(h.clients))
	for _, c := range h.clients {
		if c.SessionID != srcSession {
			targets = append(targets, c)
		}
	}
	h.mu.RUnlock()
	for _, c := range targets {
		_ = c.Send(frame)
	}
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

// ensure net is imported (used for MAC type doc context)
var _ = net.HardwareAddr{}

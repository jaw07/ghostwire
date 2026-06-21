package chat

import (
	"sync"
	"time"
)

// MaxTextLen bounds a chat message body. Remote messages larger than this are
// dropped (a peer could otherwise fill bounded history with huge messages);
// locally-sent messages are truncated.
const MaxTextLen = 4096

// ChatMessage represents a single chat message in the mesh network.
type ChatMessage struct {
	Sender    string `json:"sender"`
	Text      string `json:"text"`
	Timestamp int64  `json:"timestamp"`
}

// Service manages sending, receiving, and history of chat messages.
type Service struct {
	nodeID    string
	messages  []ChatMessage
	maxHist   int
	mu        sync.Mutex
	OnSend    func(ChatMessage) // called when this node sends
	OnReceive func(ChatMessage) // called when remote message arrives
}

// New creates a new chat Service for the given nodeID with a bounded history.
func New(nodeID string, maxHistory int) *Service {
	return &Service{
		nodeID:   nodeID,
		maxHist:  maxHistory,
		messages: make([]ChatMessage, 0, maxHistory),
	}
}

// Send creates a message from this node, appends it to history, and calls OnSend.
func (s *Service) Send(text string) {
	if len(text) > MaxTextLen {
		text = text[:MaxTextLen]
	}
	msg := ChatMessage{
		Sender:    s.nodeID,
		Text:      text,
		Timestamp: time.Now().UnixMilli(),
	}

	s.mu.Lock()
	s.appendLocked(msg)
	cb := s.OnSend
	s.mu.Unlock()

	if cb != nil {
		cb(msg)
	}
}

// Receive processes an incoming message from a remote node. Messages whose
// Sender matches this node's ID are silently dropped (echo suppression).
// Otherwise the message is appended to history and OnReceive is called.
func (s *Service) Receive(msg ChatMessage) {
	if msg.Sender == s.nodeID {
		return
	}
	// Drop oversized messages from peers rather than storing them in history.
	if len(msg.Text) > MaxTextLen {
		return
	}

	s.mu.Lock()
	s.appendLocked(msg)
	cb := s.OnReceive
	s.mu.Unlock()

	if cb != nil {
		cb(msg)
	}
}

// History returns a copy of the current message history in chronological order.
func (s *Service) History() []ChatMessage {
	s.mu.Lock()
	defer s.mu.Unlock()

	out := make([]ChatMessage, len(s.messages))
	copy(out, s.messages)
	return out
}

// appendLocked appends msg to the history slice, evicting the oldest entry when
// the slice would exceed maxHist. Must be called with s.mu held.
func (s *Service) appendLocked(msg ChatMessage) {
	if s.maxHist <= 0 {
		return
	}
	if len(s.messages) >= s.maxHist {
		// Shift left to drop the oldest message.
		copy(s.messages, s.messages[1:])
		s.messages[len(s.messages)-1] = msg
	} else {
		s.messages = append(s.messages, msg)
	}
}

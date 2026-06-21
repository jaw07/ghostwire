package chat

import (
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestNewService(t *testing.T) {
	s := New("node-1", 50)
	if s.nodeID != "node-1" {
		t.Fatalf("expected nodeID %q, got %q", "node-1", s.nodeID)
	}
	if s.maxHist != 50 {
		t.Fatalf("expected maxHist 50, got %d", s.maxHist)
	}
	if len(s.History()) != 0 {
		t.Fatal("expected empty history on new service")
	}
}

func TestSendAndHistory(t *testing.T) {
	s := New("alice", 100)

	var called int32
	var received ChatMessage
	s.OnSend = func(msg ChatMessage) {
		atomic.AddInt32(&called, 1)
		received = msg
	}

	before := time.Now().UnixMilli()
	s.Send("hello mesh")
	after := time.Now().UnixMilli()

	if atomic.LoadInt32(&called) != 1 {
		t.Fatal("OnSend was not called exactly once")
	}
	if received.Sender != "alice" {
		t.Errorf("expected sender %q, got %q", "alice", received.Sender)
	}
	if received.Text != "hello mesh" {
		t.Errorf("expected text %q, got %q", "hello mesh", received.Text)
	}
	if received.Timestamp < before || received.Timestamp > after {
		t.Errorf("timestamp %d out of expected range [%d, %d]", received.Timestamp, before, after)
	}

	hist := s.History()
	if len(hist) != 1 {
		t.Fatalf("expected 1 history entry, got %d", len(hist))
	}
	if hist[0].Text != "hello mesh" {
		t.Errorf("history entry text mismatch: got %q", hist[0].Text)
	}
}

func TestReceive(t *testing.T) {
	s := New("bob", 100)

	var called int32
	var received ChatMessage
	s.OnReceive = func(msg ChatMessage) {
		atomic.AddInt32(&called, 1)
		received = msg
	}

	incoming := ChatMessage{
		Sender:    "alice",
		Text:      "hi bob",
		Timestamp: time.Now().UnixMilli(),
	}
	s.Receive(incoming)

	if atomic.LoadInt32(&called) != 1 {
		t.Fatal("OnReceive was not called exactly once")
	}
	if received.Sender != "alice" {
		t.Errorf("expected sender %q, got %q", "alice", received.Sender)
	}
	if received.Text != "hi bob" {
		t.Errorf("expected text %q, got %q", "hi bob", received.Text)
	}

	hist := s.History()
	if len(hist) != 1 {
		t.Fatalf("expected 1 history entry, got %d", len(hist))
	}
	if hist[0].Sender != "alice" {
		t.Errorf("history entry sender mismatch: got %q", hist[0].Sender)
	}
}

func TestHistoryLimit(t *testing.T) {
	const maxHist = 5
	s := New("node-x", maxHist)

	for i := 0; i < maxHist+3; i++ {
		s.Send(string(rune('A' + i))) // sends "A", "B", … "H"
	}

	hist := s.History()
	if len(hist) != maxHist {
		t.Fatalf("expected history length %d, got %d", maxHist, len(hist))
	}

	// The oldest 3 messages ("A", "B", "C") should have been evicted.
	// Remaining should be "D", "E", "F", "G", "H".
	expected := []string{"D", "E", "F", "G", "H"}
	for i, want := range expected {
		if hist[i].Text != want {
			t.Errorf("hist[%d].Text = %q, want %q", i, hist[i].Text, want)
		}
	}
}

func TestIgnoreOwnMessages(t *testing.T) {
	s := New("self-node", 100)

	var called int32
	s.OnReceive = func(msg ChatMessage) {
		atomic.AddInt32(&called, 1)
	}

	own := ChatMessage{
		Sender:    "self-node",
		Text:      "should be ignored",
		Timestamp: time.Now().UnixMilli(),
	}
	s.Receive(own)

	if atomic.LoadInt32(&called) != 0 {
		t.Fatal("OnReceive should NOT be called for own messages")
	}
	if len(s.History()) != 0 {
		t.Fatal("own message should not appear in history")
	}
}

func TestReceiveDropsOversized(t *testing.T) {
	s := New("self", 10)
	received := 0
	s.OnReceive = func(ChatMessage) { received++ }

	s.Receive(ChatMessage{Sender: "peer", Text: strings.Repeat("x", MaxTextLen+1)})
	if received != 0 || len(s.History()) != 0 {
		t.Errorf("oversized message should be dropped: received=%d history=%d", received, len(s.History()))
	}

	s.Receive(ChatMessage{Sender: "peer", Text: "hi"})
	if received != 1 || len(s.History()) != 1 {
		t.Errorf("in-bounds message should be accepted: received=%d history=%d", received, len(s.History()))
	}
}

func TestSendTruncatesOversized(t *testing.T) {
	s := New("self", 10)
	var sent ChatMessage
	s.OnSend = func(m ChatMessage) { sent = m }

	s.Send(strings.Repeat("y", MaxTextLen+100))
	if len(sent.Text) != MaxTextLen {
		t.Errorf("Send should truncate to %d, got %d", MaxTextLen, len(sent.Text))
	}
}

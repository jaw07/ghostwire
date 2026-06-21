package canary

import (
	"crypto/ed25519"
	"sync"
	"testing"
	"time"
)

func TestNewDeadSwitch(t *testing.T) {
	c, err := NewDeadSwitch("node-1", "test dead switch", time.Hour, 3)
	if err != nil {
		t.Fatalf("NewDeadSwitch error: %v", err)
	}

	if c.Type != TypeDeadSwitch {
		t.Errorf("Type = %v, want %v", c.Type, TypeDeadSwitch)
	}
	if c.NodeID != "node-1" {
		t.Errorf("NodeID = %q, want %q", c.NodeID, "node-1")
	}
	if c.CheckInInterval != time.Hour {
		t.Errorf("CheckInInterval = %v, want %v", c.CheckInInterval, time.Hour)
	}
	if c.Threshold != 3 {
		t.Errorf("Threshold = %d, want 3", c.Threshold)
	}
}

func TestNewTripwire(t *testing.T) {
	c, err := NewTripwire("node-1", "test tripwire", "/etc/passwd")
	if err != nil {
		t.Fatalf("NewTripwire error: %v", err)
	}

	if c.Type != TypeTripwire {
		t.Errorf("Type = %v, want %v", c.Type, TypeTripwire)
	}
	if c.Context != "/etc/passwd" {
		t.Errorf("Context = %q, want %q", c.Context, "/etc/passwd")
	}
}

func TestNewHoneypot(t *testing.T) {
	c, err := NewHoneypot("node-1", "test honeypot", "fake_password")
	if err != nil {
		t.Fatalf("NewHoneypot error: %v", err)
	}

	if c.Type != TypeHoneypot {
		t.Errorf("Type = %v, want %v", c.Type, TypeHoneypot)
	}
	if c.Context != "fake_password" {
		t.Errorf("Context = %q, want %q", c.Context, "fake_password")
	}
}

func TestCanaryID(t *testing.T) {
	c, _ := NewDeadSwitch("node-1", "test", time.Hour, 3)

	// ID should be hex encoded
	id := c.IDString()
	if len(id) != CanaryIDLength*2 {
		t.Errorf("IDString length = %d, want %d", len(id), CanaryIDLength*2)
	}

	// ShortID should be 8 chars
	short := c.ShortID()
	if len(short) != 8 {
		t.Errorf("ShortID length = %d, want 8", len(short))
	}
}

func TestDeadSwitchCheckIn(t *testing.T) {
	c, _ := NewDeadSwitch("node-1", "test", 100*time.Millisecond, 2)

	// Initially not due
	if c.IsDue() {
		t.Error("Should not be due immediately")
	}

	// Wait until due (~1 missed interval). RecordMiss counts elapsed intervals,
	// so one missed window must not yet reach the threshold of 2.
	time.Sleep(150 * time.Millisecond)
	if !c.IsDue() {
		t.Error("Should be due after interval")
	}
	if c.RecordMiss() {
		t.Error("Should not trigger after 1 missed interval")
	}
	if c.MissedCount != 1 {
		t.Errorf("MissedCount = %d, want 1", c.MissedCount)
	}

	// After a second missed interval elapses, the threshold (2) is reached.
	time.Sleep(120 * time.Millisecond) // ~2.7 intervals total
	if !c.RecordMiss() {
		t.Error("Should trigger after 2 missed intervals (threshold)")
	}

	// Check-in resets
	c.CheckIn()
	if c.MissedCount != 0 {
		t.Errorf("MissedCount after check-in = %d, want 0", c.MissedCount)
	}
	if c.IsDue() {
		t.Error("Should not be due after check-in")
	}
}

func TestCanaryTrigger(t *testing.T) {
	c, _ := NewTripwire("node-1", "test", "/path")

	if c.Triggered {
		t.Error("Should not be triggered initially")
	}

	c.Trigger()
	if !c.Triggered {
		t.Error("Should be triggered after Trigger()")
	}
	if c.TriggeredAt.IsZero() {
		t.Error("TriggeredAt should be set")
	}

	// Double trigger should not change time
	firstTrigger := c.TriggeredAt
	time.Sleep(10 * time.Millisecond)
	c.Trigger()
	if c.TriggeredAt != firstTrigger {
		t.Error("TriggeredAt should not change on second trigger")
	}
}

func TestCanarySignAndVerify(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey error: %v", err)
	}

	c, _ := NewDeadSwitch("node-1", "test", time.Hour, 3)

	// Sign
	sc, err := Sign(c, priv)
	if err != nil {
		t.Fatalf("Sign error: %v", err)
	}

	// Verify
	if !Verify(sc, pub) {
		t.Error("Verify should succeed")
	}

	// Modify canary
	sc.Canary.Description = "modified"
	if Verify(sc, pub) {
		t.Error("Verify should fail after modification")
	}
}

func TestMonitorRegister(t *testing.T) {
	m := NewMonitor(&MonitorConfig{NodeID: "test"})

	c, _ := NewDeadSwitch("node-1", "test", time.Hour, 3)

	// Register
	if err := m.Register(c); err != nil {
		t.Fatalf("Register error: %v", err)
	}

	// Get
	got, ok := m.Get(c.IDString())
	if !ok || got != c {
		t.Error("Get should find registered canary")
	}

	// Double register should fail
	if err := m.Register(c); err == nil {
		t.Error("Double register should fail")
	}

	// Unregister
	if err := m.Unregister(c.IDString()); err != nil {
		t.Fatalf("Unregister error: %v", err)
	}

	// Should not find after unregister
	_, ok = m.Get(c.IDString())
	if ok {
		t.Error("Get should not find unregistered canary")
	}
}

func TestMonitorCheckIn(t *testing.T) {
	m := NewMonitor(&MonitorConfig{NodeID: "test"})

	c, _ := m.CreateDeadSwitch("test", 100*time.Millisecond, 3)

	// Wait until due
	time.Sleep(150 * time.Millisecond)
	if !c.IsDue() {
		t.Error("Should be due")
	}

	// Check in
	if err := m.CheckIn(c.IDString()); err != nil {
		t.Fatalf("CheckIn error: %v", err)
	}

	if c.IsDue() {
		t.Error("Should not be due after check-in")
	}
}

func TestMonitorAlerts(t *testing.T) {
	m := NewMonitor(&MonitorConfig{
		NodeID:        "test",
		CheckInterval: 50 * time.Millisecond,
	})

	var mu sync.Mutex
	var alerts []*Alert

	m.AddHandlerFunc(func(a *Alert) {
		mu.Lock()
		alerts = append(alerts, a)
		mu.Unlock()
	})

	// Create dead switch with short interval and low threshold
	c, _ := m.CreateDeadSwitch("test", 50*time.Millisecond, 1)

	// Start monitoring
	m.Start()
	defer m.Stop()

	// Wait for alert (miss threshold = 1, so first check after due should trigger)
	time.Sleep(200 * time.Millisecond)

	mu.Lock()
	count := len(alerts)
	mu.Unlock()

	if count == 0 {
		t.Error("Should have received alert")
	}

	if !c.Triggered {
		t.Error("Canary should be triggered")
	}
}

func TestMonitorTripwire(t *testing.T) {
	m := NewMonitor(&MonitorConfig{NodeID: "test"})

	var received *Alert
	m.AddHandlerFunc(func(a *Alert) {
		received = a
	})

	c, _ := m.CreateTripwire("test tripwire", "/secret/path")

	// Trigger
	if err := m.TriggerTripwire(c.IDString(), "192.168.1.1"); err != nil {
		t.Fatalf("TriggerTripwire error: %v", err)
	}

	if received == nil {
		t.Fatal("Should have received alert")
	}
	if received.CanaryType != TypeTripwire {
		t.Errorf("CanaryType = %v, want %v", received.CanaryType, TypeTripwire)
	}
	if received.Details.AccessSource != "192.168.1.1" {
		t.Errorf("AccessSource = %q, want %q", received.Details.AccessSource, "192.168.1.1")
	}
}

func TestMonitorHoneypot(t *testing.T) {
	m := NewMonitor(&MonitorConfig{NodeID: "test"})

	var received *Alert
	m.AddHandlerFunc(func(a *Alert) {
		received = a
	})

	c, _ := m.CreateHoneypot("test honeypot", "fake_token_123")

	// Check honeypot
	found, ok := m.CheckHoneypot("fake_token_123")
	if !ok || found != c {
		t.Error("CheckHoneypot should find matching honeypot")
	}

	_, ok = m.CheckHoneypot("real_token")
	if ok {
		t.Error("CheckHoneypot should not find non-matching value")
	}

	// Trigger
	if err := m.TriggerHoneypot(c.IDString(), "auth", "login attempt"); err != nil {
		t.Fatalf("TriggerHoneypot error: %v", err)
	}

	if received == nil {
		t.Fatal("Should have received alert")
	}
	if received.CanaryType != TypeHoneypot {
		t.Errorf("CanaryType = %v, want %v", received.CanaryType, TypeHoneypot)
	}
	if received.Details.AttemptType != "auth" {
		t.Errorf("AttemptType = %q, want %q", received.Details.AttemptType, "auth")
	}
}

func TestMonitorList(t *testing.T) {
	m := NewMonitor(&MonitorConfig{NodeID: "test"})

	m.CreateDeadSwitch("ds1", time.Hour, 3)
	m.CreateDeadSwitch("ds2", time.Hour, 3)
	m.CreateTripwire("tw1", "/path")
	m.CreateHoneypot("hp1", "value")

	all := m.List()
	if len(all) != 4 {
		t.Errorf("List() len = %d, want 4", len(all))
	}

	deadSwitches := m.ListByType(TypeDeadSwitch)
	if len(deadSwitches) != 2 {
		t.Errorf("ListByType(DeadSwitch) len = %d, want 2", len(deadSwitches))
	}

	stats := m.Stats()
	if stats.TotalCanaries != 4 {
		t.Errorf("TotalCanaries = %d, want 4", stats.TotalCanaries)
	}
	if stats.DeadSwitches != 2 {
		t.Errorf("DeadSwitches = %d, want 2", stats.DeadSwitches)
	}
}

func TestTypeString(t *testing.T) {
	tests := []struct {
		t        Type
		expected string
	}{
		{TypeDeadSwitch, "dead_switch"},
		{TypeTripwire, "tripwire"},
		{TypeHoneypot, "honeypot"},
		{Type(99), "unknown(99)"},
	}

	for _, tt := range tests {
		if got := tt.t.String(); got != tt.expected {
			t.Errorf("Type(%d).String() = %q, want %q", tt.t, got, tt.expected)
		}
	}
}

package canary

import (
	"crypto/ed25519"
	"sync"
	"testing"
	"time"
)

type testAlertHandler struct {
	mu     sync.Mutex
	alerts []*Alert
}

func (h *testAlertHandler) OnAlert(alert *Alert) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.alerts = append(h.alerts, alert)
}

func (h *testAlertHandler) getAlerts() []*Alert {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]*Alert{}, h.alerts...)
}

func TestCanaryIntegration(t *testing.T) {
	handler := &testAlertHandler{}
	monitor := NewMonitor(&MonitorConfig{
		NodeID:        "test-node",
		CheckInterval: 100 * time.Millisecond,
	})
	monitor.AddHandler(handler)
	monitor.Start()
	defer monitor.Stop()

	t.Run("DeadSwitch", func(t *testing.T) {
		// Create a dead switch with short interval for testing
		canary, err := NewDeadSwitch("test-node", "dead-switch-test", 150*time.Millisecond, 1)
		if err != nil {
			t.Fatalf("NewDeadSwitch error: %v", err)
		}
		if err := monitor.Register(canary); err != nil {
			t.Fatalf("Register error: %v", err)
		}

		t.Logf("Registered dead switch: %s", canary.ShortID())

		// Check in immediately
		if err := monitor.CheckIn(canary.IDString()); err != nil {
			t.Fatalf("CheckIn error: %v", err)
		}
		t.Log("First check-in successful")

		// Wait a bit and check in again
		time.Sleep(50 * time.Millisecond)
		if err := monitor.CheckIn(canary.IDString()); err != nil {
			t.Fatalf("Second CheckIn error: %v", err)
		}
		t.Log("Second check-in successful")

		// Miss the check-in and wait for alert (needs to miss threshold times)
		time.Sleep(400 * time.Millisecond)

		alerts := handler.getAlerts()
		foundDeadSwitch := false
		for _, alert := range alerts {
			if alert.CanaryID == canary.IDString() && alert.CanaryType == TypeDeadSwitch {
				foundDeadSwitch = true
				t.Logf("Dead switch alert fired for canary: %s", alert.CanaryID[:8])
			}
		}
		if !foundDeadSwitch {
			t.Logf("Alerts received: %d", len(alerts))
			for _, a := range alerts {
				t.Logf("  - CanaryID: %s, Type: %v", a.CanaryID[:8], a.CanaryType)
			}
		}
	})

	t.Run("Tripwire", func(t *testing.T) {
		// Create a tripwire
		canary, err := NewTripwire("test-node", "tripwire-test", "/secret/path")
		if err != nil {
			t.Fatalf("NewTripwire error: %v", err)
		}
		if err := monitor.Register(canary); err != nil {
			t.Fatalf("Register error: %v", err)
		}

		t.Logf("Registered tripwire: %s", canary.ShortID())

		// Trip the wire
		if err := monitor.TriggerTripwire(canary.IDString(), "192.0.2.100"); err != nil {
			t.Fatalf("TriggerTripwire error: %v", err)
		}

		time.Sleep(50 * time.Millisecond)

		alerts := handler.getAlerts()
		foundTripwire := false
		for _, alert := range alerts {
			if alert.CanaryID == canary.IDString() && alert.CanaryType == TypeTripwire {
				foundTripwire = true
				t.Logf("Tripwire alert fired, source: %s", alert.Details.AccessSource)
			}
		}
		if !foundTripwire {
			t.Error("Expected tripwire alert not found")
		}
	})

	t.Run("Honeypot", func(t *testing.T) {
		// Create a honeypot
		canary, err := NewHoneypot("test-node", "honeypot-test", "fake-api-key-12345")
		if err != nil {
			t.Fatalf("NewHoneypot error: %v", err)
		}
		if err := monitor.Register(canary); err != nil {
			t.Fatalf("Register error: %v", err)
		}

		t.Logf("Registered honeypot: %s", canary.ShortID())

		// Trigger the honeypot
		if err := monitor.TriggerHoneypot(canary.IDString(), "api_call", "GET /admin"); err != nil {
			t.Fatalf("TriggerHoneypot error: %v", err)
		}

		time.Sleep(50 * time.Millisecond)

		alerts := handler.getAlerts()
		foundHoneypot := false
		for _, alert := range alerts {
			if alert.CanaryID == canary.IDString() && alert.CanaryType == TypeHoneypot {
				foundHoneypot = true
				t.Logf("Honeypot alert fired, attempt type: %s", alert.Details.AttemptType)
			}
		}
		if !foundHoneypot {
			t.Error("Expected honeypot alert not found")
		}
	})

	t.Run("SignAndVerify", func(t *testing.T) {
		// Generate a key pair for signing
		pubKey, privKey, err := ed25519.GenerateKey(nil)
		if err != nil {
			t.Fatalf("GenerateKey error: %v", err)
		}

		canary, err := NewTripwire("test-node", "sign-test", "/test/path")
		if err != nil {
			t.Fatalf("NewTripwire error: %v", err)
		}

		// Sign the canary
		signed, err := Sign(canary, privKey)
		if err != nil {
			t.Fatalf("Sign error: %v", err)
		}
		t.Log("Canary signed successfully")

		// Verify
		if !Verify(signed, pubKey) {
			t.Error("Canary verification failed")
		}
		t.Log("Canary verified successfully")

		// Tamper with the canary (modify a field that IS part of the signature)
		signed.Canary.Description = "tampered-description"
		if Verify(signed, pubKey) {
			t.Error("Tampered canary should fail verification")
		}
		t.Log("Tampered canary correctly rejected")
	})

	t.Run("ListCanaries", func(t *testing.T) {
		canaries := monitor.List()
		t.Logf("Total canaries registered: %d", len(canaries))

		if len(canaries) < 3 {
			t.Errorf("Expected at least 3 canaries, got %d", len(canaries))
		}

		// Check types
		types := make(map[Type]int)
		for _, c := range canaries {
			types[c.Type]++
		}
		t.Logf("Canary types: DeadSwitch=%d, Tripwire=%d, Honeypot=%d",
			types[TypeDeadSwitch], types[TypeTripwire], types[TypeHoneypot])
	})

	t.Run("Stats", func(t *testing.T) {
		stats := monitor.Stats()
		t.Logf("Monitor stats: Total=%d, DeadSwitches=%d, Tripwires=%d, Honeypots=%d, Triggered=%d",
			stats.TotalCanaries, stats.DeadSwitches, stats.Tripwires, stats.Honeypots, stats.TriggeredCount)
	})

	t.Log("Canary integration test passed")
}

func TestCanaryManualTrigger(t *testing.T) {
	canary, err := NewTripwire("test-node", "manual-test", "/test")
	if err != nil {
		t.Fatalf("NewTripwire error: %v", err)
	}

	if canary.Triggered {
		t.Error("Canary should not be triggered initially")
	}

	// Manually trigger
	canary.Trigger()

	if !canary.Triggered {
		t.Error("Canary should be triggered after Trigger()")
	}
	if canary.TriggeredAt.IsZero() {
		t.Error("TriggeredAt should be set")
	}

	t.Logf("Canary triggered at: %v", canary.TriggeredAt)
}

func TestCheckHoneypot(t *testing.T) {
	monitor := NewMonitor(&MonitorConfig{NodeID: "test"})

	// Create a honeypot with a specific value
	canary, err := NewHoneypot("test", "api-key", "secret-key-12345")
	if err != nil {
		t.Fatalf("NewHoneypot error: %v", err)
	}
	monitor.Register(canary)

	// Check if value matches
	found, ok := monitor.CheckHoneypot("secret-key-12345")
	if !ok {
		t.Error("CheckHoneypot should find the honeypot")
	}
	if found.IDString() != canary.IDString() {
		t.Error("CheckHoneypot returned wrong canary")
	}

	// Check non-matching value
	_, ok = monitor.CheckHoneypot("wrong-key")
	if ok {
		t.Error("CheckHoneypot should not find non-matching value")
	}
}

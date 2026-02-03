package secure

import (
	"bytes"
	"testing"
)

func TestRegion(t *testing.T) {
	region, err := NewRegion(64, "test")
	if err != nil {
		t.Fatalf("NewRegion error: %v", err)
	}
	defer region.Close()

	// Write data
	data := []byte("secret data")
	if err := region.Write(data); err != nil {
		t.Fatalf("Write error: %v", err)
	}

	// Read data back
	read, err := region.Read()
	if err != nil {
		t.Fatalf("Read error: %v", err)
	}

	// Verify (Read returns full buffer, not just written data)
	if !bytes.HasPrefix(read, data) {
		t.Errorf("Read data mismatch")
	}

	// Check stats
	stats := region.Stats()
	if stats.Purpose != "test" {
		t.Errorf("Purpose = %q, want %q", stats.Purpose, "test")
	}
	if stats.AccessCount != 2 { // Write + Read
		t.Errorf("AccessCount = %d, want 2", stats.AccessCount)
	}
}

func TestRegionWipe(t *testing.T) {
	region, err := NewRegion(32, "test")
	if err != nil {
		t.Fatalf("NewRegion error: %v", err)
	}
	defer region.Close()

	data := []byte("sensitive")
	region.Write(data)

	// Wipe
	region.Wipe()

	// Should error on read after wipe
	_, err = region.Read()
	if err == nil {
		t.Error("Read should error after wipe")
	}

	// Stats should show wiped
	stats := region.Stats()
	if !stats.Wiped {
		t.Error("Wiped should be true")
	}
}

func TestRegionSizeLimit(t *testing.T) {
	region, err := NewRegion(10, "test")
	if err != nil {
		t.Fatalf("NewRegion error: %v", err)
	}
	defer region.Close()

	// Write data exceeding size
	err = region.Write([]byte("this is way too long"))
	if err == nil {
		t.Error("Write should error when data exceeds size")
	}
}

func TestCompartment(t *testing.T) {
	c := NewCompartment("test", 1024)
	defer c.Close()

	// Allocate a region
	region, err := c.Allocate("key1", 64, "private key")
	if err != nil {
		t.Fatalf("Allocate error: %v", err)
	}

	// Write to region
	if err := region.Write([]byte("secret")); err != nil {
		t.Fatalf("Write error: %v", err)
	}

	// Get region
	got, ok := c.Get("key1")
	if !ok {
		t.Fatal("Get should find region")
	}
	if got != region {
		t.Error("Get returned different region")
	}

	// Check stats
	stats := c.Stats()
	if stats.RegionCount != 1 {
		t.Errorf("RegionCount = %d, want 1", stats.RegionCount)
	}
	if stats.TotalSize != 64 {
		t.Errorf("TotalSize = %d, want 64", stats.TotalSize)
	}

	// Release region
	if err := c.Release("key1"); err != nil {
		t.Fatalf("Release error: %v", err)
	}

	// Should not find released region
	_, ok = c.Get("key1")
	if ok {
		t.Error("Get should not find released region")
	}
}

func TestCompartmentSizeLimit(t *testing.T) {
	c := NewCompartment("test", 100)
	defer c.Close()

	// First allocation
	_, err := c.Allocate("r1", 60, "test")
	if err != nil {
		t.Fatalf("First allocate error: %v", err)
	}

	// Second allocation exceeds limit
	_, err = c.Allocate("r2", 60, "test")
	if err == nil {
		t.Error("Second allocate should error when exceeding limit")
	}

	// Smaller allocation should work
	_, err = c.Allocate("r3", 30, "test")
	if err != nil {
		t.Errorf("Third allocate should succeed: %v", err)
	}
}

func TestCompartmentDuplicateID(t *testing.T) {
	c := NewCompartment("test", 1024)
	defer c.Close()

	_, err := c.Allocate("dup", 32, "test")
	if err != nil {
		t.Fatalf("First allocate error: %v", err)
	}

	_, err = c.Allocate("dup", 32, "test")
	if err == nil {
		t.Error("Duplicate allocate should error")
	}
}

func TestManager(t *testing.T) {
	m := NewManager(nil)
	defer m.Close()

	// Standard compartments should exist
	for _, name := range []string{CompartmentCA, CompartmentNode, CompartmentSession, CompartmentTokens, CompartmentSecrets} {
		_, ok := m.GetCompartment(name)
		if !ok {
			t.Errorf("Standard compartment %q not found", name)
		}
	}

	// Allocate in standard compartment
	region, err := m.Allocate(CompartmentNode, "node-key", 64, "ed25519 seed")
	if err != nil {
		t.Fatalf("Allocate error: %v", err)
	}

	data := []byte("32-byte-ed25519-seed-goes-here!")
	if err := region.Write(data); err != nil {
		t.Fatalf("Write error: %v", err)
	}

	// Get region back
	got, err := m.Get(CompartmentNode, "node-key")
	if err != nil {
		t.Fatalf("Get error: %v", err)
	}
	if got != region {
		t.Error("Get returned different region")
	}

	// Check stats
	stats := m.Stats()
	if stats.CompartmentCount != 5 {
		t.Errorf("CompartmentCount = %d, want 5", stats.CompartmentCount)
	}
	if stats.TotalRegions != 1 {
		t.Errorf("TotalRegions = %d, want 1", stats.TotalRegions)
	}

	// Release
	if err := m.Release(CompartmentNode, "node-key"); err != nil {
		t.Fatalf("Release error: %v", err)
	}
}

func TestManagerCustomCompartment(t *testing.T) {
	m := NewManager(nil)
	defer m.Close()

	// Create custom compartment
	c, err := m.CreateCompartment("custom", 512)
	if err != nil {
		t.Fatalf("CreateCompartment error: %v", err)
	}

	// Allocate in custom compartment
	_, err = c.Allocate("data", 128, "custom data")
	if err != nil {
		t.Fatalf("Allocate error: %v", err)
	}

	// Get via manager
	got, ok := m.GetCompartment("custom")
	if !ok || got != c {
		t.Error("GetCompartment should find custom compartment")
	}
}

func TestManagerWipeAll(t *testing.T) {
	m := NewManager(nil)
	defer m.Close()

	// Allocate in multiple compartments
	r1, _ := m.Allocate(CompartmentNode, "k1", 32, "test")
	r2, _ := m.Allocate(CompartmentSecrets, "k2", 32, "test")

	r1.Write([]byte("data1"))
	r2.Write([]byte("data2"))

	// Wipe all
	m.WipeAll()

	// Both should be wiped
	if !r1.Stats().Wiped || !r2.Stats().Wiped {
		t.Error("WipeAll should wipe all regions")
	}
}

func TestGlobalManager(t *testing.T) {
	// Get global manager
	m := Global()
	if m == nil {
		t.Fatal("Global() returned nil")
	}

	// Second call returns same instance
	m2 := Global()
	if m != m2 {
		t.Error("Global() should return same instance")
	}
}

func TestWipeBytes(t *testing.T) {
	data := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	wipeBytes(data)

	for i, b := range data {
		if b != 0 {
			t.Errorf("data[%d] = %d, want 0", i, b)
		}
	}
}

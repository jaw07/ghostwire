package api

import (
	"net"
	"testing"
	"time"

	"github.com/ghostwire/ghostwire/internal/config"
)

func newTestServer(subnet, nextIP, adminIP string) *EnrollmentServer {
	return &EnrollmentServer{
		adminConfig: &config.AdminConfig{
			MeshConfig: config.MeshConfig{
				MeshSubnet: subnet,
				AssignedIP: adminIP,
			},
			IPAllocator: config.IPAllocatorState{
				NextIP:    nextIP,
				Allocated: map[string]string{},
			},
		},
	}
}

func TestAllocateIPStaysInSubnet(t *testing.T) {
	// A /30 has exactly two usable hosts (.1 and .2); .0 is network, .3 broadcast.
	s := newTestServer("10.0.0.0/30", "10.0.0.0", "")

	got1, err := s.allocateIP("node-a")
	if err != nil {
		t.Fatalf("first allocation: %v", err)
	}
	// .0 is the network address and must be skipped.
	if got1 != "10.0.0.1" {
		t.Errorf("first allocation = %s, want 10.0.0.1 (network .0 must be skipped)", got1)
	}

	got2, err := s.allocateIP("node-b")
	if err != nil {
		t.Fatalf("second allocation: %v", err)
	}
	if got2 != "10.0.0.2" {
		t.Errorf("second allocation = %s, want 10.0.0.2", got2)
	}

	// Pool is now exhausted (.3 is broadcast); allocation must fail, not bleed
	// past the subnet.
	if _, err := s.allocateIP("node-c"); err == nil {
		t.Error("expected pool-exhausted error, got nil (allocator escaped subnet)")
	}
}

func TestAllocateIPSkipsCollisions(t *testing.T) {
	s := newTestServer("10.0.0.0/24", "10.0.0.10", "10.0.0.10")
	s.adminConfig.IPAllocator.Allocated["existing"] = "10.0.0.11"

	got, err := s.allocateIP("node-a")
	if err != nil {
		t.Fatalf("allocation: %v", err)
	}
	// .10 is the admin IP and .11 is already allocated; both must be skipped.
	if got == "10.0.0.10" || got == "10.0.0.11" {
		t.Errorf("allocated a colliding address: %s", got)
	}
	if got != "10.0.0.12" {
		t.Errorf("allocation = %s, want 10.0.0.12", got)
	}
}

func TestAllocateIPIdempotentForSameNode(t *testing.T) {
	s := newTestServer("10.0.0.0/24", "10.0.0.5", "")
	first, _ := s.allocateIP("node-a")
	second, _ := s.allocateIP("node-a")
	if first != second {
		t.Errorf("re-allocation for same node changed: %s != %s", first, second)
	}
}

func TestIncIPCarry(t *testing.T) {
	ip := net.ParseIP("10.0.0.255").To4()
	incIP(ip)
	if ip.String() != "10.0.1.0" {
		t.Errorf("incIP(10.0.0.255) = %s, want 10.0.1.0", ip.String())
	}
}

func TestIsReservedIP(t *testing.T) {
	_, subnet, _ := net.ParseCIDR("10.0.0.0/24")
	cases := map[string]bool{
		"10.0.0.0":   true,  // network
		"10.0.0.255": true,  // broadcast
		"10.0.0.1":   false, // usable
		"10.0.0.128": false, // usable
	}
	for ipStr, want := range cases {
		got := isReservedIP(net.ParseIP(ipStr), subnet)
		if got != want {
			t.Errorf("isReservedIP(%s) = %v, want %v", ipStr, got, want)
		}
	}
}

func TestEnrollLimiter(t *testing.T) {
	l := newEnrollLimiter(3, time.Minute)
	now := time.Now()

	for i := 0; i < 3; i++ {
		if !l.allow("1.2.3.4", now) {
			t.Fatalf("request %d should be allowed", i)
		}
	}
	// 4th within window is throttled.
	if l.allow("1.2.3.4", now) {
		t.Error("4th request within window should be rate-limited")
	}
	// A different IP is unaffected.
	if !l.allow("5.6.7.8", now) {
		t.Error("different IP should be allowed")
	}
	// After the window elapses, the original IP is allowed again.
	if !l.allow("1.2.3.4", now.Add(2*time.Minute)) {
		t.Error("request after window should be allowed")
	}
}

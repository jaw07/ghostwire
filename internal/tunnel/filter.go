package tunnel

import (
	"sync/atomic"

	"golang.zx2c4.com/wireguard/tun"
)

// PacketFilter decides whether an IP packet may traverse the data path.
//
// direction is "egress" for packets read from the local TUN (outbound, this
// node is the source) and "ingress" for packets received from a peer that are
// about to be written to the local TUN. It mirrors the direction argument of
// policy.Enforcer.CheckPacket so the enforcer can be adapted directly.
type PacketFilter interface {
	Allow(packet []byte, direction string) bool
}

// filteredTUN wraps a tun.Device and applies a PacketFilter to every packet in
// both directions. The filter is swappable at runtime (and may be nil, meaning
// allow-all) so the device can be created before the policy enforcer exists and
// have the enforcer attached during startup. Read/Write are the only methods
// that need policy; all others are promoted from the embedded tun.Device.
type filteredTUN struct {
	tun.Device
	filter atomic.Pointer[filterHolder]
}

// filterHolder boxes a PacketFilter so it can be stored in an atomic.Pointer
// regardless of the filter's concrete type.
type filterHolder struct {
	f PacketFilter
}

func newFilteredTUN(dev tun.Device) *filteredTUN {
	return &filteredTUN{Device: dev}
}

// SetFilter installs (or clears, with nil) the active packet filter.
func (f *filteredTUN) SetFilter(filter PacketFilter) {
	if filter == nil {
		f.filter.Store(nil)
		return
	}
	f.filter.Store(&filterHolder{f: filter})
}

func (f *filteredTUN) current() PacketFilter {
	h := f.filter.Load()
	if h == nil {
		return nil
	}
	return h.f
}

// Read reads packets from the underlying TUN (outbound traffic from local
// applications) and drops any the filter denies, compacting the survivors to
// the front of bufs/sizes so the returned count reflects only allowed packets.
func (f *filteredTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	n, err := f.Device.Read(bufs, sizes, offset)
	if err != nil || n == 0 {
		return n, err
	}
	filter := f.current()
	if filter == nil {
		return n, nil
	}

	w := 0
	for i := 0; i < n; i++ {
		pkt := bufs[i][offset : offset+sizes[i]]
		if filter.Allow(pkt, "egress") {
			if w != i {
				copy(bufs[w][offset:offset+sizes[i]], pkt)
				sizes[w] = sizes[i]
			}
			w++
		}
	}
	return w, nil
}

// Write writes packets to the underlying TUN (inbound traffic received from
// peers) after dropping any the filter denies. Denied packets are removed
// in place; the caller's count semantics are preserved by reporting all
// packets as consumed (wireguard-go ignores the returned count on write).
func (f *filteredTUN) Write(bufs [][]byte, offset int) (int, error) {
	filter := f.current()
	if filter == nil {
		return f.Device.Write(bufs, offset)
	}

	w := 0
	for i := range bufs {
		if filter.Allow(bufs[i][offset:], "ingress") {
			bufs[w] = bufs[i]
			w++
		}
	}
	if w == 0 {
		// Everything dropped; nothing to write but the batch is consumed.
		return len(bufs), nil
	}
	if _, err := f.Device.Write(bufs[:w], offset); err != nil {
		return 0, err
	}
	return len(bufs), nil
}

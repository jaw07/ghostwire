package mavlink

import (
	"fmt"
	"net"
	"sync"
	"sync/atomic"
)

// ProxyConfig configures a MAVLink UDP proxy.
type ProxyConfig struct {
	// ListenAddr is the UDP address to bind (e.g., "0.0.0.0:14550").
	// Use ":0" or "0.0.0.0:0" to let the OS pick a free port.
	ListenAddr string

	// ForwardAddr is the local address to deliver packets received from remote clients.
	// If empty, Deliver is a no-op for the forward path.
	ForwardAddr string

	// RemoteTargets are mesh IPs (or host:port) to forward MAVLink packets to.
	// Each target gets a UDP connection through the mesh tunnel.
	// Example: ["10.99.0.2:14550", "10.99.0.3:14550"]
	RemoteTargets []string

	// OnPacket is called for each UDP datagram that passes IsMAVLink.
	// It is called synchronously from the read loop; implementations must not block.
	OnPacket func(data []byte, info *PacketInfo)
}

// ProxyStats holds cumulative counters for a Proxy.
// All fields are updated atomically and are safe to read from any goroutine.
type ProxyStats struct {
	PacketsReceived  uint64
	PacketsForwarded uint64
	PacketsDropped   uint64
	BytesReceived    uint64
	BytesForwarded   uint64
}

// Proxy is a UDP proxy that receives MAVLink datagrams, maintains stats,
// and provides a Deliver path back to the last known sender.
type Proxy struct {
	cfg *ProxyConfig

	conn       *net.UDPConn
	listenAddr net.Addr

	// clientAddr is the most-recently-seen remote sender address.
	mu         sync.Mutex
	clientAddr *net.UDPAddr

	// remoteConns are outbound UDP connections to other mesh nodes
	remoteConns []*net.UDPConn

	// stats — individual uint64 fields kept in a struct for atomic access.
	pktsReceived  atomic.Uint64
	pktsForwarded atomic.Uint64
	pktsDropped   atomic.Uint64
	bytesReceived atomic.Uint64
	bytesForwarded atomic.Uint64

	wg   sync.WaitGroup
	done chan struct{}
}

// NewProxy creates a new Proxy with the given configuration.
// Call Start to begin receiving packets.
func NewProxy(cfg *ProxyConfig) *Proxy {
	return &Proxy{
		cfg:  cfg,
		done: make(chan struct{}),
	}
}

// Start binds the UDP socket and launches the read loop.
// Returns an error if the address cannot be bound.
func (p *Proxy) Start() error {
	addr, err := net.ResolveUDPAddr("udp4", p.cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("mavlink proxy: resolve listen addr: %w", err)
	}

	conn, err := net.ListenUDP("udp4", addr)
	if err != nil {
		return fmt.Errorf("mavlink proxy: listen UDP: %w", err)
	}

	p.conn = conn
	p.listenAddr = conn.LocalAddr()

	// Connect to remote targets (other mesh nodes' MAVLink ports)
	for _, target := range p.cfg.RemoteTargets {
		raddr, err := net.ResolveUDPAddr("udp4", target)
		if err != nil {
			continue
		}
		rc, err := net.DialUDP("udp4", nil, raddr)
		if err != nil {
			continue
		}
		p.remoteConns = append(p.remoteConns, rc)

		// Start receive loop for remote responses (telemetry from drones)
		p.wg.Add(1)
		go p.remoteReadLoop(rc)
	}

	p.wg.Add(1)
	go p.readLoop()

	return nil
}

// Stop closes the UDP socket and waits for the read loop to exit.
func (p *Proxy) Stop() {
	close(p.done)
	if p.conn != nil {
		p.conn.Close()
	}
	for _, rc := range p.remoteConns {
		rc.Close()
	}
	p.wg.Wait()
}

// AddTarget opens a UDP connection to a remote mesh node's MAVLink port.
// Can be called after Start to dynamically add targets (e.g., from gossip).
func (p *Proxy) AddTarget(addr string) error {
	raddr, err := net.ResolveUDPAddr("udp4", addr)
	if err != nil {
		return err
	}
	rc, err := net.DialUDP("udp4", nil, raddr)
	if err != nil {
		return err
	}
	p.mu.Lock()
	p.remoteConns = append(p.remoteConns, rc)
	p.mu.Unlock()

	p.wg.Add(1)
	go p.remoteReadLoop(rc)
	return nil
}

// ListenAddr returns the actual bound address (useful when port 0 was specified).
// Returns nil if Start has not been called.
func (p *Proxy) ListenAddr() net.Addr {
	return p.listenAddr
}

// Stats returns a snapshot of the proxy's cumulative counters.
func (p *Proxy) Stats() ProxyStats {
	return ProxyStats{
		PacketsReceived:  p.pktsReceived.Load(),
		PacketsForwarded: p.pktsForwarded.Load(),
		PacketsDropped:   p.pktsDropped.Load(),
		BytesReceived:    p.bytesReceived.Load(),
		BytesForwarded:   p.bytesForwarded.Load(),
	}
}

// Deliver writes data to the most recently known client address.
// Returns an error if no client has sent a packet yet, or on write failure.
func (p *Proxy) Deliver(data []byte) error {
	p.mu.Lock()
	addr := p.clientAddr
	p.mu.Unlock()

	if addr == nil {
		return fmt.Errorf("mavlink proxy: no known client address")
	}

	n, err := p.conn.WriteToUDP(data, addr)
	if err != nil {
		return fmt.Errorf("mavlink proxy: deliver write: %w", err)
	}
	p.bytesForwarded.Add(uint64(n))
	p.pktsForwarded.Add(1)
	return nil
}

// readLoop is the main receive loop. It exits when done is closed or the conn errors.
func (p *Proxy) readLoop() {
	defer p.wg.Done()

	buf := make([]byte, 65535)
	for {
		select {
		case <-p.done:
			return
		default:
		}

		n, remoteAddr, err := p.conn.ReadFromUDP(buf)
		if err != nil {
			// Check whether we were told to stop.
			select {
			case <-p.done:
				return
			default:
			}
			// Transient error — keep looping.
			p.pktsDropped.Add(1)
			continue
		}

		// Remember the sender for Deliver.
		p.mu.Lock()
		p.clientAddr = remoteAddr
		p.mu.Unlock()

		data := make([]byte, n)
		copy(data, buf[:n])

		p.pktsReceived.Add(1)
		p.bytesReceived.Add(uint64(n))

		if !IsMAVLink(data) {
			p.pktsDropped.Add(1)
			continue
		}

		info, _ := Parse(data)
		if p.cfg.OnPacket != nil {
			p.cfg.OnPacket(data, info)
		}

		// Forward to all remote targets through the mesh tunnel
		p.mu.Lock()
		targets := p.remoteConns
		p.mu.Unlock()
		for _, rc := range targets {
			rc.Write(data)
		}
		if len(targets) > 0 {
			p.pktsForwarded.Add(1)
			p.bytesForwarded.Add(uint64(n))
		}
	}
}

// remoteReadLoop reads MAVLink packets from a remote mesh node and delivers
// them to the local GCS/autopilot.
func (p *Proxy) remoteReadLoop(rc *net.UDPConn) {
	defer p.wg.Done()

	buf := make([]byte, 65535)
	for {
		select {
		case <-p.done:
			return
		default:
		}

		n, err := rc.Read(buf)
		if err != nil {
			select {
			case <-p.done:
				return
			default:
				continue
			}
		}

		data := make([]byte, n)
		copy(data, buf[:n])

		p.pktsReceived.Add(1)
		p.bytesReceived.Add(uint64(n))

		// Deliver to local GCS
		p.Deliver(data)
	}
}

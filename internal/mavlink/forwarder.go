package mavlink

import (
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// LinkConfig describes a named forwarding link between a local listen address
// and a remote target address through the mesh.
type LinkConfig struct {
	Name       string `json:"name"`
	Protocol   string `json:"protocol"`    // "tcp" or "udp"
	ListenAddr string `json:"listen_addr"` // local addr GCS connects to
	TargetAddr string `json:"target_addr"` // remote FC addr (mesh_ip:port)
}

// LinkInfo is a snapshot of a forwarding link's state and statistics.
type LinkInfo struct {
	Name        string `json:"name"`
	Protocol    string `json:"protocol"`
	ListenAddr  string `json:"listen_addr"`
	TargetAddr  string `json:"target_addr"`
	Status      string `json:"status"` // "listening", "connected", "stopped"
	BytesSent   uint64 `json:"bytes_sent"`
	BytesRecv   uint64 `json:"bytes_recv"`
	ActiveConns int    `json:"active_conns"`
}

// link is the internal state for a single forwarding link.
type link struct {
	cfg LinkConfig

	bytesSent   atomic.Uint64
	bytesRecv   atomic.Uint64
	activeConns atomic.Int64

	// listener is a TCP listener or UDP conn, depending on protocol.
	tcpListener net.Listener
	udpConn     *net.UDPConn

	done chan struct{}
	wg   sync.WaitGroup
}

func (l *link) info() LinkInfo {
	status := "listening"
	if l.activeConns.Load() > 0 {
		status = "connected"
	}
	select {
	case <-l.done:
		status = "stopped"
	default:
	}

	return LinkInfo{
		Name:        l.cfg.Name,
		Protocol:    l.cfg.Protocol,
		ListenAddr:  l.cfg.ListenAddr,
		TargetAddr:  l.cfg.TargetAddr,
		Status:      status,
		BytesSent:   l.bytesSent.Load(),
		BytesRecv:   l.bytesRecv.Load(),
		ActiveConns: int(l.activeConns.Load()),
	}
}

func (l *link) stop() {
	close(l.done)
	if l.tcpListener != nil {
		l.tcpListener.Close()
	}
	if l.udpConn != nil {
		l.udpConn.Close()
	}
	l.wg.Wait()
}

// Forwarder manages a set of named forwarding links.
type Forwarder struct {
	// OnChange is called whenever links are created or removed.
	OnChange func(links []LinkInfo)

	mu    sync.Mutex
	links map[string]*link
}

// NewForwarder creates a new Forwarder.
func NewForwarder() *Forwarder {
	return &Forwarder{
		links: make(map[string]*link),
	}
}

// CreateLink starts a new forwarding link. It binds the local listener and
// begins forwarding to the target address. The cfg.ListenAddr is updated to
// reflect the actual bound address (important when port=0).
func (f *Forwarder) CreateLink(cfg LinkConfig) error {
	if cfg.Protocol != "tcp" && cfg.Protocol != "udp" {
		return fmt.Errorf("forwarder: unsupported protocol %q", cfg.Protocol)
	}

	f.mu.Lock()
	if _, exists := f.links[cfg.Name]; exists {
		f.mu.Unlock()
		return fmt.Errorf("forwarder: link %q already exists", cfg.Name)
	}
	f.mu.Unlock()

	l := &link{
		cfg:  cfg,
		done: make(chan struct{}),
	}

	switch cfg.Protocol {
	case "tcp":
		if err := f.startTCP(l); err != nil {
			return err
		}
	case "udp":
		if err := f.startUDP(l); err != nil {
			return err
		}
	}

	f.mu.Lock()
	// Double-check after bind in case of race.
	if _, exists := f.links[cfg.Name]; exists {
		f.mu.Unlock()
		l.stop()
		return fmt.Errorf("forwarder: link %q already exists", cfg.Name)
	}
	f.links[cfg.Name] = l
	f.mu.Unlock()

	f.notifyChange()
	return nil
}

// RemoveLink stops and removes the named link.
func (f *Forwarder) RemoveLink(name string) error {
	f.mu.Lock()
	l, ok := f.links[name]
	if !ok {
		f.mu.Unlock()
		return fmt.Errorf("forwarder: link %q not found", name)
	}
	delete(f.links, name)
	f.mu.Unlock()

	l.stop()
	f.notifyChange()
	return nil
}

// List returns a snapshot of all links.
func (f *Forwarder) List() []LinkInfo {
	f.mu.Lock()
	defer f.mu.Unlock()

	infos := make([]LinkInfo, 0, len(f.links))
	for _, l := range f.links {
		infos = append(infos, l.info())
	}
	return infos
}

// StopAll stops all links and clears the map.
func (f *Forwarder) StopAll() {
	f.mu.Lock()
	links := make(map[string]*link, len(f.links))
	for k, v := range f.links {
		links[k] = v
	}
	f.links = make(map[string]*link)
	f.mu.Unlock()

	for _, l := range links {
		l.stop()
	}
}

func (f *Forwarder) notifyChange() {
	if f.OnChange != nil {
		f.OnChange(f.List())
	}
}

// --- TCP ---

func (f *Forwarder) startTCP(l *link) error {
	ln, err := net.Listen("tcp", l.cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("forwarder: tcp listen: %w", err)
	}
	l.tcpListener = ln
	l.cfg.ListenAddr = ln.Addr().String()

	l.wg.Add(1)
	go f.tcpAcceptLoop(l)
	return nil
}

func (f *Forwarder) tcpAcceptLoop(l *link) {
	defer l.wg.Done()

	for {
		conn, err := l.tcpListener.Accept()
		if err != nil {
			select {
			case <-l.done:
				return
			default:
				time.Sleep(transientReadBackoff)
				continue
			}
		}

		l.activeConns.Add(1)
		l.wg.Add(1)
		go f.tcpHandleConn(l, conn)
	}
}

func (f *Forwarder) tcpHandleConn(l *link, clientConn net.Conn) {
	defer l.wg.Done()
	defer clientConn.Close()
	defer l.activeConns.Add(-1)

	targetConn, err := net.Dial("tcp", l.cfg.TargetAddr)
	if err != nil {
		return
	}
	defer targetConn.Close()

	done := make(chan struct{})

	// client → target (GCS → FC)
	go func() {
		defer func() { close(done) }()
		n, _ := io.Copy(targetConn, clientConn)
		l.bytesSent.Add(uint64(n))
		// Close the write side so the reverse copy unblocks.
		if tc, ok := targetConn.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()

	// target → client (FC → GCS)
	n, _ := io.Copy(clientConn, targetConn)
	l.bytesRecv.Add(uint64(n))
	// Close the write side so the forward copy unblocks.
	if tc, ok := clientConn.(*net.TCPConn); ok {
		tc.CloseWrite()
	}

	<-done
}

// --- UDP ---

func (f *Forwarder) startUDP(l *link) error {
	addr, err := net.ResolveUDPAddr("udp", l.cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("forwarder: udp resolve: %w", err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("forwarder: udp listen: %w", err)
	}
	l.udpConn = conn
	l.cfg.ListenAddr = conn.LocalAddr().String()

	l.wg.Add(1)
	go f.udpLoop(l)
	return nil
}

func (f *Forwarder) udpLoop(l *link) {
	defer l.wg.Done()

	// Dial the target once.
	targetConn, err := net.Dial("udp", l.cfg.TargetAddr)
	if err != nil {
		return
	}
	defer targetConn.Close()

	var (
		clientMu   sync.Mutex
		clientAddr *net.UDPAddr
	)

	// Read from target, send to last-known client.
	l.wg.Add(1)
	go func() {
		defer l.wg.Done()
		buf := make([]byte, 65535)
		for {
			select {
			case <-l.done:
				return
			default:
			}
			n, err := targetConn.Read(buf)
			if err != nil {
				select {
				case <-l.done:
					return
				default:
					time.Sleep(transientReadBackoff)
					continue
				}
			}
			clientMu.Lock()
			ca := clientAddr
			clientMu.Unlock()
			if ca == nil {
				continue
			}
			written, _ := l.udpConn.WriteToUDP(buf[:n], ca)
			l.bytesRecv.Add(uint64(written))
		}
	}()

	// Read from local GCS, send to target.
	buf := make([]byte, 65535)
	for {
		select {
		case <-l.done:
			return
		default:
		}
		n, remote, err := l.udpConn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-l.done:
				return
			default:
				time.Sleep(transientReadBackoff)
				continue
			}
		}

		clientMu.Lock()
		if clientAddr == nil {
			l.activeConns.Add(1)
		}
		clientAddr = remote
		clientMu.Unlock()

		written, _ := targetConn.Write(buf[:n])
		l.bytesSent.Add(uint64(written))
	}
}

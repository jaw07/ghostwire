# MAVLink Port Forwarder Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the broadcast-only MAVLink UDP proxy with a configurable port forwarder that supports TCP and UDP, with a GUI panel to create/remove/monitor forwarding links.

**Architecture:** A `Forwarder` manages named `Link` instances. Each link has a local listen address (where GCS or autopilot connects), a remote target address (mesh IP + flight controller port), and a protocol (TCP or UDP). The GUI exposes a MAVLink panel to create links, see active connections, and monitor packet stats. Links are stored in the proxy config and can be added/removed at runtime via the API.

**Tech Stack:** Go `net` package (TCP/UDP), existing GUI WebSocket hub, existing MAVLink parser.

---

## File Structure

```
internal/mavlink/
  forwarder.go       -- Link + Forwarder (create, remove, list, stats)
  forwarder_test.go  -- Unit tests
  proxy.go           -- KEEP existing (used by forwarder internally for UDP)
  mavlink.go         -- KEEP existing parser

internal/gui/
  api.go             -- MODIFY: add /api/mavlink endpoints
  server.go          -- MODIFY: add MAVLink callbacks + broadcast
  web/index.html     -- MODIFY: add MAVLink panel

internal/cli/
  up.go              -- MODIFY: wire forwarder into daemon, replace old proxy
```

---

## Task 1: Link and Forwarder core

A `Link` represents one forwarding path: local listen → remote target. A `Forwarder` manages multiple links.

**Files:**
- Create: `internal/mavlink/forwarder.go`
- Create: `internal/mavlink/forwarder_test.go`

- [ ] **Step 1: Write failing tests**

Create `internal/mavlink/forwarder_test.go`:

```go
package mavlink

import (
	"io"
	"net"
	"testing"
	"time"
)

func TestForwarderCreateAndListLinks(t *testing.T) {
	f := NewForwarder()
	defer f.StopAll()

	err := f.CreateLink(LinkConfig{
		Name:       "gcs-to-drone",
		Protocol:   "udp",
		ListenAddr: "127.0.0.1:0",
		TargetAddr: "127.0.0.1:15550",
	})
	if err != nil {
		t.Fatal(err)
	}

	links := f.List()
	if len(links) != 1 {
		t.Fatalf("expected 1 link, got %d", len(links))
	}
	if links[0].Name != "gcs-to-drone" {
		t.Fatalf("name: %q", links[0].Name)
	}
	if links[0].Protocol != "udp" {
		t.Fatalf("protocol: %q", links[0].Protocol)
	}
	if links[0].Status != "listening" {
		t.Fatalf("status: %q", links[0].Status)
	}
}

func TestForwarderRemoveLink(t *testing.T) {
	f := NewForwarder()
	defer f.StopAll()

	f.CreateLink(LinkConfig{
		Name: "tmp", Protocol: "udp",
		ListenAddr: "127.0.0.1:0", TargetAddr: "127.0.0.1:15550",
	})

	if err := f.RemoveLink("tmp"); err != nil {
		t.Fatal(err)
	}
	if len(f.List()) != 0 {
		t.Fatal("link not removed")
	}
}

func TestForwarderDuplicateName(t *testing.T) {
	f := NewForwarder()
	defer f.StopAll()

	f.CreateLink(LinkConfig{
		Name: "dup", Protocol: "udp",
		ListenAddr: "127.0.0.1:0", TargetAddr: "127.0.0.1:15550",
	})
	err := f.CreateLink(LinkConfig{
		Name: "dup", Protocol: "udp",
		ListenAddr: "127.0.0.1:0", TargetAddr: "127.0.0.1:15551",
	})
	if err == nil {
		t.Fatal("expected error for duplicate name")
	}
}

func TestForwarderTCPForward(t *testing.T) {
	// Start a TCP "flight controller" server
	fcListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer fcListener.Close()

	go func() {
		conn, err := fcListener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		// Echo back with prefix
		buf := make([]byte, 1024)
		n, _ := conn.Read(buf)
		conn.Write(append([]byte("FC:"), buf[:n]...))
	}()

	f := NewForwarder()
	defer f.StopAll()

	err = f.CreateLink(LinkConfig{
		Name:       "tcp-test",
		Protocol:   "tcp",
		ListenAddr: "127.0.0.1:0",
		TargetAddr: fcListener.Addr().String(),
	})
	if err != nil {
		t.Fatal(err)
	}

	links := f.List()
	listenAddr := links[0].ListenAddr

	// Connect as GCS
	conn, err := net.DialTimeout("tcp", listenAddr, 3*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	conn.Write([]byte("HELLO"))
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf[:n]) != "FC:HELLO" {
		t.Fatalf("got %q, want %q", buf[:n], "FC:HELLO")
	}
}

func TestForwarderUDPForward(t *testing.T) {
	// Start a UDP "flight controller"
	fcAddr, _ := net.ResolveUDPAddr("udp4", "127.0.0.1:0")
	fcConn, err := net.ListenUDP("udp4", fcAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer fcConn.Close()

	go func() {
		buf := make([]byte, 1024)
		n, addr, _ := fcConn.ReadFromUDP(buf)
		fcConn.WriteToUDP(append([]byte("FC:"), buf[:n]...), addr)
	}()

	f := NewForwarder()
	defer f.StopAll()

	err = f.CreateLink(LinkConfig{
		Name:       "udp-test",
		Protocol:   "udp",
		ListenAddr: "127.0.0.1:0",
		TargetAddr: fcConn.LocalAddr().String(),
	})
	if err != nil {
		t.Fatal(err)
	}

	links := f.List()
	listenAddr := links[0].ListenAddr

	// Send as GCS
	gcs, err := net.Dial("udp", listenAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer gcs.Close()

	gcs.Write([]byte("PING"))
	gcs.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 1024)
	n, err := gcs.Read(buf)
	if err != nil && err != io.EOF {
		t.Fatalf("read: %v", err)
	}
	if string(buf[:n]) != "FC:PING" {
		t.Fatalf("got %q, want %q", buf[:n], "FC:PING")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test -v -run 'TestForwarder' ./internal/mavlink/`
Expected: FAIL — `NewForwarder` undefined

- [ ] **Step 3: Implement Forwarder**

Create `internal/mavlink/forwarder.go`:

```go
package mavlink

import (
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
)

// LinkConfig defines a forwarding link
type LinkConfig struct {
	Name       string `json:"name"`
	Protocol   string `json:"protocol"`    // "tcp" or "udp"
	ListenAddr string `json:"listen_addr"` // local address GCS connects to
	TargetAddr string `json:"target_addr"` // remote FC address (mesh_ip:port)
}

// LinkInfo is the runtime state of a link
type LinkInfo struct {
	Name           string `json:"name"`
	Protocol       string `json:"protocol"`
	ListenAddr     string `json:"listen_addr"`
	TargetAddr     string `json:"target_addr"`
	Status         string `json:"status"` // "listening", "connected", "stopped"
	BytesSent      uint64 `json:"bytes_sent"`
	BytesRecv      uint64 `json:"bytes_recv"`
	ActiveConns    int    `json:"active_conns"`
}

// link is an active forwarding link
type link struct {
	cfg        LinkConfig
	listener   net.Listener   // TCP
	udpConn    *net.UDPConn   // UDP listen
	bytesSent  atomic.Uint64
	bytesRecv  atomic.Uint64
	activeConns atomic.Int32
	done       chan struct{}
	wg         sync.WaitGroup
}

// Forwarder manages port forwarding links
type Forwarder struct {
	mu    sync.Mutex
	links map[string]*link

	// OnChange is called when links are added/removed (for GUI updates)
	OnChange func(links []LinkInfo)
}

// NewForwarder creates a new forwarder
func NewForwarder() *Forwarder {
	return &Forwarder{
		links: make(map[string]*link),
	}
}

// CreateLink creates and starts a new forwarding link
func (f *Forwarder) CreateLink(cfg LinkConfig) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if _, exists := f.links[cfg.Name]; exists {
		return fmt.Errorf("link %q already exists", cfg.Name)
	}

	l := &link{
		cfg:  cfg,
		done: make(chan struct{}),
	}

	switch cfg.Protocol {
	case "tcp":
		ln, err := net.Listen("tcp", cfg.ListenAddr)
		if err != nil {
			return fmt.Errorf("listen tcp: %w", err)
		}
		l.listener = ln
		l.cfg.ListenAddr = ln.Addr().String()
		l.wg.Add(1)
		go l.tcpAcceptLoop()

	case "udp":
		addr, err := net.ResolveUDPAddr("udp4", cfg.ListenAddr)
		if err != nil {
			return fmt.Errorf("resolve udp: %w", err)
		}
		conn, err := net.ListenUDP("udp4", addr)
		if err != nil {
			return fmt.Errorf("listen udp: %w", err)
		}
		l.udpConn = conn
		l.cfg.ListenAddr = conn.LocalAddr().String()
		l.wg.Add(1)
		go l.udpForwardLoop()

	default:
		return fmt.Errorf("unsupported protocol: %s", cfg.Protocol)
	}

	f.links[cfg.Name] = l
	f.notifyChange()
	return nil
}

// RemoveLink stops and removes a link by name
func (f *Forwarder) RemoveLink(name string) error {
	f.mu.Lock()
	l, ok := f.links[name]
	if !ok {
		f.mu.Unlock()
		return fmt.Errorf("link %q not found", name)
	}
	delete(f.links, name)
	f.mu.Unlock()

	l.stop()
	f.notifyChange()
	return nil
}

// List returns info about all active links
func (f *Forwarder) List() []LinkInfo {
	f.mu.Lock()
	defer f.mu.Unlock()

	result := make([]LinkInfo, 0, len(f.links))
	for _, l := range f.links {
		status := "listening"
		if l.activeConns.Load() > 0 {
			status = "connected"
		}
		result = append(result, LinkInfo{
			Name:        l.cfg.Name,
			Protocol:    l.cfg.Protocol,
			ListenAddr:  l.cfg.ListenAddr,
			TargetAddr:  l.cfg.TargetAddr,
			Status:      status,
			BytesSent:   l.bytesSent.Load(),
			BytesRecv:   l.bytesRecv.Load(),
			ActiveConns: int(l.activeConns.Load()),
		})
	}
	return result
}

// StopAll stops all links
func (f *Forwarder) StopAll() {
	f.mu.Lock()
	links := make([]*link, 0, len(f.links))
	for _, l := range f.links {
		links = append(links, l)
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

func (l *link) stop() {
	close(l.done)
	if l.listener != nil {
		l.listener.Close()
	}
	if l.udpConn != nil {
		l.udpConn.Close()
	}
	l.wg.Wait()
}

// --- TCP forwarding ---

func (l *link) tcpAcceptLoop() {
	defer l.wg.Done()
	for {
		conn, err := l.listener.Accept()
		if err != nil {
			select {
			case <-l.done:
				return
			default:
				continue
			}
		}
		l.wg.Add(1)
		go l.tcpHandleConn(conn)
	}
}

func (l *link) tcpHandleConn(client net.Conn) {
	defer l.wg.Done()
	defer client.Close()

	l.activeConns.Add(1)
	defer l.activeConns.Add(-1)

	// Connect to target (flight controller)
	target, err := net.DialTimeout("tcp", l.cfg.TargetAddr, 10*time.Second)
	if err != nil {
		return
	}
	defer target.Close()

	// Bidirectional copy
	done := make(chan struct{}, 2)

	go func() {
		n, _ := io.Copy(target, client)
		l.bytesSent.Add(uint64(n))
		done <- struct{}{}
	}()

	go func() {
		n, _ := io.Copy(client, target)
		l.bytesRecv.Add(uint64(n))
		done <- struct{}{}
	}()

	select {
	case <-done:
	case <-l.done:
	}
}

// --- UDP forwarding ---

func (l *link) udpForwardLoop() {
	defer l.wg.Done()

	// Connect to target for sending
	targetAddr, err := net.ResolveUDPAddr("udp4", l.cfg.TargetAddr)
	if err != nil {
		return
	}
	targetConn, err := net.DialUDP("udp4", nil, targetAddr)
	if err != nil {
		return
	}
	defer targetConn.Close()

	// Track the GCS client address for return traffic
	var clientAddr *net.UDPAddr
	var clientMu sync.Mutex

	// Read from target (FC responses), forward to GCS
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
					continue
				}
			}
			clientMu.Lock()
			ca := clientAddr
			clientMu.Unlock()
			if ca != nil {
				l.udpConn.WriteToUDP(buf[:n], ca)
				l.bytesRecv.Add(uint64(n))
			}
		}
	}()

	// Read from GCS, forward to target (FC)
	buf := make([]byte, 65535)
	for {
		select {
		case <-l.done:
			return
		default:
		}
		n, addr, err := l.udpConn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-l.done:
				return
			default:
				continue
			}
		}
		clientMu.Lock()
		if clientAddr == nil {
			l.activeConns.Add(1)
		}
		clientAddr = addr
		clientMu.Unlock()

		targetConn.Write(buf[:n])
		l.bytesSent.Add(uint64(n))
	}
}
```

Add `"time"` to the imports in forwarder.go.

- [ ] **Step 4: Run tests**

Run: `go test -v -race -run 'TestForwarder' ./internal/mavlink/`
Expected: All PASS

- [ ] **Step 5: Commit**

```bash
git add internal/mavlink/forwarder.go internal/mavlink/forwarder_test.go
git commit -m "mavlink: add TCP/UDP port forwarder with named links"
```

---

## Task 2: GUI MAVLink panel + API

Add API endpoints to create/remove/list links and a UI panel to manage them.

**Files:**
- Modify: `internal/gui/api.go`
- Modify: `internal/gui/server.go`
- Modify: `internal/gui/web/index.html`

- [ ] **Step 1: Add MAVLink API endpoints to api.go**

Add to `API` struct:
```go
	mavlinkLinks []map[string]interface{}
```

Initialize in `NewAPI`:
```go
	mavlinkLinks: make([]map[string]interface{}, 0),
```

Add cases in `ServeHTTP` switch:
```go
	case path == "/mavlink/links" && r.Method == "GET":
		a.handleGetMAVLinkLinks(w, r)
	case path == "/mavlink/links" && r.Method == "POST":
		a.handleCreateMAVLinkLink(w, r)
	case path == "/mavlink/links" && r.Method == "DELETE":
		a.handleDeleteMAVLinkLink(w, r)
```

Add handlers:
```go
func (a *API) handleGetMAVLinkLinks(w http.ResponseWriter, r *http.Request) {
	a.mu.RLock()
	links := a.mavlinkLinks
	a.mu.RUnlock()
	a.writeJSON(w, links)
}

func (a *API) handleCreateMAVLinkLink(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name       string `json:"name"`
		Protocol   string `json:"protocol"`
		ListenAddr string `json:"listen_addr"`
		TargetAddr string `json:"target_addr"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	if req.Name == "" || req.TargetAddr == "" {
		a.writeError(w, http.StatusBadRequest, "name and target_addr required")
		return
	}
	if req.Protocol == "" {
		req.Protocol = "tcp"
	}
	if req.ListenAddr == "" {
		req.ListenAddr = "0.0.0.0:0"
	}

	if a.server.onMAVLinkCreate != nil {
		if err := a.server.onMAVLinkCreate(req.Name, req.Protocol, req.ListenAddr, req.TargetAddr); err != nil {
			a.writeError(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	a.writeJSON(w, map[string]string{"status": "created"})
}

func (a *API) handleDeleteMAVLinkLink(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	if name == "" {
		a.writeError(w, http.StatusBadRequest, "name required")
		return
	}
	if a.server.onMAVLinkDelete != nil {
		if err := a.server.onMAVLinkDelete(name); err != nil {
			a.writeError(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	a.writeJSON(w, map[string]string{"status": "removed"})
}

func (a *API) SetMAVLinkLinks(links []map[string]interface{}) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.mavlinkLinks = links
}
```

- [ ] **Step 2: Add MAVLink callbacks to server.go**

Add to `Server` struct:
```go
	onMAVLinkCreate func(name, protocol, listen, target string) error
	onMAVLinkDelete func(name string) error
```

Add methods:
```go
func (s *Server) SetMAVLinkHandlers(
	onCreate func(name, protocol, listen, target string) error,
	onDelete func(name string) error,
) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.onMAVLinkCreate = onCreate
	s.onMAVLinkDelete = onDelete
}

func (s *Server) BroadcastMAVLinkLinks(links interface{}) {
	s.Broadcast("mavlink_links", links)
}
```

- [ ] **Step 3: Add MAVLink panel to index.html**

Add after the chat card, before `<div class="actions">`:

```html
<div class="card" style="margin-top: 20px;">
    <h2>MAVLink Links</h2>
    <div id="mavlink-links" style="margin-bottom: 12px;"></div>
    <details style="margin-top: 8px;">
        <summary style="cursor: pointer; color: #3b82f6; font-size: 13px;">+ New Link</summary>
        <div style="margin-top: 10px; display: flex; flex-direction: column; gap: 8px;">
            <input type="text" id="mav-name" placeholder="Link name (e.g. gcs-to-drone1)" style="padding: 8px; background: #0a0a0a; border: 1px solid #333; border-radius: 4px; color: #e0e0e0; font-size: 13px;">
            <select id="mav-proto" style="padding: 8px; background: #0a0a0a; border: 1px solid #333; border-radius: 4px; color: #e0e0e0; font-size: 13px;">
                <option value="tcp">TCP</option>
                <option value="udp">UDP</option>
            </select>
            <input type="text" id="mav-listen" placeholder="Listen (e.g. 0.0.0.0:14550)" value="0.0.0.0:14550" style="padding: 8px; background: #0a0a0a; border: 1px solid #333; border-radius: 4px; color: #e0e0e0; font-size: 13px;">
            <input type="text" id="mav-target" placeholder="Target FC (e.g. 10.99.0.2:5760)" style="padding: 8px; background: #0a0a0a; border: 1px solid #333; border-radius: 4px; color: #e0e0e0; font-size: 13px;">
            <button class="btn btn-primary" onclick="createMAVLink()" style="font-size: 13px;">Create Link</button>
        </div>
    </details>
</div>
```

Add JS functions:

```javascript
function updateMAVLinkLinks(links) {
    const el = document.getElementById('mavlink-links');
    if (!links || links.length === 0) {
        el.innerHTML = '<div style="color: #666; font-size: 13px; padding: 8px;">No active links</div>';
        return;
    }
    el.innerHTML = links.map(l => `
        <div style="display:flex;justify-content:space-between;align-items:center;padding:8px;background:#0a0a0a;border-radius:4px;margin-bottom:4px;font-size:13px;">
            <div>
                <span style="color:#fff;font-weight:500;">${l.name}</span>
                <span style="color:#666;margin-left:8px;">${l.protocol.toUpperCase()}</span>
                <span style="color:#888;margin-left:8px;">${l.listen_addr} → ${l.target_addr}</span>
            </div>
            <div style="display:flex;align-items:center;gap:12px;">
                <span style="color:${l.status==='connected'?'#4ade80':'#888'};font-size:12px;">${l.status}</span>
                <span style="color:#666;font-size:12px;">${formatBytes(l.bytes_sent||0)}↑ ${formatBytes(l.bytes_recv||0)}↓</span>
                <button onclick="deleteMAVLink('${l.name}')" style="background:none;border:none;color:#f87171;cursor:pointer;font-size:12px;">✕</button>
            </div>
        </div>
    `).join('');
}

async function createMAVLink() {
    const name = document.getElementById('mav-name').value.trim();
    const proto = document.getElementById('mav-proto').value;
    const listen = document.getElementById('mav-listen').value.trim();
    const target = document.getElementById('mav-target').value.trim();
    if (!name || !target) { showError('Name and target required'); return; }
    try {
        const res = await fetch('/api/mavlink/links?token=' + token, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({name, protocol: proto, listen_addr: listen, target_addr: target})
        });
        if (!res.ok) { const e = await res.json(); showError(e.error || 'Failed'); return; }
        document.getElementById('mav-name').value = '';
        document.getElementById('mav-target').value = '';
        fetchMAVLinkLinks();
    } catch (e) { showError(e.message); }
}

async function deleteMAVLink(name) {
    try {
        await fetch('/api/mavlink/links?token=' + token + '&name=' + name, {method: 'DELETE'});
        fetchMAVLinkLinks();
    } catch (e) { showError(e.message); }
}

async function fetchMAVLinkLinks() {
    try {
        const res = await fetch('/api/mavlink/links?token=' + token);
        if (res.ok) updateMAVLinkLinks(await res.json());
    } catch (e) {}
}
```

Add to WebSocket handler:
```javascript
if (msg.type === 'mavlink_links') updateMAVLinkLinks(msg.data);
```

Add to initial fetch:
```javascript
fetchMAVLinkLinks();
```

Add to periodic refresh:
```javascript
setInterval(fetchMAVLinkLinks, 3000);
```

- [ ] **Step 4: Run GUI tests**

Run: `go test -race ./internal/gui/`
Expected: All pass

- [ ] **Step 5: Commit**

```bash
git add internal/gui/
git commit -m "gui: add MAVLink link management panel with create/remove/monitor"
```

---

## Task 3: Wire forwarder into daemon

Replace the old broadcast proxy with the new forwarder. Connect GUI callbacks.

**Files:**
- Modify: `internal/cli/up.go`

- [ ] **Step 1: Replace proxy with forwarder in up.go**

Replace the old MAVLink proxy block with:

```go
	// Initialize MAVLink forwarder
	mavForwarder := mavlink.NewForwarder()
	mavForwarder.OnChange = func(links []mavlink.LinkInfo) {
		if guiServer != nil {
			// Convert to generic maps for JSON
			var jsonLinks []map[string]interface{}
			for _, l := range links {
				jsonLinks = append(jsonLinks, map[string]interface{}{
					"name": l.Name, "protocol": l.Protocol,
					"listen_addr": l.ListenAddr, "target_addr": l.TargetAddr,
					"status": l.Status, "bytes_sent": l.BytesSent,
					"bytes_recv": l.BytesRecv, "active_conns": l.ActiveConns,
				})
			}
			guiServer.BroadcastMAVLinkLinks(jsonLinks)
		}
	}
	defer mavForwarder.StopAll()

	if guiServer != nil {
		guiServer.SetMAVLinkHandlers(
			func(name, protocol, listen, target string) error {
				return mavForwarder.CreateLink(mavlink.LinkConfig{
					Name: name, Protocol: protocol,
					ListenAddr: listen, TargetAddr: target,
				})
			},
			func(name string) error {
				return mavForwarder.RemoveLink(name)
			},
		)
	}
	fmt.Println("  MAVLink forwarder initialized")
```

Remove the old `mavProxy` code and the gossip `AddTarget` call.

- [ ] **Step 2: Build and test**

Run: `go build ./... && go vet ./... && go test -race -count=1 -timeout 300s ./...`
Expected: All pass

- [ ] **Step 3: Commit**

```bash
git add internal/cli/up.go
git commit -m "daemon: wire MAVLink forwarder with GUI management"
```

---

## Task 4: Docker integration test

Verify TCP forwarding through the mesh — GCS on admin connects to FC on relay.

**Files:**
- Modify: `testdata/mesh-test/run-mesh-test.sh` (optional — manual test below)

- [ ] **Step 1: Manual test in Docker**

```bash
# Rebuild
docker compose -f docker-compose.test.yml down -v
docker compose -f docker-compose.test.yml build --quiet
bash testdata/mesh-test/run-mesh-test.sh

# Start a fake FC on relay (TCP echo server on port 5760)
docker exec -d gw-relay socat TCP-LISTEN:5760,reuseaddr,fork EXEC:"echo FC-REPLY"

# Create a MAVLink link via admin's GUI API
ADMIN_TOKEN=$(docker exec gw-admin cat /var/log/ghostwire/daemon.log | grep -oE 'token=[a-f0-9]+' | head -1 | cut -d= -f2)
curl -s -X POST "http://localhost:9901/api/mavlink/links?token=$ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"name":"gcs-to-relay-fc","protocol":"tcp","listen_addr":"0.0.0.0:14550","target_addr":"10.99.0.2:5760"}'

# List links
curl -s "http://localhost:9901/api/mavlink/links?token=$ADMIN_TOKEN"

# Connect as GCS through the mesh tunnel
docker exec gw-admin sh -c 'echo HELLO | socat -T 3 - TCP:127.0.0.1:14550'
# Expected: FC-REPLY
```

- [ ] **Step 2: Commit**

```bash
git add -A
git commit -m "test: MAVLink TCP forwarding through mesh"
```

---

## Self-Review

**Spec coverage:**
- TCP forwarding: ✓ (Task 1 — `tcpHandleConn` with bidirectional io.Copy)
- UDP forwarding: ✓ (Task 1 — `udpForwardLoop` with client tracking)
- Configurable via UI: ✓ (Task 2 — create/remove/monitor panel)
- Named links: ✓ (Task 1 — `LinkConfig.Name`)
- Protocol selection: ✓ (Task 2 — dropdown in UI)
- Runtime add/remove: ✓ (Task 1 — `CreateLink`/`RemoveLink`)
- Stats (bytes sent/recv): ✓ (Task 1 — `LinkInfo`)
- Wired into daemon: ✓ (Task 3)

**Placeholder scan:** None found.

**Type consistency:**
- `LinkConfig` — used in Task 1 (definition), Task 2 (API creates it), Task 3 (daemon wiring)
- `LinkInfo` — used in Task 1 (definition), Task 2 (API returns it), Task 3 (GUI broadcast)
- `Forwarder.CreateLink` / `RemoveLink` / `List` / `StopAll` — consistent across all tasks
- `onMAVLinkCreate` / `onMAVLinkDelete` — defined Task 2, called Task 3
- `SetMAVLinkHandlers` — defined Task 2, called Task 3
- `BroadcastMAVLinkLinks` — defined Task 2, called Task 3

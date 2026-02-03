# ghostwire

Mesh VPN with traffic obfuscation for environments where VPN traffic is blocked or monitored. Designed for small teams (2-50 nodes) operating in censored or surveilled networks.

## What it does

ghostwire creates encrypted tunnels between nodes using WireGuard, then wraps that traffic to look like normal HTTPS, QUIC, or DNS requests. The goal is to maintain connectivity when adversaries are actively blocking or fingerprinting VPN protocols.

Each node gets short-lived X.509 certificates (24 hours) so there's no revocation infrastructure to maintain. Nodes discover each other via SWIM gossip protocol and automatically find routes, including through NAT and via relay nodes when direct connections fail.

## Building

Requires Go 1.22 or later.

```bash
make build
```

Cross-compilation:

```bash
make build-linux
make build-darwin
make build-windows
```

## Usage

### Creating a new mesh

The first node becomes the admin and holds the CA private key:

```bash
./ghostwire init --mesh-name myteam --server-name vpn.example.com
```

You'll set a passphrase. This creates:
- `~/.config/gw/admin.enc` - Encrypted admin config containing the CA key
- `~/.config/gw/ca.crt` - CA certificate to distribute to other nodes

### Adding nodes

Create enrollment tokens on the admin node:

```bash
# Single-use token, expires in 1 hour
./ghostwire enroll create --role operator --expires 1h

# Multi-use token for provisioning multiple nodes
./ghostwire enroll create --role operator --uses 10 --expires 24h

# List active tokens
./ghostwire enroll list

# Revoke by ID prefix
./ghostwire enroll revoke abc123
```

On the new node:

```bash
./ghostwire join --token gw_enroll_... --endpoint vpn.example.com:443
```

### Running

```bash
# Foreground (see logs directly)
./ghostwire up -f

# Background
./ghostwire up

# Check status
./ghostwire status
./ghostwire status --json

# Stop
./ghostwire down
```

### Emergency wipe

Securely deletes all ghostwire config and keys:

```bash
./ghostwire panic --wipe-all --force
```

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│  CLI (cobra)                                                        │
│    init | join | up | down | status | panic | enroll | gui | logs   │
├─────────────────────────────────────────────────────────────────────┤
│  GUI                          │  Hardening                          │
│    Web dashboard (localhost)  │    Encrypted logging (age)          │
│    REST API + WebSocket       │    Memory compartments (mlock)      │
│    Real-time status/peers     │    Canary tokens (tripwire/dead sw) │
│                               │    Remote attestation               │
├───────────────────────────────┼─────────────────────────────────────┤
│  Mesh Layer                                                         │
│    SWIM gossip, route table, NAT traversal, policy engine (CEL),    │
│    certificate renewal                                              │
├─────────────────────────────────────────────────────────────────────┤
│  Obfuscation Layer                                                  │
│    Packet padding, timing jitter, decoy traffic, TLS fingerprint    │
│    mimicry (utls), probe resistance, cover site                     │
├───────────────────────────────┬─────────────────────────────────────┤
│  Transport                    │  Tunnel                             │
│    HTTPS-mimic (default)      │    WireGuard (wireguard-go)         │
│    QUIC/HTTP3                 │    TUN device                       │
│    Domain fronting            │    Custom conn.Bind                 │
│    DNS-over-HTTPS tunnel      │                                     │
│    Direct UDP                 │                                     │
├───────────────────────────────┼─────────────────────────────────────┤
│  Config                       │  PKI + Crypto                       │
│    age + scrypt encryption    │    X.509 with custom extensions     │
│    No identifiable headers    │    Ed25519 signing                  │
│                               │    X25519 + Kyber-768 (hybrid PQC)  │
│                               │    24-hour certificate lifetime     │
└───────────────────────────────┴─────────────────────────────────────┘
```

---

## Mesh networking

The mesh uses SWIM (Scalable Weakly-consistent Infection-style Membership) for peer discovery and state synchronization. Each node maintains a member list with state tracked as alive, suspect, dead, or left.

### Gossip protocol

Three loops run concurrently:

**Probe loop** (500ms interval): Selects a random alive member, sends a direct ping with piggybacked state updates. On timeout, initiates indirect probes through 3 random peers. RTT measurements stored per member.

**Gossip loop** (1s interval): Sends a digest (SHA-256 of all member incarnations) to a random peer. If digests differ, the peer requests a full sync. This achieves eventual consistency.

**Receive loop**: Listens on UDP 7946, validates HMAC-SHA256 (truncated to 16 bytes) using the mesh secret, checks timestamp freshness (±30 seconds), merges updates based on incarnation number.

### Failure detection

When a direct probe times out, the node is marked suspect and a 5-second timer starts. If indirect probes from 3 helpers succeed, suspicion clears. If the timer expires, the node is marked dead and that state propagates via gossip.

### State merge

Conflicts resolve by incarnation number. Higher incarnation wins. On tie, state priority applies: dead > suspect > alive (conservative assumption).

### Message authentication

All gossip messages include:
- 8-byte timestamp (unix seconds)
- 16-byte HMAC-SHA256 tag derived from mesh secret
- Incarnation for conflict resolution

Messages outside the ±30 second window are dropped.

---

## Transport layer

All transports implement a common interface:

```go
type Transport interface {
    Dial(ctx, addr string) (net.Conn, error)
    Listen(ctx, addr string) (Listener, error)
    Close() error
}
```

### HTTPS-mimic (default)

Wraps WireGuard packets in TLS connections that look like browser HTTPS traffic.

**Knock sequence**: Before sending tunnel data, the client must authenticate using a knock derived via HKDF-SHA256 from the mesh secret. The derivation uses the client's public key and a time window as info, producing 64 bytes:

- Bytes 0-15: Embedded in URL path
- Bytes 16-31: X-Request-ID header
- Bytes 32-47: X-Client-Token header
- Bytes 48-63: Reserved

The request looks like telemetry:

```
POST /api/v1/telemetry/{path_knock} HTTP/1.1
Host: vpn.example.com
X-Request-ID: {request_id}
X-Client-Token: {client_token}
X-Timestamp: {milliseconds}
Content-Type: application/json

{"session_id":"...","event_count":1,"client_time":...}
```

Time windows allow ±1 period of clock skew. Validation uses constant-time comparison.

**TLS fingerprinting**: Uses utls to mimic real browser ClientHello messages. Supported profiles: Chrome, Firefox, Safari, Edge, iOS, Android. Each profile has corresponding HTTP/2 settings:

| Profile | MAX_CONCURRENT_STREAMS | INITIAL_WINDOW_SIZE | HEADER_TABLE_SIZE |
|---------|------------------------|---------------------|-------------------|
| Chrome | 1000 | 6291456 | 65536 |
| Firefox | 100 | 65535 | 65536 |
| Safari | 100 | 2097152 | 4096 |

Header order also varies by profile to match real browser behavior.

**Frame protocol**: Tunnel data uses a simple framing layer:

```
[Type:1][Flags:1][Length:2][Payload][Padding]
```

Types: 0x01 data, 0x02 keepalive, 0x03 config update, 0x04 close. Keepalives sent every 30 seconds.

**Cover site**: Unauthenticated connections receive a generic HTTP response ("This server is functioning normally") and disconnect. This defeats passive enumeration.

### QUIC

Uses HTTP/3 framing over QUIC. Benefits: connection migration (survives IP changes), 0-RTT resumption, stream multiplexing. Drawback: some networks block UDP/443.

### Domain fronting

The outer TLS SNI points to an allowed CDN domain (e.g., allowed.cdn.com) while the inner HTTP Host header points to the actual relay. Works when the CDN doesn't validate Host against SNI. Increasingly blocked by CDN providers.

### DNS tunnel

Encodes data in DNS queries to a controlled nameserver. Throughput around 50-100 bps. Only useful for control plane messages when all other transports fail. Uses DNS-over-HTTPS for the outer layer.

### Direct UDP

Standard WireGuard UDP. Lowest latency but trivially identifiable as VPN traffic by packet sizes and timing patterns.

---

## PKI system

### Certificate authority

Admin nodes generate an Ed25519 keypair and create a self-signed CA certificate (2-year validity). The mesh ID is SHA-256 of the CA public key. Non-admin nodes only have the CA public certificate for verification.

### Node certificates

Certificates are X.509 with 24-hour validity. Fields:

- Serial: 128-bit random
- Subject CN: node ID
- IPAddresses: mesh IP
- Extended Key Usage: ClientAuth, ServerAuth

Custom extensions (private OID arc 1.3.6.1.4.1.99999.1.x):

| OID suffix | Name | Critical | Content |
|------------|------|----------|---------|
| 1 | NodeID | No | String identifier |
| 2 | Roles | Yes | String array |
| 3 | AllowedNetworks | Yes | CIDR + direction (egress/ingress/both) |
| 4 | MeshID | Yes | 32-byte CA pubkey hash |
| 5 | Compartment | No | Isolation group string |
| 6 | WGPubKey | No | 32-byte X25519 key |

Critical extensions must be understood or the certificate is rejected.

### Certificate renewal

A background service checks certificate expiry every hour. When less than 6 hours remain, it sends a renewal request:

```json
{
  "node_id": "node-5",
  "current_cert_hash": "base64(SHA256(cert)[:32])",
  "public_key": "base64(ed25519_pub)",
  "timestamp": 1234567890,
  "signature": "base64(sign(node_id:cert_hash:timestamp))"
}
```

The signature prevents replay. Admin node verifies and issues a new certificate. Retry uses exponential backoff: 1, 2, 4, 8, 16 minutes. After 5 failures, a callback fires but the node continues with the old certificate.

---

## WireGuard integration

### Device setup

The tunnel layer wraps wireguard-go. Configuration via IPC:

```
private_key={hex}
listen_port={port}
public_key={peer_hex}
allowed_ips={mesh_ip}/32
endpoint={host}:{port}
persistent_keepalive_interval={seconds}
```

TUN device created via platform-specific code (netlink on Linux, ifconfig on macOS, netsh on Windows). MTU set to 1420 to account for WireGuard overhead.

### Custom Bind

WireGuard normally binds directly to UDP sockets. ghostwire implements `conn.Bind` to route packets through the obfuscation layer instead.

`HTTPSBind` maintains a map of remote connections. On send, it looks up or creates a connection to the destination, frames the packet, and writes to the TLS stream. A receive loop per connection reads incoming frames and queues them on a channel for WireGuard to consume.

`HybridBind` supports mixed transports. Endpoints formatted as `https://host:port` route through HTTPS; plain `host:port` uses direct UDP.

### Peer management

Peers added/removed via IPC commands. The peer struct tracks:

```go
type Peer struct {
    NodeID              string
    PublicKey           [32]byte  // X25519
    MeshIP              netip.Addr
    Endpoint            *net.UDPAddr
    PersistentKeepalive time.Duration
}
```

Endpoint updates happen when NAT traversal discovers a new address or gossip reports a change.

---

## Obfuscation

### Packet padding

Packets are padded to match common HTTPS response sizes: 64, 128, 256, 512, 1024, 1460, 2048, 4096, 8192, 16384 bytes. Format:

```
[Length:2][Data][RandomPadding]
```

Receiver reads length, extracts data, discards padding. Padding is random bytes (not zeros) to increase entropy.

### Timing jitter

Adds random delay before sending packets. Default: 0-50ms with exponential distribution (many small delays, fewer large ones). Optional burst mode sends N packets immediately then pauses, mimicking browser page loads.

### Decoy traffic

Optional background goroutine generates fake packets during idle periods. Sends 64-1460 byte packets every 1-5 seconds. Decoys marked with 0x00 first byte; real data starting with 0x00 is escaped with 0x01 prefix. Receiver discards decoys.

### TLS fingerprint validation

`FingerprintConn` wrapper stores the browser profile used and can compute a JA3-style fingerprint. `ValidateFingerprint()` checks TLS version >= 1.2 and rejects suspicious cipher combinations.

---

## Policy engine

Policies are YAML with CEL (Common Expression Language) conditions:

```yaml
policies:
  - name: "operators-mesh-access"
    priority: 50
    subjects:
      roles: ["operator"]
    resources:
      nodes: ["*"]
      protocols: ["tcp", "udp"]
    condition: |
      dest_roles.exists(r, r == "operator" || r == "relay")
    effect: allow

  - name: "default-deny"
    priority: 0
    subjects:
      roles: ["*"]
    resources:
      nodes: ["*"]
    effect: deny
```

Rules sorted by priority descending. First match wins.

### Evaluation

CEL expressions have access to:

```
source_node_id, source_roles, source_ip
dest_node_id, dest_roles, dest_ip, dest_port
protocol, direction
metadata (arbitrary key-value)
```

### Packet enforcement

The enforcer parses IP headers, extracts addresses/ports/protocol, looks up peer info from cache, builds a request struct, evaluates against compiled CEL programs, returns allow/deny.

Connection tracking remembers established flows (5-minute TTL). Reverse direction automatically allowed for established connections.

---

## NAT traversal

### Detection

Sends STUN binding requests to multiple servers (Google, OpenStack). Parses XOR-MAPPED-ADDRESS to get external address. If responses from different servers show different ports, NAT is symmetric (hardest case).

Classification:
- NATNone: External matches local (public IP)
- NATFull: Consistent external address across servers
- NATRestricted: Address-restricted cone
- NATPort: Port-restricted cone
- NATSymmetric: Different port per destination

### Hole punching

When node A wants to reach node B through NAT:

1. A sends coordination request to a relay with both nodes' public addresses
2. Relay forwards to B
3. Both A and B send 5 UDP packets to each other's address at 50ms intervals
4. When a packet arrives, the return path is open
5. Direct connection established, relay no longer needed

Frame types: 0x01 coordination request, 0x02 punch packet, 0x03 ACK.

Timeout: 5 seconds. If hole punch fails, traffic routes through relay.

---

## Config encryption

Uses age encryption with scrypt key derivation:

- Scrypt parameters: N=2^18, r=8, p=1 (~1 second on modern hardware)
- Encryption: ChaCha20-Poly1305

The encrypted blob has no magic bytes or headers that identify it as ghostwire config. This provides plausible deniability if the config file is discovered.

Config locations:

```
~/.config/gw/
├── admin.enc      # Admin config with CA private key
├── config.enc     # Node config with node private key
├── ca.crt         # CA certificate (plaintext, shareable)
└── logs/          # Optional encrypted logs
```

---

## Encrypted logging

Logs use age encryption with per-field sensitivity levels. Sensitive fields (IPs, node IDs, keys) are encrypted while metadata (timestamps, levels) remain searchable.

### Log entry structure

```go
type Entry struct {
    Time      time.Time
    Level     Level        // Debug, Info, Warn, Error, Security
    Message   string
    Fields    map[string]interface{}
    Sensitive *SensitiveFields  // Encrypted separately
}
```

Sensitive fields encrypted with a log-specific age recipient. The private key stored separately (or derived from passphrase) allows decryption only when explicitly needed.

### Rotation

Logs rotate by size (default 10MB) and age (default 24 hours). Old logs compressed with gzip. Secure deletion overwrites files with random data before unlinking.

### Reading logs

```bash
./ghostwire logs view --key ~/.config/gw/log.key
./ghostwire logs search --pattern "error" --since 1h
./ghostwire logs export --format json --output events.json
```

---

## Memory compartmentalization

Sensitive data (private keys, session secrets, tokens) stored in isolated memory regions with mlock to prevent swapping to disk.

### Compartments

| Name | Contents | Size limit |
|------|----------|------------|
| ca-keys | CA private key | 4KB |
| node-keys | Node Ed25519/X25519 keys | 4KB |
| session-keys | Ephemeral session secrets | 64KB |
| tokens | Enrollment tokens, auth tokens | 16KB |
| mesh-secrets | Gossip HMAC keys, mesh secret | 8KB |

### Protection

Each region:
1. Allocated with guard pages (PROT_NONE) on both sides to catch overflows
2. Locked in memory via mlock() (Unix) or VirtualLock() (Windows)
3. Zeroed on deallocation before munlock
4. Access tracked per-compartment with usage limits

```go
region, err := secure.Allocate("node-keys", 64)
defer region.Free()  // Zeros and unlocks
copy(region.Data(), privateKey)
```

The manager tracks total mlocked memory against system limits (typically 64KB unprivileged on Linux).

---

## Canary tokens

Canaries detect compromise through three mechanisms:

### Dead switch

Requires periodic check-in. If check-in stops, an alert fires.

```go
canary := &Canary{
    Type:     TypeDeadSwitch,
    Interval: 1 * time.Hour,
    Secret:   []byte("..."),
}
```

The monitor goroutine expects signed check-ins within the interval. Missed check-in triggers the configured alert handler (webhook, log, custom callback).

### Tripwire

Triggers when accessed. Embed in files, endpoints, or database records that should never be touched.

```go
canary := &Canary{
    Type:   TypeTripwire,
    Secret: []byte("..."),
}
// When accessed:
monitor.Trip(canaryID)
```

### Honeypot

Fake credentials or endpoints that look valuable. Any use indicates attacker access.

### Signing

Canaries are signed with Ed25519. Check-ins must include a valid signature over (canary_id || timestamp) to prevent replay attacks.

---

## Remote attestation

Nodes prove their integrity by signing claims about their binary hash, config hash, and system state.

### Claim structure

```go
type AttestationClaim struct {
    NodeID      string
    BinaryHash  [32]byte   // SHA-256 of executable
    ConfigHash  [32]byte   // SHA-256 of config
    SystemInfo  SystemFingerprint
    Timestamp   time.Time
    Nonce       [16]byte   // From verifier challenge
    Signature   []byte     // Ed25519 over marshaled claim
}
```

SystemFingerprint includes OS, architecture, hostname (hashed), and boot time.

### Verification

The verifier maintains a registry of trusted binary hashes by version:

```go
verifier.AddTrustedHash("abc123...", "v1.2.0")
verifier.AddTrustedHash("def456...", "v1.2.1")
```

Verification checks:
1. Signature valid against node's known public key
2. Nonce matches issued challenge (prevents replay)
3. Timestamp within allowed clock skew (default ±5 minutes)
4. BinaryHash in trusted set
5. Claim not older than MaxAge (default 24 hours)

### X.509 extension

Attestation claims embedded in certificate extensions (OID 1.3.6.1.4.1.99999.1.7). Admin node verifies attestation during enrollment before issuing certificates.

---

## Post-quantum key exchange

Hybrid key exchange combines X25519 (classical) with Kyber-768 (post-quantum) for defense against future quantum computers.

### Hybrid keypair

```go
type KeyPair struct {
    X25519Public   [32]byte
    X25519Private  [32]byte
    KyberPublic    []byte  // 1184 bytes
    KyberPrivate   []byte  // 2400 bytes
}
```

### Key encapsulation

Sender side:
```go
shared, encap, err := pqc.Encapsulate(recipientPubKey)
// encap.X25519 = 32 bytes (ephemeral public key)
// encap.Kyber  = 1088 bytes (ciphertext)
// shared.Key   = 64 bytes (combined secret)
```

Receiver side:
```go
shared, err := keyPair.Decapsulate(encap)
```

### Combined secret derivation

```
X25519_SS = X25519(ephemeral_private, recipient_public)
Kyber_SS  = Kyber.Decapsulate(ciphertext, recipient_private)
Combined  = SHA-512(X25519_SS || Kyber_SS)
```

The 64-byte combined secret provides 256 bits of classical security and 128+ bits of post-quantum security. An attacker must break both algorithms to recover the secret.

### Transport integration

Hybrid keys used during handshake to derive session keys. The resulting shared secret fed into HKDF to produce:
- Encryption key (32 bytes, ChaCha20-Poly1305)
- MAC key (32 bytes)
- IV (12 bytes)

---

## Web GUI

Browser-based management interface running on localhost with token authentication.

### Starting

```bash
./ghostwire up --gui
# or standalone:
./ghostwire gui --listen 127.0.0.1:9999
```

Opens browser automatically with auth token in URL: `http://127.0.0.1:9999/?token=abc123...`

### API endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| /api/status | GET | Mesh status (connected, node ID, uptime, traffic) |
| /api/peers | GET | List of peers with IPs, endpoints, latency |
| /api/connect | POST | Connect to mesh with passphrase |
| /api/disconnect | POST | Disconnect from mesh |
| /api/stats | GET | Traffic statistics |

All endpoints require `?token=...` query param or `Authorization: Bearer ...` header.

### WebSocket

Real-time updates via `/ws?token=...`:

```json
{"type": "status", "data": {"connected": true, "node_id": "node-1", ...}}
{"type": "peers", "data": [{"node_id": "peer-1", "mesh_ip": "10.100.0.2", ...}]}
```

Client receives updates when status or peer list changes. Ping/pong keepalive every 54 seconds.

### Security

- Token generated randomly (16 bytes hex encoded) at startup
- Listens only on 127.0.0.1 by default
- No CORS (same-origin only)
- WebSocket upgrade requires valid token

---

## Roles

| Role | Purpose |
|------|---------|
| admin | Holds CA key, issues certificates, manages enrollment |
| operator | Standard mesh member with full connectivity |
| relay | Forwards traffic for nodes behind NAT |
| sensor | Egress-only, cannot receive connections |
| service | Receives on specific ports only |

Roles encoded in certificate extensions and enforced by policy engine.

---

## Files

```
~/.config/gw/
├── admin.enc      # Admin config with CA key (encrypted)
├── config.enc     # Node config (encrypted)
├── ca.crt         # CA certificate (distribute to nodes)
├── log.key        # Log decryption key (age private key)
├── canaries.json  # Canary token definitions
├── trusted.json   # Trusted binary hashes for attestation
└── logs/          # Encrypted logs (rotated by size/age)
```

## Requirements

- Go 1.22+ to build
- Root/admin for TUN device creation
- macOS, Linux, or Windows


# ghostwire

Mesh VPN with traffic obfuscation. WireGuard tunnels wrapped in WebSocket-framed HTTPS to evade DPI. SWIM gossip for peer discovery. CEL policy engine. 24-hour auto-rotating certificates.

## Building

Go 1.24+.

```bash
make build          # current platform
make release        # linux/amd64, linux/arm64, darwin/amd64, darwin/arm64, windows/amd64
make test           # tests with race detector
```

## Usage

```bash
# Initialize mesh (generates CA, admin cert, encrypted config)
ghostwire init --mesh-name ops --server-name vpn.example.com --listen :8443

# Create enrollment token
ghostwire enroll create --role operator --expires 1h

# Join from another node
ghostwire join --token gw_enroll_... --endpoint vpn.example.com:8443

# Start daemon (WireGuard tunnel + gossip + transport listener + GUI)
ghostwire up -f

# Emergency wipe (overwrite + rename + delete)
ghostwire panic --wipe-all --force
```

GUI runs on `:9999` with token auth. Printed at startup.

## Architecture

```
CLI
  init | join | up | down | status | panic | enroll
Mesh
  SWIM gossip (UDP 7946, HMAC-SHA256, replay dedup)
  Routing table (direct / relay / multi-hop)
  NAT traversal (STUN + hole punch)
  Policy engine (CEL, default-deny)
  Certificate renewal (nonce-protected)
Transport
  HTTPS-mimic: TLS 1.3 -> HTTP POST knock -> 101 WebSocket upgrade -> binary frames
  QUIC, domain fronting, DNS-over-HTTPS, direct UDP
Tunnel
  WireGuard via wireguard-go
  Custom conn.Bind routes packets through transport layer
  Peers added dynamically via gossip callbacks
Crypto
  Ed25519 signing, X25519 key agreement
  Hybrid X25519 + Kyber-768 (post-quantum)
  age + scrypt config encryption
```

## Transport protocol

Session flow as seen on the wire:

1. TLS 1.3 handshake
2. HTTP POST to `/api/v1/telemetry/{knock}` with HKDF-derived headers
3. Server responds `101 Switching Protocols` (WebSocket upgrade)
4. Client sends 2-byte XOR-masked length key
5. All subsequent data: RFC 6455 binary frames with MASK bit, random padding (4-64 bytes), XOR-masked payload length

Unauthenticated connections get a static HTML page.

Knock derivation: `HKDF-SHA256(mesh_secret, client_pubkey || BigEndian(time_window))` producing 64 bytes split into path, request ID, client token, reserved. One-time use (server-side replay cache with TTL).

## PKI

- CA: Ed25519, 2-year validity. Mesh ID = SHA-256(CA pubkey).
- Node certs: X.509, 24-hour validity, auto-renewed at T-6h.
- Custom extensions (OID 1.3.6.1.4.1.99999.1.x): NodeID, Roles (critical), MeshID (critical), WireGuard pubkey, Compartment, AllowedNetworks.
- Enrollment: token-based over TLS 1.3. CA fingerprint verified against mesh ID in token.
- Renewal: signed request with random nonce. Server verifies against registered public key and deduplicates nonces.

## Key derivation

```
Ed25519 seed (32 bytes)
  -> SHA-512 -> clamp per RFC 7748 -> X25519 private key (32 bytes)
  -> ScalarBaseMult -> X25519 public key (32 bytes)
```

Same key used for WireGuard and knock HKDF info field. Private key and SHA-512 intermediate zeroed after use.

## Gossip

SWIM protocol over UDP port 7946 (`udp4`).

- Probe: 2s interval, random alive member, indirect probes on timeout
- Gossip: 1s interval, digest exchange, delta sync
- HMAC: SHA-256 over all message fields (type, seqno, from, target, members, digest, timestamp), truncated to 16 bytes
- Freshness: 30-second window
- Replay: per-message hash deduplication (bounded LRU, 10k entries)
- Merge: higher incarnation wins, tie-break dead > suspect > alive

## Policy

Default-deny. Rules evaluated by priority (descending), first match wins.

```yaml
- name: operators-mesh-access
  priority: 50
  subjects: { roles: [operator] }
  resources: { nodes: ["*"], protocols: [tcp, udp] }
  condition: 'dest_roles.exists(r, r == "operator" || r == "relay")'
  effect: allow
```

Enforcer parses IPv4 headers, looks up peer by IP, evaluates CEL program. Connection tracking with 5-minute TTL.

## Roles

| Role | Access |
|------|--------|
| admin | Full mesh, CA ops, enrollment |
| relay | Full mesh, forwards for NAT'd nodes |
| operator | Operators, relays, admin |
| sensor | Egress-only to collectors |

## Config

age encryption, scrypt KDF (N=2^18), ChaCha20-Poly1305. No magic bytes.

```
~/.config/gw/
  admin.enc    # admin config + CA key
  config.enc   # node config
  ca.crt       # CA certificate
```

Secure delete: random overwrite, zero overwrite, rename to random filename, unlink. Note: not effective on CoW filesystems (APFS, Btrfs).

## Docker testing

```bash
docker compose -f docker-compose.test.yml build
bash testdata/mesh-test/run-mesh-test.sh
```

3 containers (admin, relay, operator). Tests: init, enroll, join, daemon start, WireGuard tunnel, mesh overlay ping, gossip discovery, network degradation (tc netem), panic wipe. GUI on ports 9901-9903.

## Post-quantum

Hybrid X25519 + Kyber-768. Combined secret: `SHA-512(X25519_SS || Kyber_SS)`. 64-byte output. Both algorithms must be broken to recover the key.

## Requirements

- Go 1.24+
- Root/admin for TUN device
- macOS, Linux, or Windows
- Docker (optional, for integration tests)

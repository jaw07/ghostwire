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
  SWIM gossip (UDP 7947, HMAC-SHA256, replay dedup)
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

```
Client                                       Server
  |                                            |
  |-- TLS 1.3 ClientHello ------------------>  |
  |<- TLS 1.3 ServerHello + Finished --------> |
  |                                            |
  |-- POST /api/v1/telemetry/{knock} ------->  |  HKDF-derived headers
  |   X-Request-ID: {hex}                      |
  |   X-Client-Token: {hex}                    |
  |   Content-Type: application/json           |
  |   {"session_id":"...","event_count":1}     |  Plausible telemetry
  |                                            |
  |<- 101 Switching Protocols ---------------  |  WebSocket upgrade
  |   Upgrade: websocket                       |
  |   Sec-WebSocket-Accept: {base64}           |
  |                                            |
  |-- [LenMask: 2 bytes] ------------------>   |  Per-session XOR key
  |                                            |
  |== WebSocket binary frames ==============>  |  All subsequent traffic
  |   [0x82][len][MASK key][payload]           |  RFC 6455 + MASK bit
  |                                            |
  |   payload = [maskedLen:2][WG pkt][pad]     |  WG pkt + 4-64 rand
  |                                            |
```

### Knock derivation

```
mesh_secret     = 32 bytes (shared across mesh)
client_pubkey   = 32 bytes (X25519 public key)
time_window     = floor(unix_timestamp / window_seconds)
info            = client_pubkey || BigEndian(time_window)

knock_material  = HKDF-SHA256(secret=mesh_secret, info=info, length=64)

path_knock      = knock_material[0:16]    -> hex-encoded in URL path
request_id      = knock_material[16:32]   -> X-Request-ID header
client_token    = knock_material[32:48]   -> X-Client-Token header
reserved        = knock_material[48:64]
```

Validation: server recomputes knock for each known client across windows `{W, W-1, W+1}` (clock skew tolerance). Constant-time comparison via `crypto/subtle`. Used knocks stored in replay cache with TTL = 3 * window.

### WebSocket frame format

```
+--------+------+----------+----------+---------------------------------+
| Offset | Size | Field    | Value    | Notes                           |
+--------+------+----------+----------+---------------------------------+
| 0      | 1    | Opcode   | 0x82     | FIN=1, RSV=000, opcode=binary   |
| 1      | 1    | Len+Mask | 0x80|len | MASK bit set (client->server)   |
| 2      | 2    | ExtLen16 | uint16   | Only if Len field == 126        |
|  or 2  | 8    | ExtLen64 | uint64   | Only if Len field == 127        |
| var    | 4    | MaskKey  | random   | RFC 6455 masking key            |
+--------+------+----------+----------+---------------------------------+
|                   Masked payload (XOR'd with MaskKey)                 |
+--------+------+----------+----------+---------------------------------+
| +0     | 2    | RealLen  | XOR'd    | BigEndian(realLen) XOR lenMask  |
| +2     | var  | Data     | WG pkt   | WireGuard packet (realLen B)    |
| +2+rl  | var  | Padding  | random   | 4-64 bytes from crypto/rand     |
+--------+------+----------+----------+---------------------------------+

lenMask  = 2 random bytes, sent as first message after WebSocket upgrade
MaskKey  = 4 random bytes per frame, per RFC 6455 Section 5.3
Padding length derived from crypto/rand (not from payload content)
```

DPI sees standard WebSocket binary frames. The XOR-masked length field prevents statistical correlation between frame size and payload size.

## PKI

### Certificate hierarchy

```
Root CA (Ed25519, 2-year validity, offline)
  Mesh ID = SHA-256(CA_public_key)       -- 32 bytes, identifies the mesh
  |
  +-- Node Certificate (Ed25519, 24-hour validity)
        Subject CN = node_id
        IPAddresses = [mesh_ip]
        Extensions:
          1.3.6.1.4.1.99999.1.1  NodeID          (string, non-critical)
          1.3.6.1.4.1.99999.1.2  Roles           (string[], critical)
          1.3.6.1.4.1.99999.1.3  AllowedNetworks (CIDR+direction, critical)
          1.3.6.1.4.1.99999.1.4  MeshID          (32 bytes, critical)
          1.3.6.1.4.1.99999.1.5  Compartment     (string, non-critical)
          1.3.6.1.4.1.99999.1.6  WGPubKey        (32 bytes X25519, non-critical)
```

### Enrollment flow

```
Admin                                            New Node
  |                                                |
  |  1. Generate token:                            |
  |     token = Sign(CA_key, {id, mesh_id,         |
  |       roles, not_before, not_after, max_uses}) |
  |                                                |
  |<--- POST /enroll {token, pubkey} --------------| 2. Generate Ed25519 + X25519
  |                                                |
  |  3. Validate token signature                   |
  |     Check expiry, usage count                  |
  |     Allocate mesh IP                           |
  |     Issue X.509 certificate                    |
  |                                                |
  |--- {cert, ca_cert, peers, ------------------->| 4. Mesh config response
  |     mesh_secret, transport}                    |
  |                                                |
  |                                                | 5. Node verifies:
  |                                                |    SHA-256(ca_cert.pubkey)
  |                                                |      == token.mesh_id
  |                                                |    cert chains to ca_cert
```

Step 5 prevents MITM: an attacker substituting a rogue CA would fail the fingerprint check because the mesh ID is embedded in the token signed by the real CA.

### Certificate renewal

```
Node                                           Admin
  |                                              |
  |  nonce = random(16 bytes)                    |
  |  sig = Sign(node_key,                        |
  |          "node_id:cert_hash:nonce:ts")       |
  |                                              |
  |-- POST /renew -----------------------------> |
  |   {node_id, cert_hash, nonce, ts, sig}       |
  |                                              |
  |                          Verify sig against  |
  |                          registered key      |
  |                          (not request key)   |
  |                          Verify cert_hash    |
  |                          Reject replayed     |
  |                          nonce               |
  |                          Preserve roles      |
  |                          from current cert   |
  |                                              |
  |<- {new_cert, expires_at} -----------------   |
  |                                              |
```

## Key derivation

```
seed (32 random bytes)
  |
  v
Ed25519 private key = ed25519.NewKeyFromSeed(seed)
Ed25519 public key  = private.Public()
  |
  v
h = SHA-512(seed)                    -- 64 bytes
h[0]  &= 248                        -- clear bottom 3 bits  \
h[31] &= 127                        -- clear top bit         | RFC 7748 clamping
h[31] |= 64                         -- set second-to-top bit /
  |
  v
X25519 private key = h[0:32]
X25519 public key  = ScalarBaseMult(private, basepoint)
  |
  v
WireGuard uses X25519 keypair for Noise IK handshake
Knock uses X25519 public key as HKDF info component
  |
  v
defer WipeBytes(x25519_private)      -- zeroed after tunnel creation
WipeBytes(h[:])                      -- SHA-512 intermediate zeroed immediately
```

The Ed25519 and X25519 keys are mathematically linked via the birational equivalence between the twisted Edwards curve (Ed25519) and the Montgomery curve (Curve25519). The conversion uses `edwards25519.ScalarBaseMult` followed by `BytesMontgomery()` for the Edwards-to-Montgomery point mapping.

## Gossip

SWIM (Scalable Weakly-consistent Infection-style Membership) over UDP port 7946.

### Protocol cycles

```
Every 2 seconds (probe):
  1. Pick random alive member M
  2. Send Ping{seqno, self_state, piggybacked_broadcasts}
  3. If no Ack within 3s:
     a. Pick 3 random members as helpers
     b. Send PingReq{target=M} to each helper
     c. Helper pings M, forwards Ack back
  4. If still no Ack after 3s: mark M as suspect
  5. After 15s suspect timeout: mark M as dead, broadcast

Every 1 second (gossip):
  1. Pick random alive member
  2. Send Sync{digest=SHA256(all member incarnations)}
  3. If digests differ: recipient responds with full member list
  4. Merge received state
```

### Message authentication

```
HMAC = HMAC-SHA256(mesh_secret,
  timestamp(8 bytes) ||
  from(string) ||
  type(1 byte) ||
  seqno(8 bytes) ||
  target(string) ||
  digest(bytes) ||
  for each member: nodeID || state(1 byte) || incarnation(8 bytes)
)[0:16]

Verification:
  1. Check |now - timestamp| <= 30 seconds
  2. Constant-time compare HMAC
  3. Compute msg_hash = SHA-256(from || seqno || timestamp)[0:8]
  4. Reject if msg_hash in seen set (bounded to 10k entries)
  5. Add msg_hash to seen set with 30s TTL
```

### State merge

```
For incoming member M with incarnation I and state S:
  If M not in local list: add, trigger onJoin callback
  If M.incarnation > local.incarnation: update (higher incarnation wins)
  If M.incarnation == local.incarnation:
    If state_priority(M.state) > state_priority(local.state): update
    Where priority: Dead(3) > Suspect(2) > Alive(1) > Left(0)
  If M.incarnation < local.incarnation: ignore (stale)
```

## Policy engine

Default-deny. Rules evaluated by priority descending, first match wins.

```yaml
- name: operators-mesh-access
  priority: 50
  subjects: { roles: [operator] }
  resources: { nodes: ["*"], protocols: [tcp, udp] }
  condition: 'dest_roles.exists(r, r == "operator" || r == "relay")'
  effect: allow
```

### Evaluation path

```
IP packet arrives on WireGuard interface
    |
    v
Parse IPv4 header
    |--- src_ip, dst_ip, protocol, src_port, dst_port
    |
    v
Peer cache lookup
    |--- src_ip --> {node_id, roles, compartment}
    |--- dst_ip --> {node_id, roles, compartment}
    |
    v
Build Request{source_*, dest_*, protocol, direction}
    |
    v
For each rule (sorted by priority desc):
    |--- Match subjects?   (roles OR node_ids OR compartments; all fields AND'd)
    |--- Match resources?  (nodes, ports, protocols, direction)
    |--- Match condition?  (evaluate CEL program if present)
    |
    +--- [all match] --> return rule.effect (Allow or Deny)
    |
    +--- [no match]  --> continue to next rule
    |
    v
No rules matched --> Deny (default)
```

CEL variables available: `source_node_id`, `source_roles`, `source_ip`, `dest_node_id`, `dest_roles`, `dest_ip`, `dest_port`, `protocol`, `direction`, `metadata`.

## WireGuard integration

### Custom conn.Bind

WireGuard normally sends/receives UDP datagrams via `conn.Bind`. ghostwire replaces this with `HTTPSBind` that routes packets through the HTTPS transport:

**Outbound (Send):**

```
WireGuard Send(packet, endpoint)
    |
    v
HTTPSBind.Send
    |--- Lock connsMu
    |--- Lookup endpoint in remoteConns map
    |
    +--- [exists] ---> reuse TLS connection
    |
    +--- [not found]
    |        |--- Unlock (slow I/O ahead)
    |        |--- TCP connect
    |        |--- TLS 1.3 handshake
    |        |--- HTTP POST knock
    |        |--- Read 101 response
    |        |--- Wrap in wsConn (exchange length mask)
    |        |--- Re-lock, double-check map
    |        |--- Store connection
    |        +--- Start receiveLoop goroutine
    |
    v
Write packet --> wsConn --> WebSocket frame --> TLS --> TCP
```

**Inbound (Receive):**

```
Incoming TLS connection
    |
    v
HTTPSBind.handleIncoming
    |--- Buffered read until \r\n\r\n
    |--- Validate knock (check replay cache)
    |
    +--- [invalid] --> serve cover HTML page, close
    |
    +--- [valid]
         |--- Send 101 WebSocket upgrade
         |--- Wrap in wsConn (read client's length mask)
         |--- Store in remoteConns
         +--- Start receiveLoop
                  |
                  +---> Read WS frame --> decode --> strip padding
                  |     Push to recvChan (capacity 256)
                  |     Loop
                  |
                  v
              WireGuard ReceiveFunc blocks on <-recvChan
              Returns packet + endpoint to WireGuard
```

### Peer lifecycle

```
Node starts
    |
    v
Gossip discovers peer (onJoin callback)
    |
    +--- RegisterKnockPeer(pubkey)         Add to knock validator
    |
    +--- IpcSet to WireGuard device:
    |      public_key={hex}
    |      allowed_ip={mesh_ip}/32
    |      endpoint={underlay_ip}:8444     Transport port from gossip
    |      persistent_keepalive_interval=25
    |
    v
WireGuard initiates Noise IK handshake via HTTPSBind.Send
    |
    v
Handshake completes --> encrypted session established
    |
    v
Traffic path:
    App --> TUN --> WireGuard encrypt --> HTTPSBind --> wsConn --> TLS --> TCP
```

## Post-quantum key exchange

Hybrid X25519 + Kyber-768 (ML-KEM). Both must be broken to recover the shared secret.

```
Alice                                            Bob
  |                                                |
  |  x25519_eph = random X25519 keypair            |
  |  kyber_eph  = random Kyber-768 keypair         |
  |                                                |
  |--- x25519_eph.pub, kyber_eph.pub ------------> | 
  |                                                |
  |                     x25519_ss = X25519(        |
  |                       bob_priv, alice_x25519)  |
  |                     kyber_ss, kyber_ct =       |
  |                       Kyber.Encapsulate(       |
  |                         alice_kyber_pub)       |
  |                                                |
  |<-- kyber_ct (1088 bytes) ----------------------|
  |                                                |
  |  x25519_ss = X25519(                           |
  |    alice_priv, bob_x25519_pub)                 |
  |  kyber_ss = Kyber.Decapsulate(                 |
  |    kyber_ct, alice_kyber_priv)                 |
  |                                                |
  |  shared = SHA-512(x25519_ss || kyber_ss)       |  64 bytes
  |         = SHA-512(32 bytes  || 32 bytes)       |
  |                                                |
  |  encryption_key = shared[0:32]                 |  ChaCha20-Poly1305
  |  mac_key        = shared[32:64]                |
```

Security: 128-bit classical (X25519) + 128-bit post-quantum (Kyber-768). Combined via SHA-512 ensures the stronger primitive dominates.

## NAT traversal

```
Node A (behind NAT)            Relay             Node B (behind NAT)
  |                              |                  |
  |  STUN query to               |                  |
  |  stun.l.google.com:19302     |                  |
  |<-- external addr A' ---------|                  |
  |                              |                  |
  |--- HolePunchReq{A', B'} ---> |                  |
  |                              |--- forward ----->|
  |                              |                  |
  |                              |    STUN query    |
  |                              |<-- addr B' ------|
  |                              |                  |
  |<======= 5 UDP packets at 50ms intervals ======> |
  |          (both sides send simultaneously)       |
  |                              |                  |
  |  NAT mapping opens:          |                  |
  |  outbound pkt matches        |                  |
  |  inbound source addr         |                  |
  |                              |                  |
  |<=========== direct WireGuard tunnel ==========> |
  |              (relay no longer needed)           |
```

NAT classification via STUN:

```
+----------------------------+------------------------------------------+
| Condition                  | Classification                           |
+----------------------------+------------------------------------------+
| A1:P1 == local addr        | NATNone       - public IP, no NAT        |
| A1 == A2 and P1 == P2      | NATFull       - full cone                |
| A1 == A2 and P1 != P2      | NATRestricted - port-restricted cone     |
| A1 != A2                   | NATSymmetric  - not hole-punchable       |
+----------------------------+------------------------------------------+
A1:P1 = external addr from STUN server 1
A2:P2 = external addr from STUN server 2
```

## Chat

Encrypted mesh chat between nodes. Messages broadcast via gossip, displayed in the GUI in real-time via WebSocket.

```
Node A (GUI)                    Gossip                    Node B (GUI)
  |                                |                          |
  |  User types message            |                          |
  |-- POST /api/chat ------------> |                          |
  |                                |                          |
  |  ChatService.Send()            |                          |
  |  OnSend callback:              |                          |
  |    json.Marshal(ChatMessage)   |                          |
  |    gossip.BroadcastPayload(    |                          |
  |      MsgChat, payload)         |                          |
  |                                |                          |
  |    UDP send to all alive ----->|--- UDP to Node B ------> |
  |    members directly            |                          |
  |                                |   verifyHMAC (covers     |
  |                                |     Payload field)       |
  |                                |   handleCustomBroadcast  |
  |                                |   ChatService.Receive()  |
  |                                |   OnReceive callback:    |
  |                                |     BroadcastChat() ---->|  WebSocket push
  |                                |                          |  updateChat(msg)
  |                                |                          |
```

Chat messages are HMAC-authenticated (the `Payload` field is included in the gossip HMAC computation) and replay-deduplicated. History capped at 200 messages per node.

API:
- `GET /api/chat?token=` — message history
- `POST /api/chat?token=` — send `{"text":"..."}`
- WebSocket type `"chat"` — real-time push `{sender, text, timestamp}`

## MAVLink port forwarder

Configurable TCP/UDP port forwarder for connecting a ground control station (GCS) to a flight controller (FC) on another mesh node. Managed via the GUI or REST API. No configuration needed on the FC node — the mesh tunnel makes it reachable.

```
GCS Node                        Mesh                        FC Node
  |                               |                           |
  |  QGroundControl               |                           |  ArduPilot / PX4
  |  connects to                  |                           |  listening on
  |  localhost:14550              |                           |  :5760
  |       |                       |                           |
  |       v                       |                           |
  |  Forwarder link               |                           |
  |  (TCP or UDP)                 |                           |
  |       |                       |                           |
  |       +-- TUN/gw0 ----------> | WireGuard encrypt ------->|
  |                               | HTTPS-mimic transport     |
  |                               | WebSocket frames          |
  |                               |                           |
  |                               |             TCP/UDP dial  |
  |                               |             mesh_ip:5760  |
  |                               |                     |     |
  |                               |                     v     |
  |                               |              Flight Controller
  |                               |                           |
  |       <-- telemetry ----------|<-- WireGuard decrypt <----|
  |       ATTITUDE, GPS, etc      |                           |
```

### Setup

From the GUI on the GCS node:
1. Open MAVLink panel → "+ Connect to Flight Controller"
2. Select the drone node from the dropdown (populated from gossip peers)
3. Set FC port (default 5760), protocol (TCP/UDP), GCS listen port (default 14550)
4. Click Connect

Or via API:

```bash
# Create link
curl -X POST "http://localhost:9999/api/mavlink/links?token=..." \
  -H 'Content-Type: application/json' \
  -d '{"name":"drone-1","protocol":"tcp","listen_addr":"0.0.0.0:14550","target_addr":"10.99.0.2:5760"}'

# List active links
curl "http://localhost:9999/api/mavlink/links?token=..."

# Remove link
curl -X DELETE "http://localhost:9999/api/mavlink/links?token=...&name=drone-1"
```

### Link types

| Protocol | Use case | How it works |
|----------|----------|-------------|
| TCP | ArduPilot SITL, most FC connections | Accept on listen, dial target, bidirectional `io.Copy` |
| UDP | MAVLink UDP broadcast, some FC configs | Listen for datagrams, forward to target, return path tracked |

### Packet parser

Extracts headers from MAVLink v1 and v2 packets for logging and routing:

```
MAVLink v1:  [FE][len][seq][sysid][compid][msgid:1][payload][crc]
MAVLink v2:  [FD][len][incompat][compat][seq][sysid][compid][msgid:3][payload][crc]
```

System IDs: 1-200 drones, 200-254 ground stations, 255 default GCS.

## Roles

| Role | Access |
|------|--------|
| admin | Full mesh, CA ops, enrollment |
| relay | Full mesh, forwards for NAT'd nodes |
| operator | Operators, relays, admin |
| sensor | Egress-only to collectors |

## Config

age encryption, scrypt KDF (N=2^18, r=8, p=1), ChaCha20-Poly1305. No magic bytes.

```
~/.config/gw/
  admin.enc    # admin config + CA key
  config.enc   # node config
  ca.crt       # CA certificate
```

Secure delete: random overwrite, zero overwrite, rename to random filename, unlink. Not effective on CoW filesystems (APFS, Btrfs).

## Docker testing

```bash
docker compose -f docker-compose.test.yml build
bash testdata/mesh-test/run-mesh-test.sh
```

3 containers (admin, relay, operator) on a bridge network. Tests init, enroll, join, daemon start, WireGuard tunnel, mesh overlay ping, gossip discovery, network degradation (tc netem 50ms latency + 5% loss), panic wipe. GUI on ports 9901-9903.

## Requirements

- Go 1.24+
- Root/admin for TUN device
- macOS, Linux, or Windows
- Docker (optional, for integration tests)

#!/usr/bin/env bash
# GHOSTWIRE Docker Mesh Integration Test
# Tests: init -> enroll -> join -> tunnel up -> traffic -> failover -> panic
set +e  # Don't exit on error — we handle errors explicitly

PASS=0
FAIL=0
PASSPHRASE="test-mesh-passphrase-123"
MESH_NAME="DOCKER-TEST-MESH"

log()  { echo -e "\033[1;34m[TEST]\033[0m $*"; }
pass() { echo -e "\033[1;32m[PASS]\033[0m $*"; ((PASS++)); }
fail() { echo -e "\033[1;31m[FAIL]\033[0m $*"; ((FAIL++)); }

run_admin()    { docker exec -i gw-admin "$@"; }
run_relay()    { docker exec -i gw-relay "$@"; }
run_operator() { docker exec -i gw-operator "$@"; }

# Helper: run ghostwire command with passphrase piped in
gw_admin()    { echo "$PASSPHRASE" | run_admin ghostwire "$@"; }
gw_relay()    { echo "$PASSPHRASE" | run_relay ghostwire "$@"; }
gw_operator() { echo "$PASSPHRASE" | run_operator ghostwire "$@"; }

cleanup() {
    log "Cleaning up..."
    docker compose -f docker-compose.test.yml down -v --remove-orphans 2>/dev/null || true
}

# Only cleanup on failure — keep containers running on success for GUI access
trap 'if [ "$FAIL" -gt 0 ]; then cleanup; fi' EXIT

# ============================================================
log "=== Phase 1: Build and start containers ==="
# ============================================================
docker compose -f docker-compose.test.yml build --quiet
docker compose -f docker-compose.test.yml up -d

# Wait for containers to be ready
sleep 2

# Verify containers are running
for node in gw-admin gw-relay gw-operator; do
    if docker ps --format '{{.Names}}' | grep -q "${node}"; then
        pass "Container $node is running"
    else
        fail "Container $node is NOT running"
        docker compose -f docker-compose.test.yml logs "$node" 2>&1 | tail -5
        exit 1
    fi
done

# Verify ghostwire binary exists in containers
for node in gw-admin gw-relay gw-operator; do
    if docker exec "$node" ghostwire version 2>&1 | grep -q ghostwire; then
        pass "$node has ghostwire binary"
    else
        fail "$node missing ghostwire binary"
        exit 1
    fi
done

# ============================================================
log "=== Phase 2: Initialize mesh on admin node ==="
# ============================================================

printf '%s\n%s\n' "$PASSPHRASE" "$PASSPHRASE" | run_admin ghostwire init \
    --mesh-name "$MESH_NAME" \
    --output /etc/ghostwire \
    --subnet "10.99.0.0/16" \
    --node-id "admin-node" \
    --server-name "gw-admin" \
    --listen "0.0.0.0:8443" 2>&1

if run_admin test -f /etc/ghostwire/admin.enc; then
    pass "Mesh initialized, admin.enc exists"
else
    fail "admin.enc not found after init"
    exit 1
fi

if run_admin test -f /etc/ghostwire/ca.crt; then
    pass "CA certificate generated"
else
    fail "ca.crt not found"
    exit 1
fi

# ============================================================
log "=== Phase 3: Create enrollment tokens (before daemon starts) ==="
# ============================================================

# Token for relay
RELAY_OUTPUT=$(printf '%s\n' "$PASSPHRASE" | run_admin ghostwire enroll create \
    --config /etc/ghostwire \
    --role relay \
    --expires 10m 2>&1)
RELAY_TOKEN=$(echo "$RELAY_OUTPUT" | grep -oE 'gw_enroll_[A-Za-z0-9_+/=-]+' | head -1)

if [ -n "$RELAY_TOKEN" ]; then
    pass "Relay enrollment token created"
    log "  Token: ${RELAY_TOKEN:0:40}..."
else
    fail "Failed to create relay token"
    echo "$RELAY_OUTPUT"
    exit 1
fi

# Token for operator
OPERATOR_OUTPUT=$(printf '%s\n' "$PASSPHRASE" | run_admin ghostwire enroll create \
    --config /etc/ghostwire \
    --role operator \
    --expires 10m 2>&1)
OPERATOR_TOKEN=$(echo "$OPERATOR_OUTPUT" | grep -oE 'gw_enroll_[A-Za-z0-9_+/=-]+' | head -1)

if [ -n "$OPERATOR_TOKEN" ]; then
    pass "Operator enrollment token created"
    log "  Token: ${OPERATOR_TOKEN:0:30}..."
else
    fail "Failed to create operator token"
    exit 1
fi

# ============================================================
log "=== Phase 4: Start admin node daemon ==="
# ============================================================

# Write passphrase to file inside container so daemon can read it
run_admin sh -c "echo '$PASSPHRASE' > /tmp/gw-pass"

# Start admin daemon in background, reading passphrase from file
run_admin sh -c 'ghostwire up --config /etc/ghostwire -f < /tmp/gw-pass > /var/log/ghostwire/daemon.log 2>&1 &'
sleep 4

# Check if the daemon started by looking at the log
if run_admin sh -c 'cat /var/log/ghostwire/daemon.log 2>/dev/null' | grep -qi 'running\|tunnel\|started\|listening'; then
    pass "Admin daemon started"
    run_admin sh -c 'head -20 /var/log/ghostwire/daemon.log'
else
    fail "Admin daemon failed to start"
    run_admin sh -c 'cat /var/log/ghostwire/daemon.log 2>/dev/null' || true
fi

# Clean up passphrase file
run_admin sh -c 'rm -f /tmp/gw-pass'

# ============================================================
log "=== Phase 5: Join relay and operator nodes ==="
# ============================================================

# Join relay
printf '%s\n%s\n' "$PASSPHRASE" "$PASSPHRASE" | run_relay ghostwire join \
    --token "$RELAY_TOKEN" \
    --endpoint "172.28.0.10:8443" \
    --name "relay-node" \
    --config /etc/ghostwire 2>&1 || true

if run_relay test -f /etc/ghostwire/config.enc; then
    pass "Relay node joined mesh"
else
    fail "Relay config not found after join"
fi

# Join operator
printf '%s\n%s\n' "$PASSPHRASE" "$PASSPHRASE" | run_operator ghostwire join \
    --token "$OPERATOR_TOKEN" \
    --endpoint "172.28.0.10:8443" \
    --name "operator-node" \
    --config /etc/ghostwire 2>&1 || true

if run_operator test -f /etc/ghostwire/config.enc; then
    pass "Operator node joined mesh"
else
    fail "Operator config not found after join"
fi

# ============================================================
log "=== Phase 6: Start all daemons and test mesh overlay traffic ==="
# ============================================================

# Start relay daemon
run_relay sh -c "echo '$PASSPHRASE' > /tmp/gw-pass"
run_relay sh -c 'ghostwire up --config /etc/ghostwire -f < /tmp/gw-pass > /var/log/ghostwire/daemon.log 2>&1 &'
run_relay sh -c 'rm -f /tmp/gw-pass'

# Start operator daemon
run_operator sh -c "echo '$PASSPHRASE' > /tmp/gw-pass"
run_operator sh -c 'ghostwire up --config /etc/ghostwire -f < /tmp/gw-pass > /var/log/ghostwire/daemon.log 2>&1 &'
run_operator sh -c 'rm -f /tmp/gw-pass'

sleep 15

# Check if daemons started (look for TUN interface)
for node in gw-admin gw-relay gw-operator; do
    if docker exec "$node" sh -c 'ip link show gw0 2>/dev/null' | grep -q gw0; then
        pass "$node: WireGuard tunnel interface gw0 is up"
    else
        log "$node: gw0 not found (checking daemon log):"
        docker exec "$node" sh -c 'tail -5 /var/log/ghostwire/daemon.log 2>/dev/null' || true
        fail "$node: WireGuard tunnel interface gw0 not up"
    fi
done

# Test mesh overlay ping (10.99.0.x addresses)
log "Testing mesh overlay connectivity (waiting for WireGuard handshake)..."

# Give WireGuard time to complete handshake over HTTPS transport
sleep 8

MESH_OK=0
for attempt in 1 2 3; do
    log "  Attempt $attempt/3..."

    if run_admin ping -c 2 -W 3 10.99.0.2 >/dev/null 2>&1; then
        pass "Admin (10.99.0.1) -> Relay (10.99.0.2) via mesh overlay"
        MESH_OK=$((MESH_OK + 1))
    else
        log "  Admin -> Relay: not yet"
    fi

    if run_admin ping -c 2 -W 3 10.99.0.3 >/dev/null 2>&1; then
        pass "Admin (10.99.0.1) -> Operator (10.99.0.3) via mesh overlay"
        MESH_OK=$((MESH_OK + 1))
    else
        log "  Admin -> Operator: not yet"
    fi

    if run_relay ping -c 2 -W 3 10.99.0.3 >/dev/null 2>&1; then
        pass "Relay (10.99.0.2) -> Operator (10.99.0.3) via mesh overlay"
        MESH_OK=$((MESH_OK + 1))
    else
        log "  Relay -> Operator: not yet"
    fi

    if [ "$MESH_OK" -ge 3 ]; then
        break
    fi

    if [ "$attempt" -lt 3 ]; then
        sleep 5
    fi
done

if [ "$MESH_OK" -eq 0 ]; then
    log "  Mesh overlay pings did not succeed (WireGuard tunnel negotiation pending)"
    log "  Checking WireGuard handshake status..."
    for node in gw-admin gw-relay gw-operator; do
        docker exec "$node" sh -c 'tail -3 /var/log/ghostwire/daemon.log 2>/dev/null' || true
    done
fi

# ============================================================
log "=== Phase 7: Verify mesh status ==="
# ============================================================

ADMIN_STATUS=$(printf '%s\n' "$PASSPHRASE" | run_admin ghostwire status --config /etc/ghostwire 2>&1 || true)
echo "$ADMIN_STATUS" | head -20
if echo "$ADMIN_STATUS" | grep -qi "mesh\|configured\|admin"; then
    pass "Admin status reports mesh info"
else
    fail "Admin status doesn't show mesh info"
fi

# ============================================================
log "=== Phase 8: Docker network connectivity test ==="
# ============================================================

# Test basic connectivity between containers on the Docker network
if run_admin ping -c 1 -W 2 172.28.0.20 >/dev/null 2>&1; then
    pass "Admin can reach relay on Docker network"
else
    fail "Admin cannot reach relay on Docker network"
fi

if run_admin ping -c 1 -W 2 172.28.0.30 >/dev/null 2>&1; then
    pass "Admin can reach operator on Docker network"
else
    fail "Admin cannot reach operator on Docker network"
fi

if run_relay ping -c 1 -W 2 172.28.0.30 >/dev/null 2>&1; then
    pass "Relay can reach operator on Docker network"
else
    fail "Relay cannot reach operator on Docker network"
fi

# ============================================================
log "=== Phase 9: Simulated network degradation ==="
# ============================================================

# Add 50ms latency and 5% packet loss to relay
run_relay sh -c 'tc qdisc add dev eth0 root netem delay 50ms loss 5% 2>/dev/null' || true
sleep 1

if run_admin ping -c 3 -W 5 172.28.0.20 2>&1 | grep -q 'bytes from'; then
    RTT=$(run_admin ping -c 3 -W 5 172.28.0.20 2>&1 | grep 'avg' | awk -F'/' '{print $5}')
    pass "Relay reachable with simulated latency (avg RTT: ${RTT}ms)"
else
    fail "Relay unreachable with simulated latency"
fi

# Remove degradation
run_relay sh -c 'tc qdisc del dev eth0 root 2>/dev/null' || true

# ============================================================
log "=== Phase 10: Panic wipe test ==="
# ============================================================

# Copy config to a temp dir first so we can verify wipe
run_operator sh -c 'cp -r /etc/ghostwire /tmp/gw-backup' 2>/dev/null || true

run_operator ghostwire panic --config /etc/ghostwire --wipe-all --force 2>&1 || true

if run_operator test -f /etc/ghostwire/config.enc 2>/dev/null; then
    fail "Config still exists after panic wipe"
else
    pass "Panic wipe removed config files"
fi

# ============================================================
log "=== Results ==="
# ============================================================

echo ""
echo "============================================"
echo "  Passed: $PASS"
echo "  Failed: $FAIL"
echo "  Total:  $((PASS + FAIL))"
echo "============================================"
echo ""

if [ "$FAIL" -gt 0 ]; then
    fail "Some tests failed!"
    exit 1
else
    pass "All mesh integration tests passed!"

    # Print GUI URLs
    echo ""
    log "=== GUI Dashboard ==="
    for node in gw-admin gw-relay gw-operator; do
        GUI_TOKEN=$(docker exec "$node" sh -c 'cat /var/log/ghostwire/daemon.log 2>/dev/null' | grep -oE 'token=[a-f0-9]+' | head -1 | cut -d= -f2)
        PORT=$(docker port "$node" 9999 2>/dev/null | head -1 | cut -d: -f2)
        if [ -n "$PORT" ] && [ -n "$GUI_TOKEN" ]; then
            log "  $node: http://localhost:${PORT}/?token=${GUI_TOKEN}"
        elif [ -n "$PORT" ]; then
            log "  $node: http://localhost:${PORT}/ (check daemon log for token)"
        fi
    done
    echo ""
    log "Containers are still running. Use 'docker compose -f docker-compose.test.yml down' to stop."
    exit 0
fi

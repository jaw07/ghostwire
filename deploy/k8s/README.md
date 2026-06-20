# Deploying ghostwire to k3s (with Cloudflare)

Target: 4× arm64 Raspberry Pi k3s cluster (`192.168.8.0/24`), pod CIDR
`10.42.0.0/16`, MetalLB pool `192.168.8.230-255`, gitea registry at
`192.168.8.119:3000`.

## Cloudflare side — already provisioned

| Resource | Value |
|---|---|
| Tunnel | `ghostwire-k3s` / `45c0895f-015a-4ab0-99d3-5880a2c44a6d` |
| Public hostnames | `gw.dronedocs.net` → enroll :8443, `gwt.dronedocs.net` → transport :8444 |
| WARP route | `10.42.0.0/16` → tunnel (UDP 7947 gossip reaches pods via WARP) |
| Connector token | `~/.ghostwire-cfd-token` |

The HTTPS-mimic transport + enrollment ride the public hostnames (fronted by
Cloudflare). Gossip (UDP) is reachable only by **WARP-enrolled** clients via the
`10.42.0.0/16` private route — non-WARP clients use static peering instead.

## 1. Build + push the arm64 image

```sh
docker buildx build --platform linux/arm64 \
  -t 192.168.8.119:3000/<owner>/ghostwire:latest --push .
```
Then set `192.168.8.119:3000/REPLACE_OWNER/ghostwire:latest` in
`ghostwire-k3s.yaml` (init + main container). If the registry is plain HTTP,
add it to each node's `/etc/rancher/k3s/registries.yaml` as an insecure
registry and restart k3s.

## 2. Secrets (kept out of git)

```sh
kubectl create namespace ghostwire
kubectl -n ghostwire create secret generic ghostwire-cfd-token \
  --from-file=token=$HOME/.ghostwire-cfd-token
kubectl -n ghostwire create secret generic ghostwire-passphrase \
  --from-literal=passphrase='<choose-a-strong-passphrase>'
```

## 3. Apply

```sh
kubectl apply -f deploy/k8s/ghostwire-k3s.yaml
kubectl -n ghostwire rollout status deploy/ghostwire
kubectl -n ghostwire rollout status deploy/cloudflared
```

The ghostwire pod's `init-config` container runs `ghostwire init` once (using
`GHOSTWIRE_PASSPHRASE`) to create the mesh CA/admin config on the PVC; the main
container then runs `ghostwire up`.

## 4. Verify

```sh
# enrollment reachable through the tunnel:
curl -sk https://gw.dronedocs.net/health      # -> {"status":"ok"}
kubectl -n ghostwire logs deploy/ghostwire | grep -E "Tunnel active|listener|gossip"
```

## 5. Enroll a client

```sh
# admin side: mint a token against the RUNNING daemon (no passphrase, no restart)
TOKEN=$(kubectl -n ghostwire exec deploy/ghostwire -c ghostwire -- \
  ghostwire token create -c /etc/ghostwire --role operator --uses 1 --expires 1h)
# client side (passphrase via env, no prompt):
GHOSTWIRE_PASSPHRASE=... ghostwire join --endpoint gw.dronedocs.net --token "$TOKEN"
```

For UDP gossip discovery, the client must be on WARP (so `10.42.0.0/16` routes).
Otherwise enroll/transport still work over the public hostnames; configure peers
statically.

## Notes / caveats

- **Pod pinned to `user2`** because the PVC is node-local (local-path). Move the
  `nodeSelector` if you want it elsewhere.
- Cloudflare **terminates TLS at the edge**; the HTTPS-mimic transport tolerates
  this, but the outer cert is Cloudflare's, not end-to-end.
- If TUN can't be opened with `NET_ADMIN` alone on a node, set
  `securityContext.privileged: true` on the ghostwire container.
- Roll the Cloudflare **Global API Key** (`cfk_…`) — it was only needed to mint
  the scoped tokens. Scoped tokens in use: `ghostwire-dns-dronedocs`,
  `ghostwire-tunnel-dns`. Delete them when the project is done.

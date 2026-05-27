# era-ocserv

Go port of OpenConnect's `ocserv` for ERA. A real L3 VPN gateway speaking the
Cisco AnyConnect / OpenConnect SSL VPN protocol so unmodified Cisco Secure
Client and OpenConnect clients can connect.

Sibling to `era-wg` (kernel WireGuard). Listens on loopback behind
`era-facade`'s SNI / UDP demux at `:443`. Single shared multi-queue Linux tun.
mTLS plus AnyConnect password-form challenge against era-portal.

## Status

Stage 1 scaffold. No protocol code yet.

## Reference

- Protocol spec &mdash; <https://github.com/zhouchenh/tpm/blob/main/docs/architecture/era-ocserv-protocol.md>
- Architecture ADR 0057 &mdash; <https://github.com/zhouchenh/tpm/blob/main/docs/decisions/0057-era-ocserv-architecture.md>

## Deploy

The `deploy/` directory ships the systemd unit, host setup script, and a
matching teardown. The harness assumes a Linux host that already has the
ERA data plane (era-wg / era-clat / TAYGA) running &mdash; era-ocserv is a
sibling, not a replacement.

### 1. Build

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -trimpath -o era-ocserv ./cmd/era-ocserv
```

For arm64 swap `GOARCH=arm64`. CI uploads both as workflow artifacts on
`v*` tag pushes.

### 2. Stage on the target host

```sh
# Copy the binary + harness onto the host.
scp era-ocserv          root@HOST:/opt/era-ocserv/era-ocserv
scp deploy/era-ocserv*  root@HOST:/root/era-ocserv-deploy/
ssh root@HOST 'chmod +x /opt/era-ocserv/era-ocserv \
  /root/era-ocserv-deploy/era-ocserv-setup.sh \
  /root/era-ocserv-deploy/era-ocserv-teardown.sh'
```

### 3. Run setup

```sh
ssh root@HOST 'cd /root/era-ocserv-deploy && ./era-ocserv-setup.sh'
```

The setup script is idempotent. It creates `/opt/era-ocserv/`,
`/etc/era-ocserv/`, `/var/lib/era-ocserv/`, `/var/log/era-ocserv/`, drops a
placeholder env file, sets IPv6 forwarding sysctls (recording the originals
in a marker file for teardown), and installs the systemd unit.

If the host needs proxy NDP on the egress interface (only when era-wg does
NOT already proxy the /128 pool you'll hand to era-ocserv), pass
`PROXY_NDP=1`:

```sh
PROXY_NDP=1 ./era-ocserv-setup.sh
```

### 4. Populate `/etc/era-ocserv/era-ocserv.env`

The setup script writes a template with `REPLACE_ME` placeholders. Edit it
in place. The systemd unit only expands `$ERA_OCSERV_ARGS`, so keep the
single-variable shape.

Sample env file (placeholders &mdash; replace the `REPLACE_ME_*` values):

```sh
ERA_OCSERV_ARGS=" \
  -listen 127.0.0.1:8444 \
  -tls-cert /etc/era-ocserv/tls/fullchain.pem \
  -tls-key  /etc/era-ocserv/tls/privkey.pem \
  -client-ca /etc/era-ocserv/pki/era-client-ca.pem \
  -era-portal-url https://portal.internal.eracloud.app \
  -era-portal-token REPLACE_ME_ERA_PORTAL_SERVICE_TOKEN \
  -tpm-url http://127.0.0.1:9090 \
  -tpm-token REPLACE_ME_TPM_SERVICE_TOKEN \
  -tun-name era-ocserv-tun \
  -tun-mtu  1500 \
  -tun-queues 0 \
  -tun-ipv6 2001:470:f9d1:9001:ffff::1/128 \
  -server-name vpn.eracloud.app \
  -dns 2606:4700:4700::1111,2606:4700:4700::1001 \
  -log-level info \
"
```

Then drop TLS material in:

```
/etc/era-ocserv/tls/fullchain.pem    # 0644, the *.eracloud.app wildcard
/etc/era-ocserv/tls/privkey.pem      # 0600
/etc/era-ocserv/pki/era-client-ca.pem # 0644, ERA PKI client CA
```

### 5. Enable + start

```sh
systemctl daemon-reload
systemctl enable --now era-ocserv
systemctl status era-ocserv
journalctl -u era-ocserv -f
```

### 6. Wire era-facade

era-ocserv binds loopback. Public ingress is era-facade's job:

- **TCP/443** &mdash; SNI rule `vpn.eracloud.app` &rarr; `127.0.0.1:8444` with
  PROXY protocol v2 prepended so era-ocserv sees the real client IP.
- **UDP/443** &mdash; widen the demux to first-byte sniff: `0x16` (DTLS
  ClientHello) routes to the era-ocserv DTLS loopback socket.

See ADR 0057 §2 for the details and the TT-merge Phase 2 dispatcher
crossover.

### 7. Smoke test

From the host, verify the TLS handshake terminates and the server cert is
the expected wildcard:

```sh
openssl s_client -connect 127.0.0.1:8444 -servername vpn.eracloud.app \
  -showcerts -verifyCAfile /etc/era-ocserv/tls/fullchain.pem </dev/null \
  | head -40
```

Expected: `Verify return code: 0` and `subject= CN = *.eracloud.app`.
A 401 on the unauthenticated init POST is also fine &mdash; that means TLS
is up and mTLS is required.

Once era-facade is fronting the public IP, a full client smoke is:

```sh
openconnect --servercert pin-sha256:<pin> vpn.eracloud.app \
  --certificate device.crt --sslkey device.key
```

### Teardown

```sh
./era-ocserv-teardown.sh
```

The teardown stops + disables the unit, removes the tun device if it
lingered, restores any sysctls it set (from the marker file), and removes
`/opt/era-ocserv` plus state. `/etc/era-ocserv/era-ocserv.env` and any TLS /
PKI material are deliberately preserved.

### What this does NOT disturb

- era-wg (kernel WireGuard, `:51821/udp`)
- era-clat (wireguard-go-clat, `:51822/udp`)
- nat64-era (TAYGA NAT64)
- era-tt-reconciler / ttd
- wg0, echo0, eth0 addressing or default routes

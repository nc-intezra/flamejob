# TLS for flamejob

flamejob speaks plain HTTP by default and expects transport TLS to be provided
by the deployment. As of **1.6.0** there are three supported ways to get it, and
you can mix them (e.g. a proxy in front of the API, native TLS on the dashboard).

Agent authentication does **not** depend on transport TLS: an agent proves its
identity at the application layer by sending its CA-signed certificate in the
WebSocket `Hello` frame, which the server matches by fingerprint against the
`agents` table. So terminating TLS at a reverse proxy is safe — it does not
break mutual authentication, and the `/agent/stream` WebSocket proxies through
transparently.

## Option 1 — Caddy reverse proxy with automatic Let's Encrypt (recommended)

Best when the control plane has a public DNS name. [Caddy](https://caddyserver.com)
obtains and renews a certificate automatically (ACME / Let's Encrypt or ZeroSSL),
redirects HTTP→HTTPS, and staples OCSP — no cron, no renewal scripts.

```bash
docker compose -f deploy/docker-compose.yml -f deploy/docker-compose.caddy.yml up --build
```

Edit [`deploy/caddy/Caddyfile`](../../deploy/caddy/Caddyfile) to set your domain.
A minimal site block is all it takes:

```caddyfile
flamejob.example.com {
    reverse_proxy flamejobd:8443
}
```

Requires a public DNS record pointing at the host and reachable ports 80 and 443
for the ACME challenge.

## Option 2 — Caddy with an enterprise / pre-created certificate

When your organization's CA issues the certificate, point Caddy at the PEM files
instead of letting it talk to Let's Encrypt:

```caddyfile
flamejob.example.com {
    tls /etc/flamejob/tls/api.crt /etc/flamejob/tls/api.key
    reverse_proxy flamejobd:8443
}
```

If you run an internal ACME CA (e.g. [smallstep](https://smallstep.com)), keep
automation but change the issuer:

```caddyfile
flamejob.example.com {
    tls { issuer acme { ca https://ca.internal/acme/acme/directory } }
    reverse_proxy flamejobd:8443
}
```

For a private network with no public names, `tls internal` uses Caddy's own CA.

## Option 3 — Native rustls on flamejobd (no proxy)

flamejobd can serve the API over HTTPS directly from a pre-created certificate —
useful when you already have an enterprise cert and do not want a proxy in the
path. Set both `tls_cert` and `tls_key` under `[server]` (the web dashboard has
the same option under `[web]`):

```toml
[server]
bind     = "0.0.0.0:8443"
tls_cert = "/etc/flamejob/api.crt"
tls_key  = "/etc/flamejob/api.key"

[web]
bind     = "0.0.0.0:9443"
tls_cert = "/etc/flamejob/web.crt"
tls_key  = "/etc/flamejob/web.key"
```

Both `tls_cert` and `tls_key` must be set together; with neither, the listener
stays on plain HTTP. flamejobd does not itself run an ACME client — for automatic
Let's Encrypt use Option 1. This keeps certificate automation out of the control
plane, where an expiry or challenge failure would be a single point of failure;
a dedicated proxy renews independently of the application.

## Option 4 — Sitewide settings in the dashboard (runtime, no restart)

A superadmin or admin can paste a certificate and private key straight into the
dashboard — **[sitewide settings]** (top bar, next to the username) — and toggle
**HTTPS on tcp/443** with a checkbox. The change takes effect live: the server
binds (or drops) a dedicated :443 HTTPS listener on the spot. The existing plain
HTTP dashboard port (default 9443) is never affected, so you never lock yourself
out.

- The private key is stored **encrypted at rest** (AES-256-GCM, the same cipher
  that protects cracked plaintext) and is never shown again.
- Binding 443 is privileged. Running under systemd, the provided unit grants
  `CAP_NET_BIND_SERVICE`; otherwise run with that capability or choose a
  non-privileged `[web].https_bind`. If the bind fails, the HTTP dashboard keeps
  running and the settings panel shows "not listening".
- Because this serves the dashboard over HTTPS, make the API reachable over HTTPS
  too (Option 2/3 or a proxy) — a browser blocks an HTTPS page calling an HTTP API.

## Which to choose

| Situation | Use |
| --- | --- |
| Public domain, want zero-maintenance certs | Option 1 (Caddy + Let's Encrypt) |
| Certs issued by your corporate/enterprise CA | Option 2 or Option 3 |
| Internal ACME server (smallstep, etc.) | Option 2 (`issuer acme`) |
| No proxy allowed in the path | Option 3 (native rustls) |
| Air-gapped / private network, self-signed | Option 2 (`tls internal`) or Option 3 |
| Want to add/rotate the dashboard cert from the UI, live | Option 4 (Sitewide settings) |

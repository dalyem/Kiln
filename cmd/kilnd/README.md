# kilnd gateway

`kilnd gateway --config /etc/kiln/gateway.json` runs an outbound-only gateway
identity and heartbeat client. It opens no administration listener and does not
change routing, firewall rules, or guest state.

The configuration file contains paths, never an inline bootstrap token:

```json
{
  "enrollmentUrl": "https://kiln.example.test:4443",
  "heartbeatUrl": "https://kiln.example.test:4444",
  "serverCaFile": "/etc/kiln/core-server-ca.pem",
  "clientCaFile": "/etc/kiln/gateway-issuer-ca.pem",
  "installationId": "inst_123",
  "resourceId": "gw_123",
  "generation": "1",
  "bootstrapTokenFile": "/etc/kiln/gateway-bootstrap-token",
  "stateDir": "/var/lib/kilnd",
  "serviceUnits": ["dnsmasq.service"]
}
```

Both endpoints must be HTTPS bases without paths, query strings, credentials,
or fragments. The client requires TLS 1.3, uses `serverCaFile` for server
authentication, and uses `clientCaFile` to validate the returned client leaf.
The two CA files have different roles.

`stateDir` must be mode `0700` or stricter. `kilnd` writes a P-256 private key
and enrollment state there with mode `0600`; it refuses symlinks, broad state
permissions, and a second daemon holding the same state directory. The token
file must also be a regular mode-`0600` file. If a bootstrap response is lost,
restart with the same state directory so the same key can use the server's
narrow replay response. If the server's token window has expired, an
administrator must issue a new token.

Configured `serviceUnits` are observed with `systemctl is-active --quiet`.
They produce `PASS` or `FAIL`; omitted units produce `UNKNOWN`. Policy and
reservation remain `UNKNOWN` in this release.

## Network probe client

`kilnd probe --config /etc/kiln/probe.json` is a one-shot diagnostic client.
Core currently creates a fake probe resource. To exercise the real checker,
an operator supplies this configuration and the scoped token manually.
VM provisioning and automatic credential delivery are deferred:

```json
{
  "coreUrl": "https://kiln.example.test:4443",
  "serverCaFile": "/etc/kiln/core-server-ca.pem",
  "probeId": "probe_123",
  "tokenFile": "/etc/kiln/probe-token"
}
```

The token stays in a regular mode-`0600` file. The client rejects inline
credentials, redirects, proxy settings, invalid plans, untrusted TLS servers,
and expired plans. It fetches a Core-defined plan, runs the listed DNS, HTTPS,
and TCP checks once in order, then retries the exact report bytes until the
earlier of plan expiry or a ten-minute local limit. It has no listener, does
not run commands, and does not change the guest network.

DNS uses only the plan's explicit resolver. HTTPS requires TLS 1.3 and uses
the host trust store plus an optional profile CA. TCP makes one connection to
the planned IP and port. A TCP connection failure for a target expected to be
blocked reports `TCP_FAILED`; Core treats that as unknown rather than proof of
isolation.

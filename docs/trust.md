# HTTPS identity and database trust

There are two independent trust decisions:

1. **Who am I connecting to?** HTTPS verifies the hostname and certificate chain.
2. **Who published these database bytes?** Ed25519 verifies the signed manifest,
   which binds content hashes, sizes, revision and expiry to the publisher.

The second check survives transport through GitHub, static hosting or offline copying.
A GitHub HTTPS certificate authenticates GitHub, not the author of a database.

## Create a private identity

```sh
mkdir -p .local
bin/shixpeer-ward-beacon init -pki .local/pki -hosts beacon.example,localhost,127.0.0.1,::1
```

The directory must not exist; keys are never silently overwritten. Files:

| File | Purpose | Share? |
| --- | --- | --- |
| `server.key` | Beacon HTTPS private key | Only the HTTPS publisher account |
| `server.crt` | Beacon HTTPS certificate, one-year lifetime | Public |
| `ca.key` | Signs HTTPS certificates; generated for bootstrap | Keep offline after provisioning |
| `ca.crt` | Agent's private-CA trust anchor, five-year lifetime | Agents, through a trusted channel |
| `signing.key` | Signs database manifests | Only the export/signer account |
| `feed.pub` | Verifies database manifests | Agents, through a trusted channel |

Private keys are written `0600`; the key reader rejects group/world-readable
signing keys. The serve command rejects an over-permissive TLS key.
Use administrator-owned parent directories; do not copy an entire PKI directory
into the public export directory or repository. Production provision only the
specific key needed by each service. Keep `ca.key` off the live publisher if possible.

`init` is a bootstrap tool, not a certificate renewal service. Renew before expiry
using your certificate-management process, preserving the chosen CA or securely
reprovisioning trust. Publicly trusted certificates may replace the generated TLS
identity; omit `-ca-file` for a public CA. No `--insecure` TLS bypass is provided.

## Bootstrap an agent

Copy `ca.crt` and `feed.pub` with an existing trusted administrative channel.
Compare their hashes through an independent trusted channel when appropriate.
Never fetch the initial trust key from an untrusted mirror and trust it automatically.

```sh
shixpeer-ward-agent pull \
  -feed-url https://beacon.example:8443/v1/manifest.json \
  -ca-file "$HOME/.shixpeer.ward/config/ca.crt" \
  -trusted-key "$HOME/.shixpeer.ward/config/feed.pub"
```

No mutual TLS/client identity is required for this public-data download. The agent
does not send hostname, inventory, installed versions, or a client identifier.
Your web server/CDN still sees network metadata. HTTPS endpoints and redirect
hostnames must be explicitly trusted; there is no anonymous-network promise.

## Rotation and compromise

TLS rotation and data-signing rotation are separate. Replacing the signing key
requires secure out-of-band rollout of the new `feed.pub`; the old key cannot
authorize an automatic replacement through a downloaded feed. Multi-key rotation
and revocation lists are not implemented. Keep backups and a documented operator
process. A compromised trusted signing key can publish false data; signatures do
not replace source review or isolate a compromised publisher.

Agents persist the highest verified revision/digest and refuse lower/conflicting
revisions. Do not delete checkpoints as routine recovery. A fresh machine has no
revision history and relies on the pinned key and manifest expiry. Correct time
is required. The snapshot TTL is at most seven days, default 24 hours.

Current installations bind the pinned signing key and accepted manifest in one
atomic `database/current.json`. A different pinned key is rejected against existing
state. There is no automatic trust/history reset: key replacement requires a planned
out-of-band reprovisioning into a separate state directory, retaining the old state
for audit. This is an explicit operator migration, not a downloaded instruction.

Agent installers require a separately trusted script SHA256 before execution, then
a provisioned public key or pinned SPKI SHA256. Signed release manifests bind Linux
architecture, hashes, sizes and validity. See [Ubuntu deployment](ubuntu-deployment.uk.md).

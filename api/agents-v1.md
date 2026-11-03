# Signed agent release v1

`beacon release` publishes `agents.txt`, raw Ed25519 `agents.sig`, public
`feed.pub`, pinned-bootstrap `install.sh` and immutable Linux binary objects.
TLS and signing keys are independent; the HTTPS worker must not read signing keys.
The installer SHA256 itself must be verified out of band **before** executing it.
Provision the public signing key or its SHA256 of DER SPKI independently too.

The signed bytes are UTF-8/LF, canonical TSV, including a final newline:

```text
WARD-AGENT-RELEASE-V1
<Unix creation/revision seconds>
<Unix expiry seconds>
<version: 1..64 ASCII letters/digits/dot/plus/underscore/hyphen>
<sha256>\t<bytes>\tagent-linux-amd64-<sha256>
<sha256>\t<bytes>\tagent-linux-arm64-<sha256>
```

The code emits actual tabs, not the literal `\t` shown above. A valid release
contains both architectures exactly once, 1..64 MiB per ELF64 little-endian
artifact, amd64 machine 62 or arm64 machine 183. TTL: 1 hour through 30 days;
clients reject expired/future (>5 min) manifests. `agents.txt` is <=4 KiB and the
Ed25519 signature is 64 bytes. No shell evaluation of manifest fields is allowed.

The installer verifies signature, time, hash and byte lengths before creating
configuration/installing a binary. It fetches both builds in manifest order for
all clients and selects architecture locally. The source database/snapshot is
unrelated: installation never uploads package inventory or queries per-package data.
URLs remain on the explicitly supplied HTTPS origin, without redirects/proxies.

Per-home installation checkpoints pin the publisher key, highest revision and
manifest digest; key changes, older revisions and conflicting same-revision
manifests are refused. A fresh client has no historic checkpoint and trusts a
valid release within its lifetime. No automatic binary update or key rotation.

Publication writes the manifest last. During a concurrent re-publication the
manifest/signature pair may transiently differ and verification fails closed;
retry the installation. Content-addressed binaries do not change under a name.
Old binaries must only be pruned after all releases referencing them have expired.
Data/checkpoints/reports/CA/pins live under the service user's ~/.shixpeer.ward/;
systemd unit definitions are the only system-wide installation configuration.

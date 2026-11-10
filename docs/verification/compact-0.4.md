# Compact database verification — 0.4.0-dev, 2026-10-30

> Historical verification notes. For deployment and current procedures, see the [documentation index](../README.md).

Executed on macOS arm64, Go 1.26.10. Measurements use `/usr/bin/time -l`; macOS
reports maximum RSS in **bytes**. MiB below means 1,048,576 bytes. Download timings
use a local HTTPS server with normal certificate validation and a separately pinned
Ed25519 key. Network/WAN timings and other machines will differ.

## Full default publication, not a catalog-only check

All **18 enabled sources** in `configs/beacon.default.json` completed streaming
import: Canonical CVE/Livepatch, Debian Tracker, SOFA, Apple bulletin discovery,
EPSS, KEV, Go/PyPI/Packagist/Maven/NuGet/RubyGems/Rust/GitHub Actions/npm OSV,
all 25 annual NVD files (2002–2026), CVEProject and GitHub Advisory Database.
The `all` publication profile was used, without selecting by installed inventory.

The final publication has **6,778,963 rows** in **896 indexed files**, totaling
**324,303,740 bytes (309.28 MiB)**. Rows include rules, source facts, aliases,
risk records and shared version sets; they are **not a unique-CVE count**.

| Group | Rows | File bytes |
| --- | ---: | ---: |
| Package rules | 4,023,882 | 82,343,602 |
| Advisory facts/aliases | 2,353,602 | 215,502,724 |
| KEV/EPSS risk | 399,906 | 22,953,641 |
| Shared exact version sets | 1,573 | 3,503,773 |

The raw upstream archives are not delivered to agents. Disk files contain compressed
64 KiB blocks and a small sorted block index; delivery does not add another gzip
layer. The signed envelope is manifest v3; the disk magic is `WARDDB03`.

## Agent measurements with the full publication

| Operation | Wall time | CPU user + system | Maximum RSS |
| --- | ---: | ---: | ---: |
| First HTTPS download, verification and durable install | 4.74 s | 1.43 s | 22.94 MiB |
| Repeat pull of the installed publication | 0.05 s | 0.02 s | 20.77 MiB |
| Offline Debian bookworm `xz-utils` lookup, six rows | <0.01 s | <0.01 s resolution | 12.38 MiB |
| Offline risk lookup for CVE-2024-3094, one row | <0.01 s | <0.01 s resolution | 12.41 MiB |

First pull downloaded 896 objects / 324,303,740 bytes. Repeat pull downloaded
**zero objects and zero database bytes**; the signed manifest was still requested.
The package/CVE lookups do not perform network requests. They demonstrate indexed
retrieval, not a claim that this computer has those packages or vulnerabilities.

An explicit publisher-side news scan retained 200 critical/KEV facts: 5.89 s wall,
20.31 MiB maximum RSS. It does not run on agents.

## Publisher work

The initial full upstream import took about 6.5 minutes on this run (including
network and source parsing), using about 163 MiB peak RSS. Importing large vendor
archives is intentionally a separate publisher job. Processing does not require
loading the archives or final database into RAM together.

Compiled inputs are compressed and cached per input digest. Unchanged input data
skips reparsing; an unchanged aggregate skips external sorting. An offline repeat
of the three real cached Ubuntu/Debian/macOS inputs took 0.07 s / 12.56 MiB RSS.
Changes to EPSS are confined to risk files and do not invalidate package rules.
The publisher still needs raw/compiled cache disk space; the agent does not.

## Validation performed

- `make check`: gofmt, go vet and all tests with the race detector passed.
- Native macOS arm64 builds and Linux amd64 cross-builds passed.
- `govulncheck` v1.9.0: no vulnerabilities found.
- Agent dependency inspection: no Beacon/source adapter, external HTML parser or
  XZ decoder is linked into the agent command path.
- External sort, compressed blocks, cross-key filtering, split keys, exact version
  sets, CRC failures, oversized JSON, ZIP64 and cancellation tested with fixtures.
- Debian epochs/tilde/revisions, not-affected status, unsupported conditions and
  preservation of uncovered exact versions tested.
- HTTPS cache/ETag behavior, bounded NVD download workers and immutable mirror URLs
  tested with local TLS servers.
- Invalid signatures, expiry (including expiry during download), rollback,
  conflicting revisions, changed pinned keys, unapproved hosts, damaged first/last
  objects and interrupted installation tested. A partially downloaded generation
  never replaces the installed pointer; verified partial files can be reused.
- Failed configured source synchronization preserves the complete catalog and
  blocks publication. Private stale cache/catalog generations are pruned.

Tests do not access live sources. The live import/download above was a separate
explicit CLI verification. No remote server, firewall or host software was changed.
No repository/release/data was published to GitHub.

## Reproduce

The [README](../../README.md) starts with a small synthetic local demo. To verify
real data, substitute `configs/beacon.default.json` for the demo source config.
Use separate fresh state paths for this contract transition. A first full import
needs publisher network/cache space; subsequent agents consume the compact export.
See [protocol and publication](../distribution.md) for exact trust and size limits.

On the development machine this run's validated state is retained, gitignored,
under `~/.shixpeer.ward/validation/`. Run from the project directory:

```sh
bin/shixpeer-ward-agent lookup -state ~/.shixpeer.ward/validation/agent \
  -ecosystem Debian:bookworm -package xz-utils
bin/shixpeer-ward-agent lookup -state ~/.shixpeer.ward/validation/agent \
  -group r -id CVE-2024-3094
```

To serve the retained export locally:

```sh
bin/shixpeer-ward-beacon serve -state ~/.shixpeer.ward/validation/beacon \
  -out ~/.shixpeer.ward/validation/public \
  -tls-cert ~/.shixpeer.ward/validation/pki/server.crt \
  -tls-key ~/.shixpeer.ward/validation/pki/server.key
```

Then pull in another terminal:

```sh
bin/shixpeer-ward-agent pull -state ~/.shixpeer.ward/validation/agent \
  -feed-url https://localhost:8443/v1/manifest.json \
  -ca-file ~/.shixpeer.ward/validation/pki/ca.crt \
  -trusted-key ~/.shixpeer.ward/validation/pki/feed.pub
```

This saved publication expires after 24 hours. Refresh it with `beacon sync` and
`export`; expiry is never bypassed. Large benchmark raw caches and old intermediate
formats were removed. Immutable test objects are hard-linked locally across the
retained test fixture to avoid storing three copies. Deployments should use the
separate accounts/permissions described in [operations](../operations.md).

Host package/container collection, installed-version matching, impact assessment
and notifications remain future work. Unsupported applicability is not a safe verdict.

On 2026-11-02 the retained fixture moved into home state; its October publication
may be expired. Do not bypass expiry to repeat historical measurements. Use fresh
source synchronization or synthetic fixtures for current tests.

# Architecture and boundaries (0.4)

`shixpeer-ward-beacon` is the separate publisher. `shixpeer-ward-agent` observes a
host and maintains a local disk database. Neither program updates host software.

```text
explicit upstream sources → streamed raw cache (Beacon only)
                          → compact matching rules + advisory/risk facts
                          → external sort → indexed disk buckets
                          → signed manifest + immutable block-compressed files
                          → HTTPS mirror / GitHub
                          → agent verifies changed objects → atomic local install
local observation         → private snapshot → local version matching → JSON/Markdown report
local database lookup     → disk binary search → bounded JSON results
```

The publisher owns normalization, provenance and delivery. It does not embed a
scanner-specific SQL database. There is no database engine or external service.
Raw source documents and prose are not distributed to agents. Rules preserve OSV
range events, exact versions not provably covered by ranges, release/status and
vendor conditions understood by the projection. Large exact version lists are
shared binary disk sets. Unknown conditions are flagged `requires_review`.

Debian/Ubuntu versions use Debian ordering (epoch, revision, tilde). Exact version
lists are removed only when every listed version is demonstrably covered by the
retained ECOSYSTEM ranges. Debian `fixed_version=0` with resolved status means
`not_affected`; it is not an invented version range. Distro rules address **source**
packages: the scanner resolves binary → source package/version locally with dpkg-query.
SOFA describes security releases and branches; it does not establish that every
older macOS version is vulnerable. NVD CPE leaves for explicitly mapped products are indexed with their bounds and
complexity flags; simple supported alternatives can match. Full Boolean logic and
CNA-specific version schemes still require review.
The original evidence remains in Beacon's current raw cache for investigation.
Different sources remain distinct; conflicting records are not silently overwritten.

## Bounded storage and work

Each group (`p` package rules, `v` advisory facts, `r` KEV/EPSS risk facts, `s` exact
version sets) uses SHA-256 prefix buckets (256 each for p/v/r, 128 for s). Sorted rows are grouped into independently compressed 64 KiB blocks
(large exact sets are bounded exceptions). Files have a fixed-size sorted block index;
lookups use `ReadAt` binary search without loading the database or index into RAM.
The default query emits at most 100 rows and reports an incomplete query on overflow.
Rules are limited to 64 KiB, shared sets to 8 MiB, and objects to 128 MiB on disk.
EPSS changes do not force package-rule downloads.

Imports process records independently. External sorting uses an 8 MiB run budget
and merge fan-in four; individual input/decoder allocations have explicit bounds.
The XZ decoder also needs its dictionary (up to 64 MiB). Publisher RSS is therefore
larger than the sort budget. This is intentionally separate from agent resource use.

Conditional HTTP requests avoid unchanged upstream bodies when supported. Per-input
compressed compiled caches avoid reparsing unchanged annual NVD files/articles. An unchanged
aggregate skips sorting. Public buckets are deterministic, so agents fetch only
changed objects. Current private compiled/raw caches and the catalog are pruned on
successful sync; failed sync retains last-good state. Public immutable objects are
retained for in-flight clients; operators must prune expired publications separately.

## Trust and privacy

All agents using a publication fetch the same set of changed objects. No package,
version, hostname or inventory enters a request. `-profile all` is the default.
`-profile prototype` is an explicit public coverage subset (Ubuntu 24.04 LTS, Debian
bookworm/12, macOS); it is not inferred from host inventory. Different profiles need
separate publisher/agent state. Mirrors still see IPs, timing and publication choice.

Manifest v3 and disk format 3 are incompatible with old JSON feeds. An update must
verify the independent Ed25519 signature, TTL, revision and object sizes/hashes
before atomically replacing a small `current.json` pointer. This pointer is also the
anti-rollback checkpoint, so it cannot advance before installation. Downloads do not
block readers of the old database. Crash-released file locks serialize writers;
shared reader locks protect objects from deletion during lookups.

## Scope

Offline scanning collects OS/kernel, package versions, macOS bundles, service
registries, sockets, local Docker metadata and global npm/Python package metadata.
Supported distro/language rules and explicit CPE identities are matched locally;
unknown identities, container packages, project lockfiles and complex applicability
remain explicit. Missing coverage is never a clean bill of health.
`beacon news` explicitly scans advisory/risk buckets and retains up to 200 recent
critical/KEV records; this scan does not run on agents. There is no separate signed
news artifact in the new protocol. KEV/EPSS lookup by CVE works. No automatic remediation, remote commands or telemetry.

See [offline scanning](scanning.md) for report status, priorities, limits and unsupported coverage.

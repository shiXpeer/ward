# Security policy

Shixpeer Ward is pre-release. It has not received an independent security audit.
There is no supported production release yet. Only current main is maintained.

For suspected vulnerabilities, do not open a public issue containing secrets or
exploit details. Use GitHub's private vulnerability reporting when enabled on the
repository, or request a secure reporting channel through [shixpeer.com](https://shixpeer.com).
No private reporting endpoint is implied until the repository owner enables one.

## Trust boundaries

- Beacon fetches only locally configured sources; no source is discovered from a
  downloaded advisory. Explicit configuration is not a guarantee of source quality.
- HTTPS uses a local private server key. Agents trust the corresponding CA through
  out-of-band provisioning. Never distribute `server.key`, `ca.key`, or `signing.key`.
- Database snapshots use a separate Ed25519 signing key, a SHA-256 digest, revision,
  and expiry. TLS authenticates transport; a signature authenticates artifact bytes.
  Neither guarantees an advisory is factually correct or applies to a host.
- Initial `ca.crt` and `feed.pub` must come through a trusted channel, not an
  unauthenticated download beside the database. Deleting an agent's checkpoint
  resets its rollback protection. Clock correctness is part of freshness checking.
- Agent collection never posts inventory. The downloader uses fixed manifest/artifact
  requests, no package/CVE queries, no telemetry, and no implicit HTTP proxy.
- Offline scanning is partial: supported distro/language rules and explicitly mapped
  CPE products can match. Services, sockets and Docker metadata are inventoried;
  unknown identities, container packages and project lockfiles remain unchecked. Do not treat zero findings as a clean host. See docs/scanning.md.

## Isolation

No command requests sudo or modifies firewall/software. An unprivileged process can
only inspect readable data. The convenience `agent run` combines collection and
network fetching; goroutines are not a sandbox. For stricter deployments, use the
separate collect and pull service/timer examples with distinct users and state dirs.
No Docker socket access is required by the current Go collector.

HTTP client redirects require HTTPS and an allowlisted hostname. DNS is still part
of endpoint trust; IP pinning/SSRF-resistant routing is not implemented. Configure
sources and redirect hosts as administrator-owned inputs, never untrusted requests.
Keys/state require restrictive permissions and trusted parent directories. Files
are committed with temp-file, fsync and rename; this does not defend against a
compromised local account able to replace the application or its parent directories.
Only a dedicated public export directory is served. No directory listing or private
state/key endpoint exists. External certificate renewal/revocation and signing-key
rotation are operator responsibilities; there is no automatic key update from feeds.

## Limits and recovery

Sources have configured compressed input bounds (at most 512 MiB), up to 16 GiB
streamed expansion, 8 MiB per archive record and 1.5 million advisories per input.
XZ dictionaries are limited to 64 MiB. Imports and external sorting are bounded;
raw datasets are not loaded into memory together. Publisher RSS still includes
decoder dictionaries and individual records; measure before setting process limits.

Agents accept signed manifest v3/disk format 3 only: at most 896 objects, 128 MiB per
file, 4 GiB total file bytes, TTL up to seven days. These are disk/transport rejection
bounds, not RAM allocations. The disk index and compressed blocks are read on demand.
Rules are at most 64 KiB, shared exact version sets at most 8 MiB. Default lookup
limits results to 100 and explicitly reports incompleteness when exceeded.

Crash-released advisory locks serialize publisher/updater writers and protect active
readers during pointer replacement/garbage collection. Lock files are not stale lock
ownership tokens and do not need removal after a crash.

All object sizes/hashes and indexes are verified before a single atomic current
manifest/checkpoint pointer is replaced. Object-directory renames are synced first.
Signature, expiry, rollback, network and validation failures retain the installed
generation. A storage error after the final pointer rename can leave crash durability
uncertain; retain objects and retry rather than deleting trust/revision state.

Any configured source failure blocks publication, preserving the last complete
catalog/export; a failed first fetch never becomes empty healthy coverage. Unknown
vendor conditions, unsupported NVD Boolean/CNA applicability and missing package coverage must not
be interpreted as a clean host. Raw source evidence stays on Beacon. Public source
facts and local package lookup do not constitute an installed-version scanner.

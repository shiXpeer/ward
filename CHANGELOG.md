# Changelog

Versions follow Semantic Versioning. While pre-1.0, any breaking change is explicit
in release notes. Software tags are `vMAJOR.MINOR.PATCH`; data tags are separate.

## Unreleased (0.3.0-dev)

- Implement streamed Canonical OSV tar.xz, Debian Tracker, Apple HTML/SOFA,
  full annual NVD, EPSS, CVE JSON 5 and direct GHSA repository adapters.
- Ship real default/extended/quickstart profiles and live check-sources/status commands.
- Accept OSV affected records without package identity, preserving unmapped evidence.
- Add explicit feed v3 packed evidence and manifest v2 ordered signed shards.
- Stream private state array I/O and retain verification/checkpoint on failed parts.
- Require patched Go 1.26.10 and validate reachable vulnerabilities with govulncheck.
- Pin pure-Go XZ and HTML parser dependencies and include third-party notices.

### Migration from 0.2.0-dev

Rebuild agent and Beacon together; use fresh private state directories. Feed v3 is
not readable by the old agent. TLS and signing identities may be retained securely.
Snapshots may require substantial RAM/disk; this is not a completed package matcher.


- Rename commands to `shixpeer-ward-agent` and `shixpeer-ward-beacon`.
- Consolidate into one Go module, with versioned shared JSON contracts.
- Configure OSV JSON/ZIP and CISA KEV sources without compiling source URLs into code.
- Preserve per-source snapshots across failed refreshes and cursor-based deltas.
- Retain original advisory evidence, OSV ranges and source-specific withdrawal status.
- Export signed, expiring immutable artifacts for HTTPS and GitHub distribution.
- Generate separate private TLS and Ed25519 signing identities.
- Add a small recent critical/known-exploited news feed with stable item IDs.
- Add tests, CI, release packaging, contributor and operator documentation.

### Breaking changes

The old `hostagent`/`vulnfeed` command names, three-module layout, unsigned `/v1/feed`
endpoint, and feed format v1 are replaced. Existing prototype state must not be
silently reused. Start fresh state directories and bootstrap CA/public-key trust.

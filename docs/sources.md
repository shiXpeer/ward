# Sources, normalization and validation

Beacon fetches an explicit local JSON configuration supplied with `-sources`.
Sources cannot add other sources or execute code. Agents receive the same complete
signed database, independent of installed packages. No inventory is sent upstream.

## Shipped configurations

- `configs/beacon.quickstart.json`: smaller **real** online datasets for a first run
  (Debian Tracker, SOFA, EPSS, CISA KEV and Go OSV).
- `configs/beacon.default.json`: Canonical CVE/Livepatch, Debian Tracker, Apple,
  SOFA, complete annual NVD, EPSS, KEV, direct CVE/GHSA repositories and major OSV
  language ecosystems including npm.
- `configs/beacon.extended.json`: default plus converted Debian/Alpine/Linux OSV.
- `configs/beacon.nvd.json` / `beacon.repositories.json`: standalone bulk profiles.
- `configs/beacon.demo.json`: synthetic offline demo.
- `configs/source-catalog.json`: research/coverage catalog, not runtime configuration.

```sh
bin/shixpeer-ward-beacon check-sources -sources configs/beacon.quickstart.json
bin/shixpeer-ward-beacon sync -sources configs/beacon.default.json -state .local/beacon-live
bin/shixpeer-ward-beacon status -state .local/beacon-live
```

`check-sources` uses the same streamed compilation/cache path as `sync`, prints
coverage and size totals, and exits nonzero on failure. Use `-state` to choose its
private validation state; it stops at the first failed source. It neither collects inventory nor installs
updates. It is an explicit live operation; unit tests use local fixtures only.
`status` reports the last complete catalog and per-source checks/counts. A failed
attempt blocks export; the last complete catalog remains available. Inspect it after sync: one successful source does not make all
configured sources successful. A live validation run does not promise future uptime.

## Adapter formats

| Type | Input and behavior |
| --- | --- |
| `osv` | Single record, array or `{"vulns": [...]}` |
| `osv-zip` | Full ecosystem ZIP, read without filesystem extraction |
| `osv-tar-xz` | Canonical OSV tar.xz, streamed with bounded decoder dictionary |
| `debian-tracker` | Whole Security Tracker JSON, package/release statuses preserved |
| `sofa` | SOFA macOS v1 JSON, branch/version/build/references preserved |
| `apple-security` | Apple security index and its same-host numeric bulletin links |
| `nvd-gzip` | One complete annual NVD JSON 2.0 gzip file |
| `nvd-years` | All annual files from 2002 (including older CVEs) through current UTC year |
| `epss-gzip` | Whole daily CSV gzip, date/score/percentile retained in agent risk facts; model metadata stays on Beacon |
| `cisa-kev` | Whole KEV JSON, dateAdded is exploitation-catalog date, not CVE publication |
| `cve-tar-gzip` | CVEProject repository archive, only CVE-named JSON under cves/ |
| `ghsa-tar-gzip` | Advisory repository archive, only JSON under advisories/ |

Canonical `record_kinds` may select `cve`, `usn`, `lsn`. The default selects all
per-CVE records plus Livepatch. USN is supported but excluded from the default
because its cves_map repeats substantial per-CVE material. Removing USN does not
remove the per-CVE dataset. Without record_kinds all three are parsed.

Apple is a bounded HTML integration, not a stable vendor bulk API: it covers the
currently linked bulletin index, not Apple's entire historical archive. Every
linked bulletin must succeed or the source refresh fails. Discovery is restricted
to HTTPS, the configured index host and numeric bulletin paths; maximum 512 links.
No inventory-dependent requests are made. HTML/schema drift produces an error.
SOFA is independent community evidence; a fixed version in a branch does not mean
all earlier macOS branches are affected. Applicability requires vendor context.

NVD annual import deliberately bootstraps full history instead of treating the
recent/modified window as a complete database. Conditional ETag/Last-Modified caching avoids unchanged downloads where the
upstream supports it. Up to four annual downloads run concurrently; parsing remains
sequential. Per-file compiled caches avoid reparsing unchanged years. Schedule broad
profiles sensibly (for example daily with `-ttl 72h`), not once per minute.
The signed TTL must exceed the interval plus refresh time. NVD CPE configuration
boolean trees and CVE CNA/ADP statuses remain in evidence; they are not flattened
into generic version ranges.

## Configuration boundary

Each enabled entry requires a unique ID, a supported type and exactly one of path
or HTTPS URL. Relative paths and ca_file resolve beside the configuration. Custom
CA files are additive to system roots. Redirect hostnames must be explicitly
allowlisted with allowed_hosts; no wildcard, credential helper, inherited HTTP proxy,
plain HTTP, URL credentials, shell plugins or downloaded source configuration.
Apple and nvd-years require URL mode. For NVD use an explicit directory ending /.

Input limits default to 64 MiB and may be configured up to 512 MiB compressed.
Streaming formats allow at most 16 GiB expanded, 8 MiB per archive entry and
1.5 million advisories. The XZ dictionary is capped at 64 MiB. NVD's combined annual
compressed input is capped at 2 GiB. Source operations have a 20-minute context;
individual HTTP operations retain their own timeout. Cancellation and trailing
compressed checksums are checked. Exceeding limits fails instead of accepting a
partial snapshot. Some source records intentionally have no package identity;
they retain raw evidence and report unmapped_affected, not an invented package.

## Compact publication (0.4)

The CLI now uses streaming `Prepare`/`Walk` adapters and compact indexed files.
It does not call the old batch normalizer or assemble JSON feeds. Raw evidence
remains on Beacon; agents receive rules and source-specific facts, not raw documents.
Unknown vendor conditions and unsupported applicability schemes require review.
See [architecture](architecture.md) and [protocol v3](distribution.md).

Records with identical keys and identical bodies are deduplicated on disk. Distinct
or contradictory bodies remain separate. Source signatures are not implied: HTTPS
and the configured source allowlist establish upstream transport trust; Ward signs
its resulting publication separately.

## Source conflicts and safety

Keep epochs, backports, release identity, source/binary packages, no-dsa, Pro/FIPS
and Livepatch context. Debian fixed_version=0 is not affected and never becomes an
invented affected range. Missing versions/status are not proof of safety. OSV
upstream CVE IDs participate in alias normalization; multi-CVE bulletins are not
collapsed into a single CVE. Preserve original-source evidence and withdrawals.

Aggregate display severity uses the first available configured source, not a host
risk verdict. EPSS is probability, KEV is observed exploitation evidence. News
includes recent explicit critical severity and KEV additions; it is not a complete
news or notification service. Installed-version matching for supported ecosystems
is partial and is described in [scanning](scanning.md).

## Redistribution

Ward's PolyForm Internal Use license does not relicense upstream data. Canonical data is
CC-BY-SA-4.0; GitHub advisories use CC-BY-4.0; OSV aggregates sources with different
terms. Keep attribution and review redistribution obligations before publishing a
combined database. Export advisories only, never inventory, private source caches,
credentials or keys. See the [Ukrainian source review](source-catalog.uk.md) and the
catalog's documentation links for authoritative upstream references.

CLI export/run publication refuses a saved feed containing source errors. A partial
sync remains inspectable through status, but does not replace the last signed
public manifest. Refresh and export again after fixing the source failure.

## Indexed NVD rules

Projection 105 indexes explicit product mappings as CPE rules, preserving bounds
and complex/negated conditions. Only supported simple alternatives are eligible
for confirmation. See [scanner semantics](scanning.md). Selected-source sync can
retain other data and original freshness with `-keep-other-sources`; export refuses
stale retained sources.

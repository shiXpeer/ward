# Local system scan

After setup and database update:

```sh
bin/shixpeer-ward-agent scan
```

Scanning is offline and never calls update. A verified, unexpired installed
publication is held under a shared generation lock throughout matching.
No software, service, firewall or container configuration is changed. Reports
`report.json` and `report.md` are private files (mode 600), saved next to
`snapshot.json` in agent state. Override output with `scan -report-dir PATH`.
The default is `~/.shixpeer.ward/agent/` on Linux/macOS, with configuration in
`~/.shixpeer.ward/config/agent.json`; root uses `/root/.shixpeer.ward/`.
`run` now performs initial update then periodic full scans/reports and independent
database updates. Use `migrate-home` to preserve legacy trust/checkpoints.
See [Ubuntu deployment](ubuntu-deployment.ru.md).

## Console summary

Every scan prints a bounded plain-text summary automatically: total/completed/
unchecked/incomplete component queries, affected components and version-rule
matches, and review-only components versus all components with review records.
The most urgent eight affected components appear first (known exploited, critical,
high, other), followed by up to three uncertain component groups and five warnings.
Repeated findings are grouped by component/version/origin/ecosystem. The example
advisory and its fixed version apply to that example, not all findings in the group.
Additional entries stay in the full JSON/Markdown reports, with omitted counts
shown in the console. Failed probes and incomplete scans remain visible; zero
matches never means safe. Common management/monitoring/database bindings are
flagged for review without claiming Internet reachability. Metadata controls,
newlines and bidirectional formatting characters are sanitized before terminal
output. No ANSI colors/control sequences are emitted, including when piped.

## Implemented inventory

- OS/kernel identity; Debian/Ubuntu installed dpkg binary packages, source package
  names and source versions. Distro rules use source versions, including epochs,
  revisions and backports, rather than upstream semver.
- Homebrew installed formula/cask versions. Core formula matching requires a local
  stable INSTALL_RECEIPT.json with `source.tap=homebrew/core`, matching installed
  version/revision and an explicit product mapping. HEAD builds, unknown receipts
  and arbitrary taps are not assigned upstream identities.
- macOS application name, bundle identifier and version from Info.plist, without
  executing the application. Roots: /Applications, /System/Applications and
  ~/Applications, with one category directory level; directory symlinks and other
  volumes are excluded. Bundle ID mapping is exact and case-sensitive. Build-only bundle versions are
  not treated as upstream release versions.
- macOS launchctl or Linux systemctl service registry; TCP listening sockets and
  bound UDP sockets with lsof/ss. Process owners and service associations are
  included when visible. Full process command lines are not collected.
- Running Docker metadata and published ports, only through an explicit local Unix
  socket. Remote contexts are not contacted. Inspect templates select only image,
  name, ID, start time and ports; environment variables/mounts are not requested.
  No docker exec, pull, install, start, stop or privilege escalation is performed.
- Current interpreter global Python distribution metadata, using isolated `-I -S`
  and explicit sysconfig paths (no site startup/.pth execution). Global top-level
  npm packages use offline, ignore-scripts, no-audit and no-fund options.
  Homebrew auto-update/analytics and npm update notifications are disabled.

## Matching and evidence

Debian/Ubuntu ECOSYSTEM intervals, exact version sets, exclusive fixed/limit
boundaries, inclusive last_affected and multiple intervals are supported.
PyPI/npm exact versions and stable numeric intervals are supported. Unsupported
prerelease, epoch, postrelease and vendor semantics remain review candidates.

NVD is indexed under ecosystem `CPE`. Product mappings live in
`internal/productid/catalog.go`; this is a finite, explicit list, not fuzzy name
matching. Publisher projection retains the vulnerable CPE leaf, version bounds
and whether its configuration had AND/negation/unknown operators. Only supported
simple alternatives can confirm a version-rule match. Resolvable platform and
architecture mismatches are excluded; edition/update/language/unknown platform
conditions require review. Nonnumeric intervals and unbounded wildcard versions
also require review. AND conditions never produce standalone confirmation;
negation always requires full configuration review. An NVD end boundary is not
presented as a guaranteed fixed version.

macOS SOFA release records are candidates for review only when a newer security
release exists in the same major branch. A release list does not establish that
all older releases were affected. A missing or failed probe is not evidence of
absence. Source-specific withdrawals/not_affected rules do not produce findings.

Each finding retains source, advisory ID, aliases, the representative matched
compact rule, installed and comparison versions, references, matching-rule count,
local KEV/EPSS enrichment and a recommendation. Multiple matching rules for one
source/advisory/component are aggregated; a confirmed supported alternative takes
precedence over a review-only alternative. Priorities: confirmed known exploited,
critical, high, other confirmed matches, then review candidates.

## Coverage and remaining limitations

This remains a **partial scanner**. Unknown formula/app identities are NOT_CHECKED
with a reason; adding an inventory row is not a completed vulnerability check.
Other limits: packages inside containers, project lockfiles, virtual environments,
nested npm dependencies, other language runtimes, kernels without a supported loaded-version signature,
full NVD Boolean evaluation and CNA-specific version schemes.

Local bind scope does not prove Internet reachability: firewall, Docker NAT,
cloud rules and an independent outside vantage point are not tested. Reports
flag common database/monitoring/management ports for access-restriction review,
without claiming those services are externally reachable. User permissions limit
process visibility. Listening on a port is not proof that a particular product
or version owns it; socket names do not create vulnerability matches.

NO_ADVISORY_FOUND means no rule was found for a supported identity.
NO_MATCH_IN_AVAILABLE_RULES means available rules did not match. Neither means
safe. REQUIRES_REVIEW is not a confirmed vulnerability. A confirmed version-rule
match does not demonstrate runtime exploitability or inspect local backport patches.

Status is partial even on success because of these limits. Missing/expired/invalid
DBs, missing objects or query/result bounds produce an incomplete report and
nonzero exit status. Update an expired database; signature/expiry/rollback checks
are never bypassed. A pre-CPE publication leaves mapped products NOT_CHECKED with
an explicit migration reason instead of claiming zero vulnerabilities.

## Bounded work and local contracts

Limits: 50,000 package entries, 3,000 app bundles, 10,000 services/sockets/global
packages, 1,000 running containers; 16 MiB dpkg, 4 MiB other large probe output,
1 MiB plist/receipt output; 30 seconds per probe and two minutes total command time.
Matching streams up to 100,000 rules per component without retaining them all;
output retains up to 64 findings per component and 10,000 overall. Counts include omitted details; output limits do not stop component checks. Public lookup CLI retains its
10,000-row bound. The complete DB is never loaded.

JSON contains all bounded inventory/findings; Markdown shows up to 100 findings
and services, groups repeated actions, and lists ports, component results and
limitations. Keep reports private. A failed write may leave an older report;
check generated_at before using it.

Local report format_version remains 1, with additive identity/reason/evidence
fields (api/report-v1.schema.json). Inventory-v1 adds OS, receipt provenance,
comparison versions and service associations. Signed manifest/disk format remain
v3. Sources advertise `rule_formats: ["nvd-cpe-v1"]` inside the signed payload.
Changing product mappings or interpretation requires bumping projection.Version
so publisher caches recompile. Agent builds do not import upstream source parsers.

## Refreshing an existing publisher without downloading every source

An explicit selected-source refresh retains other source data and its original
checked_at. It does not make stale sources fresh:

```sh
bin/shixpeer-ward-beacon sync -state BEACON_STATE -sources configs/beacon.nvd.json -keep-other-sources
```

Then export using the existing signing key, agent update, and scan. Export refuses
any retained source older than 24 hours. Normal sync still replaces the entire
configured source set. Selected refresh keeps other sources’ compiled/raw caches, prunes replaced
compiled inputs and retains old exact sets only when referenced by retained rules
(up to 65,536 distinct set references). Raw downloads replace bodies for the same
URL; after changing source URLs, use full sync to remove old raw cache entries. Public old artifacts remain available for in-flight
clients and should only be pruned after publication lifetimes have elapsed.

References: [NVD applicability data](https://nvd.nist.gov/developers/vulnerabilities),
[Homebrew local installation receipts](https://docs.brew.sh/Formula-Cookbook.html).

Running Ubuntu kernels are resolved using /proc/version_signature and dpkg/Built-Using;
Debian uses its uname -v build signature. Installed and loaded source versions remain
separate. A pending reboot is warned, never performed.

Beacon includes a versioned `product_policy` in the signed manifest. It contains
exact Homebrew core formula and application bundle identifiers, plus scoped CVE
exclusions for known patched builds and fixed upstream releases. A legacy feed
without this policy leaves these identities unchecked and reports the gap in
Coverage. Docker Desktop on macOS is an exception for older signed databases
that explicitly declare `nvd-cpe-docker-desktop-v1`. Ward can use that existing
coverage for the `com.docker.docker` release version. A published product policy,
when present, remains authoritative. Other inventory ecosystems use their own
matching rules.

The publisher defaults are in `internal/productid/defaults.json`. To publish
a modified catalog, pass `-product-policy PATH` to Beacon `sync` or `run`.
Refresh the NVD sources together when changing the policy, then export and
update the agent database. The agent binary can stay in place.

# Operations

All default runtime state/config/report paths are under the executing account's
`~/.shixpeer.ward/`, on Linux and macOS, including root. Changing HOME or using
sudo changes that account's storage. Explicit CLI overrides remain available.

| Content | Default |
|---|---|
| Agent settings | ~/.shixpeer.ward/config/agent.json |
| Agent DB/checkpoint | ~/.shixpeer.ward/agent/database/ |
| Reports/inventory | ~/.shixpeer.ward/agent/ |
| Resident logs | ~/.shixpeer.ward/logs/agent.log and .previous (4 MiB each) |
| Beacon state/cache/public files | ~/.shixpeer.ward/beacon/ |
| Beacon sources | ~/.shixpeer.ward/config/beacon.json |

See [Ubuntu deployment](ubuntu-deployment.ru.md) for complete commands, binaries,
trust bootstrap, separate publisher/HTTPS accounts and installation services.

## Agent commands

- setup: save URL/pinned public key, copy the CA into home config by default.
- update/pull (or no command): fetch signed manifest and changed immutable objects.
- scan: offline full supported collection/matching, console summary and reports.
- lookup: local bounded advisory/package/risk query, not a host verdict.
- collect: minimal OS/kernel snapshot (diagnostic prototype; use scan for full data).
- run: initial update then full report, independent periodic report/update loops;
  defaults are 15-minute reports and one-minute manifest polling; the installer uses hourly reports.
  A failed pass logs an error and the process continues. Logs stay in home, bounded.
- migrate-home: explicitly copy legacy settings/state/checkpoint into home defaults;
  original files remain as backup. It does not bypass signature/expiry/rollback.

Run setup/update/scan as the same account. For installed agents view resident reports
with `tail -f ~/.shixpeer.ward/logs/agent.log`; journalctl is for service lifecycle
and fatal startup failures. Reboot persistence comes from the enabled systemd unit,
not a cron script. Services use a non-root user; unavailable observations stay explicit.

## Beacon roles

The Ubuntu installer uses shixpeer-ward-beacon for upstream ingestion/signing and shixpeer-ward-serve
for read-only HTTPS. Each uses its own home root; the HTTPS worker gets ACL traversal
and public-artifact read access only, plus its separate TLS private key. It cannot
read CA/signing keys or modify artifacts. A oneshot sync service and persistent
six-hour timer normalize/export; the public HTTP service remains responsive while
imports run. Existing source failures retain the last successful state; failed or
stale source checks block publication. No PostgreSQL/SQLite/external DB is involved.

`beacon release` publishes signed, expiring, content-addressed Linux agent binaries
and an installer. Independently pin installer SHA256 before running it, then trust
the provisioned public key or SPKI SHA256. Agent installation is an explicit admin
action, not automatic code updates. No installer adds Docker group membership,
changes firewall/SSH or updates installed application packages.

The files under packaging/systemd are reference units for /home/shixpeer-ward-* defaults;
installation scripts generate actual paths/users. The optional agent-pull timer
must not be enabled alongside the resident updater. See the deployment guide for
first import, status, manual runs, source configuration and migration.

Runtime reports/private keys must never be published. HTTP whitelists only signed
database files and explicit installer assets, never snapshots/reports or *.key.
An expired DB cannot be used for a new successful scan. Fix synchronization/clock
and run update; do not remove checkpoints or disable verification.

Resident retries failed database synchronization within one minute (or the shorter
configured interval); changed database objects request an immediate new
report. Scans remain serialized, so downloads never create concurrent report writers.

Manifest polling uses If-None-Match with an ETag derived from the signed envelope.
Unchanged publications return 304 without a body; older mirrors can return the
manifest normally. Only missing/changed content-addressed objects are downloaded.
A signature renewal without changed objects updates freshness but does not trigger
a scan. Scheduled scans remain independent.

# Update an installed Shixpeer Ward

Commands from a Mac run from the project root. Use the same SSH hosts, ports
and HTTPS address as the first installation. Updating system packages,
rebooting Ubuntu, deleting the database or changing keys is not required.
Ukrainian: [ubuntu-update.uk.md](ubuntu-update.uk.md).

1. Build the archive:

   ```bash
   make ubuntu-bundle
   ```

2. When the current Beacon import has finished, update Beacon from the Mac:

   ```bash
   bash packaging/shixpeer-ward-deploy-beacon.sh BEACON_SSH_HOST https://BEACON_HOST:8443
   ```

   For a non-default SSH port use `BEACON_SSH_HOST:PORT`. Reinstallation uses
   the existing accounts, settings, CA, signing key and database. The Ward
   HTTPS service restarts. The installer publishes signed binaries and starts
   a background import. The previous publication stays available while it is
   still valid. Rules are rebuilt because normalization changed. Unchanged
   archives can be taken from the cache.

3. Repeat the agent installation command for each server:

   ```bash
   bash packaging/shixpeer-ward-deploy-agent.sh BEACON_SSH_HOST AGENT_SSH_HOST https://BEACON_HOST:8443
   ```

   Both SSH ports are optional and independent. The command keeps the database
   and checkpoint for the same user and replaces the verified binary. The
   agent service restarts, then runs update and a new scan. An existing valid
   database is kept. A new Beacon answers 304 when the manifest is unchanged.
   An older Beacon stays compatible and returns the whole manifest.

4. Check on the agent server as root:

   ```bash
   /home/shixpeer-ward-agent/.shixpeer.ward/bin/shixpeer-ward-agent version
   tail -F /home/shixpeer-ward-agent/.shixpeer.ward/logs/agent.log
   ```

   The expected version is `0.4.8-dev`. After `scan: complete`, open
   `/home/shixpeer-ward-agent/.shixpeer.ward/agent/report.md`. If the service
   uses another user, use that user's HOME.

## Parallel downloads on Beacon

For this change, steps 1 and 2 are enough. By default Beacon prepares up to
three sources at once and keeps at most three HTTP downloads, including
downloads of individual NVD years. Normalization runs one source at a time.
The limit from 1 to 8 is the `-source-workers` flag. For an installed service,
change it with `systemctl edit shixpeer-ward-beacon-sync.service`:

```ini
[Service]
Environment=SHIXPEER_WARD_SOURCE_WORKERS=2
```

The setting applies on the next import.

## How to read the new report

- `omitted_findings` is how many details were left out because of the output
  limit. The summary counters include them. This is not a scan error. Look
  separately at the number of completed and incomplete components.
- An Ubuntu OSV record without an applicable fix boundary can mean either a
  known vulnerability or a status that still needs assessment. Those records
  need review, not an update command. See the
  [Ubuntu OSV format](https://documentation.ubuntu.com/security/security-updates/osv/).
- For reboot, the report shows the running and installed kernel versions and
  the packages from the Ubuntu marker when they are available. The marker
  itself does not prove that a kernel update is what is required.
- Ports show local binds. To check owners and Docker, an administrator can
  separately run, as root:

  ```bash
  ss -lntup
  docker --host unix:///var/run/docker.sock ps --format 'table {{.Names}}\t{{.Image}}\t{{.Ports}}'
  ```

  Do not add the Ward daemon to the docker group for the sake of the report.
  Check external reachability from an allowed external point, taking firewall
  and NAT into account.

## Update data only, without installing a new version

Beacon updates sources on a timer. The agent downloads changed parts by
itself. To update manually, on Beacon as root:

```bash
systemctl start shixpeer-ward-beacon-sync.service
```

After a successful publication, on the agent server as root:

```bash
runuser -u shixpeer-ward-agent -- env HOME=/home/shixpeer-ward-agent /home/shixpeer-ward-agent/.shixpeer.ward/bin/shixpeer-ward-agent update
runuser -u shixpeer-ward-agent -- env HOME=/home/shixpeer-ward-agent /home/shixpeer-ward-agent/.shixpeer.ward/bin/shixpeer-ward-agent scan
```

`update` refreshes only the database. To update Ward itself, use the first
three steps. None of these commands installs OS fixes.

## Automatic Docker snapshot

After the agent is updated, the installer enables a separate systemd collector.
It captures local Docker metadata before the agent starts and every five
minutes. The agent service reads the snapshot from its state directory. The
collector state is visible with
`journalctl -u shixpeer-ward-agent-capture.service`.

### Firewall verdicts and Ubuntu VEX

When Beacon is updated with the standard Canonical OSV profile, the installer
enables the accompanying Ubuntu VEX. An explicitly configured or disabled VEX
source is preserved. The agent narrows ambiguous OSV records by an exact match
of source package, version and release codename. When there is no match, or
the records conflict, the entry stays in review. Installed-package data stays
local.

The same timer automatically collects the dpkg database of Debian/Ubuntu
containers, listeners and firewall rules. **Local ingress firewall** shows
verdicts for new incoming packets on interface addresses that have a default
route. For Docker DNAT it shows the original port, the translated port and the
FORWARD path. iptables/UFW and simple nftables INPUT/FORWARD filters are
supported. Unsupported conditions, or missing data, produce UNKNOWN. External
reachability also depends on the external network and the return path. The
collector reads state and does not change rules.

Ubuntu verdicts use the nftables, iptables and iproute2 already installed. If
a required utility is missing, the report names the coverage gap.

In 0.4.7-dev the report also shows review separately for the running kernel,
host packages and applications, and containers. Package OVAL applies to Ubuntu
22.04: the agent compares the installed binary package and its dpkg version
with a supported Canonical rule. For confirmed findings that have no fix
version, the agent looks for a related USN for the same CVE, release and
source package. Markdown and JSON name that USN. Update Beacon and the agent
for these capabilities.

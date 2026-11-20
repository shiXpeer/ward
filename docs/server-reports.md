# Server reports in Ward

Servers → Automatic sync checks configured report relays at launch and every five
minutes while Ward is running. The switch is saved locally. Sync reports performs
an immediate check even with automatic sync disabled. Only configured HTTPS relay
origins are contacted; redirects, relay authentication and envelope verification
remain mandatory. No scan or package update is executed remotely.

Each server is identified by `(Beacon UUID, server_id)`; its displayed hostname and
OS come from its report. Separate relays may use the same server ID. New servers
appear when the relay lists their first uploaded report. A successful empty relay
list means “waiting for reports”, not “servers are safe”.

Ward stores authenticated, decrypted JSON reports locally under
`~/.shixpeer.ward/macos/server-reports/`, with private directory/file permissions.
The atomic catalog contains receipt times, report timestamps, checksums, expected
intervals and sync outcomes. Report files are checked against SHA-256 before use.
Up to 64 servers, 20 distinct received reports per server and 256 MiB of report
content are retained. Older history is pruned first, preserving each server's
latest report. If latest reports alone exceed the limit, saving fails visibly.
Repeated content does not create another history row; an older report never
replaces a newer one. History and last sync errors survive a Ward restart.

**Current relay limitation:** `/v1/reports/{id}` exposes the latest uploaded
report only. Ward's history starts with reports it receives. Reports overwritten
on the relay before Ward fetches them (including while Ward is closed) cannot be
recovered. Relay-side historical delivery is a separate future protocol extension.

Status describes delivery, not security:

- Report current: the latest scan timestamp is within twice the expected interval.
- Report overdue: that threshold has passed (minimum threshold ten minutes).
- Sync error: fetching, authentication, decoding or saving failed, or a previously
  known server is absent from the relay list. Saved reports remain available.
- Incomplete scan coverage is shown separately from delivery status and findings.

Expand a server card for history, Open / Save JSON and Expected scan interval.
The interval controls only the overdue indicator; it does not reconfigure the
server agent. Open latest shows the standard read-only report browser, with a
Servers button to return. Existing new-findings notification preferences also
apply to new findings in subsequently received server reports; the first report
is the baseline.

## Verification

1. Configure a Beacon with a report relay and reader token; open Servers.
2. Deliver one fresh encrypted report with the configured agent, then click
   Sync reports. Confirm server ID, hostname, OS, report time and counts.
3. Sync the same report again: history count must not increase.
4. Deliver a new scan, leave Ward running and wait up to five minutes. Expand the
   server: both received versions should be available. Open an older version,
   return using Servers and export it with Save JSON.
5. Restart Ward. Saved reports/history should be available even if the relay is
   unreachable. Click Sync reports with the relay stopped: show a connection error
   without deleting history. Restart the relay and sync: the error should clear.
6. Choose the correct expected interval. A report older than two intervals should
   be marked overdue. Changing this picker must not change the agent service.
7. Turn Automatic sync off: only an explicit Sync reports should fetch reports.

Developer checks (macOS): `bash apps/macos/test-server-reports.sh`; Go transport
and relay regression tests: `make check`. These tests use synthetic local data,
not production inventories, credentials or external services.

## One-command agent installation (enrollment v1)

In Servers → Connect a Server choose a configured Beacon/relay, a new server ID and
scan interval. Paste the `WARD-RELAY-1:` connection code printed by relay setup
and confirm the displayed relay address. Ward verifies HTTPS using the included
public certificate, stores access tokens in Keychain, and scopes certificate trust
to this relay. No system trust changes or certificate transfer are needed.
In Install and connect create the command; credentials and certificate are filled
automatically. Legacy manual connections can still enter tokens/CA separately.
Copy/paste the installation command into the
Linux server terminal. It requests sudo, installs the signed Linux agent under the
existing restricted service account, enrolls it, writes private upload settings and
enables/restarts systemd. No manual JSON or unit override is required. The first
report follows the initial signed database sync. Verify Report checks freshness
against command creation time, then Open Report opens the received scan.

The generated command expires after 15 minutes. It contains only public trust
material and an enrollment capability, never the reader/management token or Ward's
private report key. Root-executed bootstrap shell code is embedded from the Ward
build; no remote shell script is executed. Linux binaries are downloaded from the
selected Beacon and checked against the existing signed release, trusted feed key,
expiry/digests and installed rollback checkpoints. HTTPS validation is never
skipped. Installation requires Linux amd64/arm64, systemd and the standard installer
prerequisites (curl, OpenSSL, system tools). It does not install host dependencies,
update other software or change firewall rules.

### One-time infrastructure upgrade

Existing relay/agent binaries predate enrollment. Update them before testing:

1. On the relay host, update the trusted checkout and rerun the existing command:

   ```sh
   bash packaging/shixpeer-ward-prepare-relay.sh --hostname relay.example.com --port 8444
   ```

   Supply the same hostname/port (or existing certificate/key arguments). The script
   preserves reader/static writer credentials, adds a separate `enrollment_token`
   and restarts the service. Retrieve that management token in your trusted SSH
   session and paste it into Ward (do not copy it to an agent):

   ```sh
   "$HOME/.shixpeer.ward/bin/shixpeer-ward-relay" enrollment-token \
     -config "$HOME/.shixpeer.ward/relay.json"
   ```

2. Publish freshly built Linux agents using your existing Beacon signing key and
   release process. `make ubuntu-bundle` produces the updated deployment bundle;
   the existing Beacon install/upgrade process publishes signed agent artifacts.
   If publishing from a source checkout directly on the Beacon host, use your
   actual output/key paths, for example under the publisher account:

   ```sh
   mkdir -p "$HOME/.shixpeer.ward/releases"
   CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath \
     -o "$HOME/.shixpeer.ward/releases/shixpeer-ward-agent-linux-amd64" ./cmd/shixpeer-ward-agent
   CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath \
     -o "$HOME/.shixpeer.ward/releases/shixpeer-ward-agent-linux-arm64" ./cmd/shixpeer-ward-agent
   go run ./cmd/shixpeer-ward-beacon release \
     -state "$HOME/.shixpeer.ward/beacon" -binaries "$HOME/.shixpeer.ward/releases" \
     -signing-key "$HOME/.shixpeer.ward/pki/signing.key"
   ```

   No key is rotated or exported. The installer rejects old signed agents lacking
   `enroll` support before creating the service account or replacing a running
   executable. These infrastructure upgrades are not deployed remotely by Ward.

### Protocol and recovery

`POST /v1/enrollments` requires the management token and binds a ticket to server ID
and recipient public key. Reader/writer tokens cannot create enrollments. Ticket
redemption at `POST /v1/enrollments/redeem` returns only that server's writer token.
TLS is mandatory; a different installation cannot reuse a claimed ticket. A local
private nonce checkpoint allows the **same installation** to retry a lost response
until expiry. Existing matching upload settings make repeated installs idempotent;
settings for another server/recipient are never silently overwritten. Creating a
new unclaimed ticket invalidates the previous pending ticket for that ID. Existing
registered IDs are not overwritten; choose a different ID rather than rotating
another server's credentials. There is no remote command execution API.

Relay enrollment state uses a private, atomic, bounded `enrollment-v1.json` file in
the relay report state directory (64 registered/pending entries). It survives a
restart and must be preserved with the private relay config during maintenance.
Do not publish that directory. Turning enrollment management off removes the API
but preserves existing report-writer credentials.

### Installation verification

1. Complete the infrastructure upgrade above once. In Ward create a command for a
   **new** server ID, then paste it into the target Linux server terminal.
2. Confirm `systemctl is-active shixpeer-ward-agent` and
   `systemctl is-enabled shixpeer-ward-agent`. Use `journalctl -u
   shixpeer-ward-agent -n 50 --no-pager` for startup errors; collection/update logs
   remain under the service user's `~/.shixpeer.ward/logs/agent.log`.
3. Click Next → Verify Report after the initial database sync/scan. Open Report;
   the server should also appear automatically in Servers with saved history.
4. Re-run the same command before expiry: it should keep the writer credential and
   restart the service without creating a second server. Reboot the target and
   check that a new scheduled report arrives. A different host cannot redeem the
   already claimed command.
5. Keep Ward running with automatic sync enabled. Subsequent distinct reports are
   added to local history. Stopping the agent should eventually mark the report
   overdue, without deleting history.

### Compact relay setup

Relay setup in Ward now generates one copyable command from hostname, port and
optional existing certificate/key paths. With Repository already cloned switched
off it includes clone, cd and the setup script in one `&&` chain. Otherwise run
it in the existing checkout:

```sh
bash packaging/shixpeer-ward-prepare-relay.sh --hostname relay.example.com --port 8444
```

The script builds the relay, creates/reuses TLS and tokens, enables lingering
(startup after logout/reboot, requesting sudo if needed), starts the user service,
and verifies authenticated HTTPS. Only then it prints one private connection
code for Servers → Connect a Server. The versioned code contains the HTTPS origin,
reader/enrollment credentials and public certificate, never the TLS private key.
It is an encoded secret, not encryption: copy it through your authenticated server
terminal and keep it private. Existing credentials and encrypted report state are preserved. For an
existing TLS certificate add `--tls-cert /path/fullchain.pem --tls-key
/path/privkey.pem`; `--listen 127.0.0.1` restricts binding to loopback.
When Go 1.26.10+ is missing, setup downloads an official, pinned Go archive from
`go.dev` (redirects to `dl.google.com`), verifies its SHA-256, and uses it in a
temporary directory that is removed on exit. This supports Linux x86_64/arm64
and requires curl or wget. It does not install system packages or alter
network/firewall rules. The legacy positional syntax
remains supported.

Relay host fields accept DNS names, IPv4 and IPv6. The command preview follows
host/port edits immediately; Copy command confirms a successful clipboard write.
IPv6 HTTPS origins use brackets. Generated certificates use IP SAN and IP
verification for literal addresses, retaining normal DNS SAN/hostname verification
for DNS names. `python3 packaging/test-relay-options.py` covers argument parsing
and address/TLS selection without starting a service or changing the host.

Relay setup shows four short stages and ends with `SUCCESS` only after authenticated HTTPS verification, or `FAILED` with a reason. Detailed setup output is saved privately in `~/.shixpeer.ward/logs/relay-setup.log`. The existing-checkout command first pulls the latest repository version.

# Ubuntu: Beacon, agent installation and the first report

For Ubuntu 24.04 with systemd, amd64 or arm64. An administrator runs the
commands below. Developing on a Mac does not mean anything is already installed
on the servers. Project: https://shixpeer.com. The servers do not need Go; they
use prebuilt binaries. Ukrainian: [ubuntu-deployment.uk.md](ubuntu-deployment.uk.md).

## Quick path from a Mac

The archive is `dist/shixpeer-ward-ubuntu.tar.gz` (rebuild with
`make ubuntu-bundle`). For a new Beacon that has `acl` installed:

```bash
bash packaging/shixpeer-ward-deploy-beacon.sh BEACON_SSH_HOST https://BEACON_HOST:8443
```

Skip that step when Beacon is already installed. After the first successful
publication, run one command for each agent server:

```bash
bash packaging/shixpeer-ward-deploy-agent.sh BEACON_SSH_HOST AGENT_SSH_HOST https://BEACON_HOST:8443
```

Both SSH hosts accept an optional port, for example `beacon.example.org:2222`
and `agent.example.org:2200`. Without a port, OpenSSH settings apply. The HTTPS
address is the last argument and is independent of the SSH port.

Use SSH keys and known_hosts entries for both hosts that were checked in
advance. The agent host needs curl and OpenSSL. The scripts do not change SSH
or the firewall. The manual path below is for diagnosis and for cases without
direct SSH access.

## What is checked

The agent locally collects installed dpkg packages and source-package versions,
the OS, kernel, services, listening TCP/UDP sockets and available process
owners, metadata of running Docker containers and their published ports, and
global npm/Python packages. Supported rules are matched against the signed
local database. Nothing from the inventory is sent to Beacon. Every agent
receives the same database.

A running Ubuntu kernel uses `/proc/version_signature`. Debian uses the
supported build signature from `uname -v`. For signed Ubuntu images the source
package comes from Built-Using. The installed package version is not
substituted for the running kernel version. When they cannot be linked, the
result is UNRESOLVED or NOT_CHECKED. `/var/run/reboot-required` and a known lag
of the running version are warnings: an update may still require a reboot.

This is a partial scanner. Unknown products, complex CVE conditions, packages
inside containers, project lockfiles and virtualenvs, and unsupported version
schemes stay explicitly unchecked. A port cannot be "updated": the report shows
the bind and the owner, and external reachability depends on firewall, NAT and
cloud rules. If ss/iproute2 is missing, `/proc/net` tables are read without
owner attribution. There is no check from outside the host. A version-rule
match is a reason to review the advisory and the update, not proof of
exploitation. There is no automatic OS or software update, reboot, UFW,
firewall or SSH change, or `docker exec`.

## Where data lives

By default all Ward state is in the HOME directory of the **process user**:

```text
~/.shixpeer.ward/
  bin/                      installed binaries and helper scripts
  config/agent.json         Beacon address, public key, data directory
  config/ca.crt             trusted public CA, when private HTTPS is used
  agent/database/           signed local database and rollback checkpoint
  agent/snapshot.json       local snapshot
  agent/report.md           readable report
  agent/report.json         full report and evidence
  beacon/                   publisher state, cache and public database (on Beacon)
  pki/                      keys only on the matching server and user
  releases/                 Linux binaries served to agents (on Beacon)
  logs/agent.log            daemon report log, up to 4 MiB plus the previous file
```

A normal run uses the current user's HOME. `sudo -H` uses `/root`. The daemon
does not run as root. `--user ubuntu` uses `/home/ubuntu/.shixpeer.ward/`. The
installer account `shixpeer-ward-agent` uses
`/home/shixpeer-ward-agent/.shixpeer.ward/`. Databases and reports are not
stored in the checkout, `/var/lib`, or next to the sources. systemd unit files
are installed in `/etc/systemd/system`. The service journal is kept by systemd.
Short daemon reports are written to `logs/agent.log` in the home directory, not
to the journal. `-state`, `-config` and `-report-dir` remain explicit overrides.

## 1. Build the archive on the development machine

From the repository root:

```bash
make check
make ubuntu-bundle
```

This produces `dist/shixpeer-ward-ubuntu.tar.gz`: both applications for Linux
amd64 and arm64, source settings and the Beacon installer. `dist/` is excluded
from the repository. This is a development build; do not present it as a
published stable release.

## 2. Prepare a separate Beacon server

In the examples, `BEACON_HOST` is your real DNS name or IPv4 address. A stable
internal address is convenient on a private network; the TLS certificate is
created for that name. The installer uses port 8443. There is no public
official Ward endpoint by default.

On Beacon, create a directory for the archive:

```bash
install -d -m 700 "$HOME/.shixpeer.ward/bootstrap"
```

From the Mac, copy the archive over SSH after the host key has been verified:

```bash
scp dist/shixpeer-ward-ubuntu.tar.gz root@BEACON_HOST:/root/.shixpeer.ward/bootstrap/
```

Then **on Beacon, as root**:

```bash
apt-get update
NEEDRESTART_MODE=l apt-get install --no-upgrade -y ca-certificates curl openssl acl
cd "$HOME/.shixpeer.ward/bootstrap"
tar -xzf shixpeer-ward-ubuntu.tar.gz
bash ubuntu/packaging/shixpeer-ward-install-beacon.sh --origin https://BEACON_HOST:8443
```

If a needrestart window is already open, clear every checkbox with the space
bar, scroll the whole list and confirm the empty selection. `NEEDRESTART_MODE=l`
only lists services. It does not control the package scripts' own actions.

The installer creates two unprivileged accounts:

- `shixpeer-ward-beacon` downloads sources, normalizes them and signs the
  publication. Data is in `/home/shixpeer-ward-beacon/.shixpeer.ward/`.
- `shixpeer-ward-serve` only serves the published files over HTTPS. It has its
  own HOME and TLS key. An ACL lets it read `public`, and does not let it read
  the signing key, the private CA or the raw caches.

It creates the HTTPS service and a separate oneshot service and timer for
updates. The timer repeats synchronization 6 hours after the previous pass
finishes, and it starts again after reboot. The first import starts
asynchronously and can take a noticeable amount of time. The database is not
loaded entirely into RAM. The publisher's initial cache is substantially larger
than the agent database. Do not run the import every minute.

Check readiness:

```bash
journalctl -u shixpeer-ward-beacon-sync -f
```

After a successful finish, leave the pager with Ctrl+C:

```bash
systemctl status shixpeer-ward-beacon --no-pager
systemctl status shixpeer-ward-beacon-sync --no-pager
systemctl list-timers shixpeer-ward-beacon-sync.timer
runuser -u shixpeer-ward-beacon -- env HOME=/home/shixpeer-ward-beacon /home/shixpeer-ward-beacon/.shixpeer.ward/bin/shixpeer-ward-beacon status
```

After success the sync service may show `inactive (dead)`. That is normal for
a oneshot unit. Look at `Result=success` and the next timer run. A failed
import does not replace the last good database. Do not bypass the TTL of an
old database.

The installer does not change the firewall. TCP 8443 must be reachable by the
agents through your existing network rules; limit it to the addresses that need
it. Do not reset UFW or change SSH for this installation. HTTPS listens on
IPv4 and IPv6 when the OS supports it.

## One-command agent installation from a Mac

After Beacon's first successful import, from the project root:

```bash
bash packaging/shixpeer-ward-deploy-agent.sh BEACON_SSH_HOST AGENT_SSH_HOST https://BEACON_HOST:8443
```

Both SSH hosts must already be verified and known to OpenSSH. The connection
runs as root and does not forward an SSH agent. The last argument is the
address reachable from the agent server and present in the Beacon certificate.
The script sends only the public CA, the public signing key and the installer
over SSH. The installer then checks the signed release and downloads binaries
over HTTPS. Beacon's private keys stay on Beacon. Use the manual path below
when the Mac does not have SSH access to both servers.

## 3. Initial trust for agents, once

Do not download the CA from an unknown server and do not use `curl -k`.
You need the public CA and **two independently obtained fingerprints** from the
Beacon console: the signing public key (SPKI SHA256) and `install.sh` itself
(SHA256). The installer fingerprint still protects you if a compromised HTTPS
process replaces the script. Checking the binary signature inside a replaced
script is not enough.

Print the fingerprints again on a Beacon you trust:

```bash
runuser -u shixpeer-ward-beacon -- env HOME=/home/shixpeer-ward-beacon /home/shixpeer-ward-beacon/.shixpeer.ward/bin/shixpeer-ward-beacon release -state /home/shixpeer-ward-beacon/.shixpeer.ward/beacon -binaries /home/shixpeer-ward-beacon/.shixpeer.ward/releases -signing-key /home/shixpeer-ward-beacon/.shixpeer.ward/pki/signing.key -release-ttl 720h
```

The CA is a public certificate, not a private key. Prepare it in the HOME of
your SSH user on Beacon, without granting access to private keys:

```bash
install -d -m 700 "$HOME/.shixpeer.ward/bootstrap"
runuser -u shixpeer-ward-beacon -- cat /home/shixpeer-ward-beacon/.shixpeer.ward/pki/ca.crt > "$HOME/.shixpeer.ward/bootstrap/beacon-ca.crt"
```

On each agent server, prepare the directory once and copy that file over
authenticated SSH, after checking Beacon's host key:

```bash
install -d -m 700 "$HOME/.shixpeer.ward/bootstrap"
scp root@BEACON_HOST:/root/.shixpeer.ward/bootstrap/beacon-ca.crt "$HOME/.shixpeer.ward/bootstrap/ca.crt"
```

Do not send `ca.key`, `signing.key` or `server.key` to agents. If you use your
own public CA certificate instead of the generated private one, the local CA
file and `--cacert` / `--ca-file` are unnecessary, but the independent
fingerprints are still required.

## 4. Install the agent: two commands after trust is prepared

Replace `BEACON_HOST`, `INSTALLER_SHA256` and `FEED_KEY_SHA256` with the
trusted values from the previous steps. By default the installer creates a
separate minimal user `shixpeer-ward-agent`, a service and that user's home
directory:

```bash
curl --fail --show-error --proto '=https' --tlsv1.2 --noproxy '*' --user-agent Shixpeer-Ward-Installer/1 --cacert "$HOME/.shixpeer.ward/bootstrap/ca.crt" https://BEACON_HOST:8443/install.sh -o "$HOME/.shixpeer.ward/bootstrap/install-agent.sh" && printf '%s  %s\n' 'INSTALLER_SHA256' "$HOME/.shixpeer.ward/bootstrap/install-agent.sh" | sha256sum -c -
```

```bash
bash "$HOME/.shixpeer.ward/bootstrap/install-agent.sh" --beacon https://BEACON_HOST:8443 --ca-file "$HOME/.shixpeer.ward/bootstrap/ca.crt" --key-sha256 FEED_KEY_SHA256
```

Run the second command **only after the first check succeeds**. The installer
checks the release Ed25519 signature, expiry, size and SHA256 of the binaries,
then creates settings and a systemd service. Both Linux builds are downloaded
with the same requests from every client. Architecture selection is local. A
fingerprint mismatch, a release conflict or a rollback to an older release is
rejected. There is no network redirect to another URL. Nothing is added to the
docker group, and the daemon has no sudo. If `--user` is omitted, the installer
creates the minimal unprivileged user `shixpeer-ward-agent` with HOME
`/home/shixpeer-ward-agent`. `--user "$USER"` is an explicit choice of your
current unprivileged user when you want that. The installer does not grant
extra groups. Do not change the user between installation and later runs: each
account has its own database and checkpoint.

The binary is not updated automatically. An administrator runs a later install
with a current script fingerprint. Database updates are separate and automatic.

## 5. The first report on Ubuntu

For the standard install with the dedicated `shixpeer-ward-agent` user:

```bash
systemctl status shixpeer-ward-agent --no-pager
journalctl -u shixpeer-ward-agent -n 50 --no-pager
runuser -u shixpeer-ward-agent -- tail -f /home/shixpeer-ward-agent/.shixpeer.ward/logs/agent.log
```

On startup the service tries to synchronize the database, then creates the
first report. After that the database manifest is checked once a minute and
the report once an hour. Pass errors are logged and the process stays up. The
report log is limited to two files of 4 MiB. Ctrl+C stops viewing the log. It
does not stop the service.

For an explicit console test:

```bash
runuser -u shixpeer-ward-agent -- env HOME=/home/shixpeer-ward-agent /home/shixpeer-ward-agent/.shixpeer.ward/bin/shixpeer-ward-agent update
runuser -u shixpeer-ward-agent -- env HOME=/home/shixpeer-ward-agent /home/shixpeer-ward-agent/.shixpeer.ward/bin/shixpeer-ward-agent scan
```

The console shows coverage, priority matches, uncertain records and warnings.
The full files:

```bash
less /home/shixpeer-ward-agent/.shixpeer.ward/agent/report.md
```

JSON is `/home/shixpeer-ward-agent/.shixpeer.ward/agent/report.json`. It
contains source versions, the source, conditions, the compared version and
recommendations. If you explicitly chose `--user "$USER"`, use your own HOME
without sudo:

```bash
"$HOME/.shixpeer.ward/bin/shixpeer-ward-agent" update
"$HOME/.shixpeer.ward/bin/shixpeer-ward-agent" scan
less "$HOME/.shixpeer.ward/agent/report.md"
```

Install commands run as root. When logged in as root, do not add
`--user "$USER"`: the installer creates `shixpeer-ward-agent` itself. Do not
mix root and a normal HOME. If you need a separate manual privileged audit,
configure a root agent on its own with `sudo -H`. Data will be in
`/root/.shixpeer.ward/`. That is an administrator's explicit decision, not
installer behavior. Without root, some PIDs, services and containers stay
unavailable.

## 6. Change sources and intervals

Beacon sources live in
`/home/shixpeer-ward-beacon/.shixpeer.ward/config/beacon.json`. The list already
contains the default Ubuntu, Debian, macOS, NVD, CVE/GHSA, KEV/EPSS and
supported language-ecosystem sources. Supported adapters can be disabled or
added. An arbitrary unsupported JSON format cannot be substituted. A missing
source does not mean there are no vulnerabilities.

Update now:

```bash
systemctl start shixpeer-ward-beacon-sync.service
```

Change intervals through systemd overrides. After editing a unit or override,
run `systemctl daemon-reload` and restart the service or timer you changed.
Agent flags: `run -feed-interval 1m -collect-interval 1h`. Do not delete
binaries, keys or config while clearing a database: the checkpoint protects
against rollback. Do not publish agent reports through Beacon. It serves only
the allowed public artifacts.

## 7. Move an old local installation

Before changing the location, stop the old agent if it is running. With the
new binary, **as the previous user**:

```bash
bin/shixpeer-ward-agent migrate-home
```

For a non-default location:

```bash
bin/shixpeer-ward-agent migrate-home -from-config /absolute/path/to/old/agent.json
```

The command copies settings, the public CA, the database, the checkpoint and
reports into the new HOME. Old files are kept as a backup. After you have
checked the new installation, you can delete or move them manually. A repeated
migration does not overwrite existing trust. A link to the old CA is replaced
by a copy in the home directory. An expired database stays expired. After
migration you need `update`, not a bypass of the time check.

## Diagnosis

- `snapshot HTTPS request failed`: check that Beacon is running, the address
  and port, reachability from the agent network, that DNS or IP matches the
  certificate, and that the CA is trusted.
- 404 on the manifest: the first import has not finished, or it failed.
- Expired database: fix the import, network or clock, then update. Do not
  disable the signature or the TTL.
- Many NOT_CHECKED results: read the reasons, permissions and coverage. This
  is not a list of safe software.
- Containers are missing: there is no access to the local Docker socket. The
  installer deliberately does not grant effective root through the docker group.
- The service does not start: `journalctl -u NAME -n 100 --no-pager`.

The release archive and installers are checked locally. Installation on your
real servers is done by you. See also [scanner coverage](scanning.md),
[trust boundaries](trust.md), the
[OpenSSL documentation](https://docs.openssl.org/3.0/man1/openssl-pkeyutl/)
and the [systemd sandbox](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html).

After a synchronization error the agent retries within a minute, or sooner
when a shorter interval is configured. A background update that changes
database files immediately requests a new report. An unchanged manifest, or a
publication expiry extension that does not change files, does not start an
unscheduled scan. Scans are sequential. There are no competing report writers.
After changing agent settings with `setup`, restart its service: configuration
is read at startup and is not changed remotely while it runs.

## When Beacon was installed under the old names

A new installation does not need this step. For an existing installation, plan
a short interruption of HTTPS distribution. Back up the service home
directories, including keys and the database. As root, stop only the Ward
services:

```bash
systemctl stop shixpeer-ward-beacon-sync.timer shixpeer-ward-beacon-sync.service shixpeer-ward-beacon.service
```

If the new accounts and home directories do not exist yet, rename the old ones
and keep the UID, GID and ACL:

```bash
usermod -l shixpeer-ward-beacon -d /home/shixpeer-ward-beacon -m ward-beacon
groupmod -n shixpeer-ward-beacon ward-beacon
usermod -l shixpeer-ward-serve -d /home/shixpeer-ward-serve -m ward-serve
groupmod -n shixpeer-ward-serve ward-serve
```

Then run the new Beacon installer with the same `--origin`. It updates the
unit files and ACL and uses the moved keys. If the old and new accounts
already exist at the same time, do not merge the directories blindly.

For an agent installed under the old dedicated user, stop
`shixpeer-ward-agent.service`, rename the account the same way
(`ward-agent` to `shixpeer-ward-agent`, HOME to `/home/shixpeer-ward-agent`),
then repeat the installation with the checked new script and the same
publisher key. The installer updates path configuration. The database directory
and checkpoint stay in the moved HOME. Agents installed under an explicitly
chosen user do not need a rename.

For an existing installation see
[updating without resetting keys or the database](ubuntu-update.md).

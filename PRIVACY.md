# Shixpeer Ward privacy

Shixpeer Ward is developed by [shixpeer](https://shixpeer.com). Ward has no
central user account. The macOS app can check its own signed updates through Sparkle.

- **Agent:** Inventory and scan results stay on the host by default. Default
  state is under `~/.shixpeer.ward/` for the account running the process;
  operators can configure other paths. The agent fetches signed vulnerability
  data from the configured Beacon without sending the hostname, installed package
  list or versions. The Beacon can see ordinary request metadata such as IP and
  timing. An operator can explicitly configure encrypted report upload.
- **Beacon:** Fetches vulnerability data from configured sources. Upstream
  services can observe request metadata such as source IP and timing.
- **macOS app:** Reports remain local. Relay read tokens and report decryption keys
  are kept in macOS Keychain. Application version checks send public application
  identifiers, CPU architecture and declared update-channel metadata to the Ward
  backend. Installed versions, local paths and hostnames are not included. The
  backend fetches and parses vendor metadata and caches active public channels;
  it does not create device accounts or subscriber IDs. Ward polls for changed
  results while running. Installer archives come directly from vendors; their
  signatures, identities and available checksums are verified locally. Native
  macOS Software Update talks to Apple through the system service.
- **Optional update-failure diagnostics:** Off by default, with a choice in the
  first-run screen and Settings. Only unresolved bundle identifiers and one of
  two categories (unsupported channel/check failed) are submitted. No installed
  versions, URL, free-form error text, hostname, user/device/session ID or local
  path is included. The backend keeps bounded daily event counts for at most
  30 days plus an hourly retention sweep. Counts do not represent unique users.
  The client limits submissions per app/category/day and never queues failures
  offline. Raw request bodies and IPs are not stored in these counters. Network
  infrastructure necessarily processes connection metadata such as source IP;
  this feature does not provide network-layer anonymity. Internal bundle IDs
  can reveal the identity of private software; leave the option off if this is
  a concern. Counter access is restricted to server operators over SSH.
- **Optional relay:** An operator hosts it and controls access. It retains the
  latest encrypted report per configured server ID. It can see the server ID,
  upload time and ciphertext size, as well as ordinary connection metadata.
  Report contents are encrypted for the configured recipient. This version
  does not provide end-to-end sender signatures, replay protection or key recovery.

See the [macOS guide](apps/macos/README.md) for relay setup and limitations.

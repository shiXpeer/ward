# Shixpeer Ward privacy

Shixpeer Ward is developed by [shixpeer](https://shixpeer.com). Ward has no
central account, telemetry service or automatic self-updater.

- **Agent:** Inventory and scan results stay on the host by default. Default
  state is under `~/.shixpeer.ward/` for the account running the process;
  operators can configure other paths. The agent fetches signed vulnerability
  data from the configured Beacon without sending the hostname, installed package
  list or versions. The Beacon can see ordinary request metadata such as IP and
  timing. An operator can explicitly configure encrypted report upload.
- **Beacon:** Fetches vulnerability data from configured sources. Upstream
  services can observe request metadata such as source IP and timing.
- **macOS app:** Imported and retrieved reports remain in the app session.
  Relay read tokens and the report decryption key are kept in macOS Keychain.
  The Applications view and optional scheduled checks can contact third-party
  update sources or use an installed vendor updater to check availability.
  Installing a supported third-party update requires a user action and can
  prompt for administrator approval.
- **Optional relay:** An operator hosts it and controls access. It retains the
  latest encrypted report per configured server ID. It can see the server ID,
  upload time and ciphertext size, as well as ordinary connection metadata.
  Report contents are encrypted for the configured recipient. This version
  does not provide end-to-end sender signatures, replay protection or key recovery.

See the [macOS guide](apps/macos/README.md) for relay setup and limitations.

import Foundation
import CryptoKit

struct ServerEnrollmentCommand {
    struct Grant: Decodable {
        let token: String
        let expires_at: String
        var expiry: Date? {
            (try? Date.ISO8601FormatStyle(includingFractionalSeconds: true).parse(expires_at))
                ?? (try? Date.ISO8601FormatStyle().parse(expires_at))
        }
    }
    static func quote(_ value: String) -> String { "'" + value.replacingOccurrences(of: "'", with: "'\\''") + "'" }
    static func relaySetupCommand(hostname: String, port: String, existingCheckout: Bool,
                                  certificate: String = "", privateKey: String = "") -> String? {
        guard hostname.range(of: "^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$", options: .regularExpression) != nil,
              !hostname.contains(".."), hostname.range(of: "^[0-9.]+$", options: .regularExpression) == nil,
              let number = Int(port), (1024...65535).contains(number),
              certificate.isEmpty == privateKey.isEmpty else { return nil }
        var command = "bash packaging/shixpeer-ward-prepare-relay.sh --hostname " + quote(hostname) + " --port " + String(number)
        if !certificate.isEmpty {
            guard certificate.hasPrefix("/"), privateKey.hasPrefix("/"),
                  !certificate.contains("\n"), !privateKey.contains("\n"),
                  !certificate.contains("\r"), !privateKey.contains("\r") else { return nil }
            command += " --tls-cert " + quote(certificate) + " --tls-key " + quote(privateKey)
        }
        return existingCheckout ? command : "git clone https://github.com/shiXpeer/ward.git shixpeer.ward && cd shixpeer.ward && " + command
    }

    static func readPublicFile(_ path: String, maximum: Int) throws -> Data {
        let url = URL(fileURLWithPath: (path as NSString).expandingTildeInPath)
        guard (try url.resourceValues(forKeys: [.fileSizeKey]).fileSize ?? Int.max) <= maximum else {
            throw WardError("Public trust file is too large.")
        }
        return try Data(contentsOf: url)
    }
    static func build(installer: Data, feed: String, feedKey: Data, feedCA: Data?, relay: String,
                      relayCA: Data?, serverID: String, interval: String, recipient: String, grant: Grant) throws -> String {
        _ = try Wire.origin(feed)
        _ = try Wire.origin(relay)
        guard ServerReportArchive.validID(serverID), ["15m", "1h", "6h", "24h"].contains(interval),
              grant.token.range(of: "^[a-f0-9]{64}$", options: .regularExpression) != nil,
              let expiry = grant.expiry, expiry > Date(), expiry.timeIntervalSinceNow <= 1000,
              Data(base64Encoded: recipient)?.count == 32,
              installer.count > 0, installer.count <= 128 * 1024, feedKey.count <= 4096,
              String(data: feedKey, encoding: .utf8)?.contains("BEGIN PUBLIC KEY") == true else {
            throw WardError("Invalid enrollment command or public trust material.")
        }
        let enrollment = try JSONSerialization.data(withJSONObject: ["url": relay, "token": grant.token,
            "server_id": serverID, "recipient_public_key": recipient], options: [.sortedKeys])
        func material(_ data: Data, _ name: String) -> String {
            "printf %s " + quote(data.base64EncodedString()) + " | base64 --decode > \"$ward_tmp/" + name + "\""
        }
        // All executable bootstrap code comes from this Ward build, not a remotely
        // downloaded shell script. Signed Linux agent archives are still verified.
        var script = """
            set -euo pipefail
            umask 077
            export PATH=/usr/sbin:/usr/bin:/sbin:/bin
            command -v base64 >/dev/null
            [[ $(uname -s) == Linux ]] || { echo 'Linux with systemd required.' >&2; exit 1; }
            ward_tmp=$(mktemp -d)
            trap 'rm -rf -- "$ward_tmp"' EXIT
            """
        script += "\n" + material(installer, "install.sh") + "\n" + material(feedKey, "feed.pub")
        script += "\n" + material(enrollment, "enrollment.json")
        var options = " --beacon " + quote(feed) + " --trusted-key \"$ward_tmp/feed.pub\" --report-enrollment \"$ward_tmp/enrollment.json\" --collect-interval " + quote(interval)
        if let feedCA, !feedCA.isEmpty {
            script += "\n" + material(feedCA, "feed-ca.crt")
            options += " --ca-file \"$ward_tmp/feed-ca.crt\""
        }
        if let relayCA, !relayCA.isEmpty {
            script += "\n" + material(relayCA, "relay-ca.crt")
            options += " --relay-ca-file \"$ward_tmp/relay-ca.crt\""
        }
        script += "\nbash \"$ward_tmp/install.sh\"" + options
        // sudo authenticates on the terminal before execution; no secret is put in
        // a remote URL. The embedded ticket is short-lived and is write-only.
        let command = "sudo /bin/bash -c " + quote(script)
        guard command.utf8.count <= 96 * 1024 else {
            throw WardError("Trust certificate bundle is too large for one command. Select a smaller public CA certificate file.")
        }
        return command
    }
}

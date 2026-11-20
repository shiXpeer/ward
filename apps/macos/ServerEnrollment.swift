import Foundation
import CryptoKit
import Darwin

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
    static func relayHost(_ input: String) -> String? {
        var host = input.trimmingCharacters(in: .whitespacesAndNewlines)
        if host.hasPrefix("["), host.hasSuffix("]") { host = String(host.dropFirst().dropLast()) }
        var address4 = in_addr()
        var address6 = in6_addr()
        let ipv4 = host.withCString { inet_pton(AF_INET, $0, &address4) == 1 }
        let ipv6 = host.withCString { inet_pton(AF_INET6, $0, &address6) == 1 }
        if ipv4 || ipv6 { return host }
        guard host.count <= 253, !host.isEmpty,
              host.range(of: "^[0-9.]+$", options: .regularExpression) == nil,
              host.split(separator: ".", omittingEmptySubsequences: false).allSatisfy({ label in
                  label.count <= 63 && label.range(of: "^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?$", options: .regularExpression) != nil
              }) else { return nil }
        return host
    }
    static func relayOrigin(hostname: String, port: String) -> String? {
        guard let host = relayHost(hostname), let number = Int(port.trimmingCharacters(in: .whitespacesAndNewlines)),
              (1024...65535).contains(number) else { return nil }
        return "https://" + (host.contains(":") ? "[" + host + "]" : host) + ":" + String(number)
    }
    static func relaySetupPreview(hostname: String, port: String, existingCheckout: Bool,
                                  certificate: String = "", privateKey: String = "") -> String {
        let host = hostname.isEmpty ? "relay.example.com" : hostname
        let value = port.isEmpty ? "8444" : port
        var command = "bash packaging/shixpeer-ward-prepare-relay.sh --hostname " + quote(host) + " --port " + (Int(value).map(String.init) ?? quote(value))
        if !certificate.isEmpty { command += " --tls-cert " + quote(certificate) }
        if !privateKey.isEmpty { command += " --tls-key " + quote(privateKey) }
        return existingCheckout ? "git pull --ff-only --quiet && " + command : "git clone --quiet https://github.com/shiXpeer/ward.git shixpeer.ward && cd shixpeer.ward && " + command
    }
    static func relaySetupCommand(hostname: String, port: String, existingCheckout: Bool,
                                  certificate: String = "", privateKey: String = "") -> String? {
        guard let host = relayHost(hostname), let number = Int(port.trimmingCharacters(in: .whitespacesAndNewlines)),
              (1024...65535).contains(number), certificate.isEmpty == privateKey.isEmpty else { return nil }
        if !certificate.isEmpty {
            guard certificate.hasPrefix("/"), privateKey.hasPrefix("/"),
                  !certificate.contains("\n"), !privateKey.contains("\n"),
                  !certificate.contains("\r"), !privateKey.contains("\r") else { return nil }
        }
        return relaySetupPreview(hostname: host, port: String(number), existingCheckout: existingCheckout,
                                 certificate: certificate, privateKey: privateKey)
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

struct RelayConnectionCode: Decodable {
    let version: Int
    let origin: String
    let reader: String
    let enrollment: String
    let certificate: Data
    static func parse(_ input: String) throws -> RelayConnectionCode {
        let value = input.trimmingCharacters(in: .whitespacesAndNewlines)
        let prefix = "WARD-RELAY-1:"
        guard value.count <= 32768, value.hasPrefix(prefix),
              let raw = Data(base64Encoded: String(value.dropFirst(prefix.count))) else {
            throw WardError("Paste the connection code printed by relay setup.")
        }
        let code = try JSONDecoder().decode(Self.self, from: raw)
        guard code.version == 1, code.reader.utf8.count >= 32, code.enrollment.utf8.count >= 32,
              code.reader != code.enrollment, !code.certificate.isEmpty, code.certificate.count <= 16384,
              let url = URLComponents(string: code.origin), url.scheme == "https", url.host != nil,
              url.user == nil, url.password == nil, url.query == nil, url.fragment == nil,
              url.path.isEmpty || url.path == "/" else { throw WardError("Invalid relay connection code.") }
        return code
    }
    var certificatePEM: Data {
        Data(("-----BEGIN CERTIFICATE-----\n" + certificate.base64EncodedString(options: .lineLength64Characters) + "\n-----END CERTIFICATE-----\n").utf8)
    }
}

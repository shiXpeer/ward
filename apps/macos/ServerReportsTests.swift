import Foundation
import CryptoKit

@main struct ServerReportsTests {
    static func fixture(_ date: Date, name: String = "fixture-server") throws -> Data {
        try JSONSerialization.data(withJSONObject: [
            "format_version": 1, "generated_at": date.ISO8601Format(), "hostname": name,
            "status": "complete", "confirmed": 0, "requires_review": 0,
            "findings": [], "coverage": [],
            "inventory": ["host": ["os": "linux", "architecture": "x86_64"]]
        ], options: [.sortedKeys])
    }
    static func rejects(_ action: () async throws -> Void) async throws {
        do { try await action() } catch { return }
        throw WardError("Expected operation to be rejected")
    }
    static func main() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let archive = ServerReportArchive(root: root)
        let beacon = UUID()
        let now = Date(timeIntervalSince1970: 1_800_000_000)
        _ = try await archive.load()
        let ids = try ServerReportArchive.relayIDs(Data("[\"a\",\"b\"]".utf8))
        precondition(ids == ["a", "b"])
        try await rejects { _ = try ServerReportArchive.relayIDs(Data("[\"a\",\"a\"]".utf8)) }
        try await rejects { _ = try ServerReportArchive.relayIDs(Data("[\"../bad\"]".utf8)) }
        try await rejects { _ = try ServerReportArchive.relayIDs(JSONEncoder().encode((0...64).map { "s" + String($0) })) }
        let raw = try fixture(now)
        let recipient = Curve25519.KeyAgreement.PrivateKey()
        let ephemeral = Curve25519.KeyAgreement.PrivateKey()
        let shared = try ephemeral.sharedSecretFromKeyAgreement(with: recipient.publicKey)
        let key = shared.hkdfDerivedSymmetricKey(using: SHA256.self, salt: Data(),
            sharedInfo: Data("shixpeer-ward/report/v1".utf8), outputByteCount: 32)
        let sealed = try AES.GCM.seal(raw, using: key, authenticating: Data("test-01".utf8))
        let envelope = Data([1]) + ephemeral.publicKey.rawRepresentation + sealed.combined!
        let opened = try Wire.open(envelope, id: "test-01", key: recipient)
        precondition(opened == raw)
        try await rejects { _ = try Wire.open(envelope, id: "another-server", key: recipient) }
        try await rejects { _ = try Wire.open(envelope, id: "test-01", key: Curve25519.KeyAgreement.PrivateKey()) }
        let (first, _) = try await archive.accept(raw, beaconID: beacon, serverID: "test-01", now: now)
        precondition(first.servers.count == 1 && first.servers[0].snapshots.count == 1)
        let (duplicate, _) = try await archive.accept(raw, beaconID: beacon, serverID: "test-01", now: now)
        precondition(duplicate.servers[0].snapshots.count == 1)
        for i in 1...25 {
            _ = try await archive.accept(fixture(now.addingTimeInterval(Double(i))), beaconID: beacon, serverID: "test-01", now: now.addingTimeInterval(100))
        }
        let reloaded = ServerReportArchive(root: root)
        var saved = try await reloaded.load()
        precondition(saved.servers[0].snapshots.count == 20)
        let snapshotFiles = FileManager.default.enumerator(at: root, includingPropertiesForKeys: nil)!.allObjects.compactMap { $0 as? URL }.filter { $0.pathExtension == "json" && $0.lastPathComponent != "catalog.json" }
        precondition(snapshotFiles.count == 20)
        let (_, newest) = try await reloaded.accept(fixture(now.addingTimeInterval(-100)), beaconID: beacon, serverID: "test-01", now: now)
        precondition(newest.generated_at == now.addingTimeInterval(25).ISO8601Format(), "Old report replaced latest")
        saved = try await reloaded.load()
        let server = saved.servers[0]
        precondition(!server.stale(at: now.addingTimeInterval(7000)))
        precondition(server.stale(at: now.addingTimeInterval(7300)))
        saved = try await reloaded.setInterval(serverID: server.id, seconds: 21600)
        precondition(!saved.servers[0].stale(at: now.addingTimeInterval(7300)))
        saved = try await reloaded.finish(beaconID: beacon, ids: nil, errors: [:], error: "Connection failed", now: now)
        precondition(saved.relays[beacon.uuidString]?.error == "Connection failed" && saved.servers.count == 1)
        saved = try await reloaded.finish(beaconID: beacon, ids: [], errors: [:], error: nil, now: now)
        precondition(saved.servers[0].error != nil && saved.servers[0].snapshots.count == 20)
        try await rejects { _ = try await reloaded.accept(raw, beaconID: beacon, serverID: "../escape", now: now) }
        try await rejects { _ = try await reloaded.accept(Data("{}".utf8), beaconID: beacon, serverID: "bad", now: now) }
        try await rejects { _ = try await reloaded.accept(fixture(now.addingTimeInterval(301)), beaconID: beacon, serverID: "bad", now: now) }
        try await rejects { _ = try await reloaded.setInterval(serverID: server.id, seconds: 0) }
        let latest = saved.servers[0].latest!
        let path = root.appendingPathComponent(beacon.uuidString).appendingPathComponent("test-01").appendingPathComponent(latest.id + ".json")
        var damaged = try Data(contentsOf: path)
        damaged[0] = 0
        try damaged.write(to: path)
        try await rejects { _ = try await reloaded.read(server, snapshot: latest.id) }
        _ = try await reloaded.accept(fixture(now.addingTimeInterval(25)), beaconID: beacon, serverID: "test-01", now: now.addingTimeInterval(100))
        _ = try await reloaded.read(server, snapshot: latest.id)
        let permissions = try FileManager.default.attributesOfItem(atPath: path.path)[.posixPermissions] as! NSNumber
        precondition(permissions.intValue == 0o600)
        try Data("invalid".utf8).write(to: root.appendingPathComponent("catalog.json"))
        let corrupt = ServerReportArchive(root: root)
        try await rejects { _ = try await corrupt.load() }
        let badIndex = root.appendingPathComponent("catalog.json")
        try Data(repeating: 0, count: 1_048_577).write(to: badIndex)
        try await rejects { _ = try await ServerReportArchive(root: root).load() }
        let installer = try Data(contentsOf: URL(fileURLWithPath: "internal/distribution/install-agent.sh"))
        let pem = Data("-----BEGIN PUBLIC KEY-----\nfixture\n-----END PUBLIC KEY-----\n".utf8)
        let grant = ServerEnrollmentCommand.Grant(token: String(repeating: "a", count: 64),
            expires_at: Date().addingTimeInterval(900).ISO8601Format())
        let command = try ServerEnrollmentCommand.build(installer: installer, feed: "https://feed.example:8443", feedKey: pem,
            feedCA: nil, relay: "https://relay.example:8444", relayCA: nil, serverID: "fixture-01", interval: "1h",
            recipient: Data(repeating: 1, count: 32).base64EncodedString(), grant: grant)
        let check = Process()
        check.executableURL = URL(fileURLWithPath: "/bin/bash")
        check.arguments = ["-n"]
        let input = Pipe()
        check.standardInput = input
        try check.run()
        input.fileHandleForWriting.write(Data(command.utf8))
        try input.fileHandleForWriting.close()
        check.waitUntilExit()
        precondition(check.terminationStatus == 0, "Installation command shell syntax is invalid")
        try await rejects {
            _ = try ServerEnrollmentCommand.build(installer: installer, feed: "http://feed.example", feedKey: pem,
                feedCA: nil, relay: "https://relay.example", relayCA: nil, serverID: "fixture", interval: "1h",
                recipient: Data(repeating: 1, count: 32).base64EncodedString(), grant: grant)
        }
        try await rejects {
            _ = try ServerEnrollmentCommand.build(installer: installer, feed: "https://feed.example", feedKey: pem,
                feedCA: nil, relay: "https://relay.example", relayCA: nil, serverID: "bad; touch /tmp/no", interval: "1h",
                recipient: Data(repeating: 1, count: 32).base64EncodedString(), grant: grant)
        }
        let setup = ServerEnrollmentCommand.relaySetupCommand(hostname: "relay.example.com", port: "8444", existingCheckout: false)!
        precondition(setup.contains("git clone https://github.com/shiXpeer/ward.git shixpeer.ward && cd shixpeer.ward && bash"))
        precondition(ServerEnrollmentCommand.relaySetupCommand(hostname: "bad;touch", port: "8444", existingCheckout: true) == nil)
        precondition(ServerEnrollmentCommand.relaySetupCommand(hostname: "relay.example.com", port: "80", existingCheckout: true) == nil)
        precondition(ServerEnrollmentCommand.relaySetupCommand(hostname: "relay.example.com", port: "8444", existingCheckout: true,
            certificate: "/tmp/cert", privateKey: "") == nil)
        let custom = ServerEnrollmentCommand.relaySetupCommand(hostname: "relay.example.com", port: "8444", existingCheckout: true,
            certificate: "/tmp/it's a cert.pem", privateKey: "/tmp/key.pem")!
        precondition(!custom.contains("git clone"))
        let syntax = Process();syntax.executableURL = URL(fileURLWithPath: "/bin/bash");syntax.arguments = ["-n"]
        let syntaxInput = Pipe();syntax.standardInput = syntaxInput;try syntax.run()
        syntaxInput.fileHandleForWriting.write(Data((setup + "\n" + custom).utf8))
        try syntaxInput.fileHandleForWriting.close();syntax.waitUntilExit()
        precondition(syntax.terminationStatus == 0)
        print("PASS: enrollment command syntax; HTTPS-only origins; unsafe server ID rejection")
        print("PASS: persistence, duplicate suppression, retention, rollback ordering, freshness, relay errors, invalid IDs/timestamps, tamper rejection/repair and file permissions")
    }
}

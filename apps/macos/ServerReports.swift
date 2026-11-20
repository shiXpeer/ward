import Foundation
import CryptoKit

struct ServerSnapshot: Codable, Identifiable {
    let id: String
    let generatedAt, receivedAt: Date
    let hostname, system: String?
    let findings, review: Int
    let status: String
    let bytes: Int
}

struct ServerRecord: Codable, Identifiable {
    let beaconID: UUID
    let serverID: String
    var snapshots: [ServerSnapshot]
    var expectedInterval: TimeInterval = 3600
    var error: String?
    var id: String { beaconID.uuidString + ":" + serverID }
    var latest: ServerSnapshot? { snapshots.first }
    var name: String { latest?.hostname ?? serverID }
    func stale(at now: Date) -> Bool {
        guard let latest else { return true }
        return now.timeIntervalSince(latest.generatedAt) > max(600, expectedInterval * 2)
    }
}

struct RelaySyncState: Codable {
    var lastAttempt: Date?
    var lastSuccess: Date?
    var error: String?
    var connectionFailed = false
}

struct ServerCatalog: Codable {
    var format = 1
    var servers: [ServerRecord] = []
    var relays: [String: RelaySyncState] = [:]
}

/// Actor serialization keeps disk work and report decoding off the UI thread.
actor ServerReportArchive {
    static let maxServers = 64
    static let maxHistory = 20
    static let maxBytes = 256 * 1024 * 1024
    let root: URL
    private var catalog = ServerCatalog()

    init(root: URL) { self.root = root }

    static func validID(_ value: String) -> Bool {
        value.range(of: "^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$", options: .regularExpression) != nil
    }

    static func relayIDs(_ data: Data) throws -> [String] {
        let ids = try JSONDecoder().decode([String].self, from: data)
        guard ids.count <= maxServers, Set(ids).count == ids.count, ids.allSatisfy(validID) else {
            throw WardError("Invalid relay server list or server limit exceeded.")
        }
        return ids
    }

    private func file(_ record: ServerRecord, _ snapshot: ServerSnapshot) -> URL {
        root.appendingPathComponent(record.beaconID.uuidString, isDirectory: true)
            .appendingPathComponent(record.serverID, isDirectory: true)
            .appendingPathComponent(snapshot.id + ".json")
    }

    func load() throws -> ServerCatalog {
        let url = root.appendingPathComponent("catalog.json")
        guard FileManager.default.fileExists(atPath: url.path) else { return catalog }
        guard (try url.resourceValues(forKeys: [.fileSizeKey]).fileSize ?? Int.max) <= 1_048_576 else {
            throw WardError("Server history index exceeds its size limit.")
        }
        let saved = try JSONDecoder().decode(ServerCatalog.self, from: Data(contentsOf: url))
        guard saved.format == 1, saved.servers.count <= Self.maxServers,
              saved.relays.count <= 256, Set(saved.servers.map(\.id)).count == saved.servers.count else {
            throw WardError("Invalid server history index.")
        }
        var bytes = 0
        for server in saved.servers {
            guard Self.validID(server.serverID), server.snapshots.count <= Self.maxHistory,
                  server.expectedInterval >= 60, server.expectedInterval <= 604800,
                  Set(server.snapshots.map(\.id)).count == server.snapshots.count else {
                throw WardError("Invalid server history entry.")
            }
            for snapshot in server.snapshots {
                guard snapshot.id.range(of: "^[a-f0-9]{64}$", options: .regularExpression) != nil,
                      snapshot.bytes > 0, snapshot.bytes <= Wire.maxReport else {
                    throw WardError("Invalid server snapshot entry.")
                }
                bytes += snapshot.bytes
            }
        }
        guard bytes <= Self.maxBytes else { throw WardError("Server history exceeds its storage limit.") }
        catalog = saved
        return saved
    }

    private func commit(_ next: ServerCatalog) throws {
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true,
                                                attributes: [.posixPermissions: 0o700])
        let data = try JSONEncoder().encode(next)
        guard data.count <= 1_048_576 else { throw WardError("Server history index is full.") }
        let url = root.appendingPathComponent("catalog.json")
        try data.write(to: url, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
        catalog = next
    }

    func accept(_ data: Data, beaconID: UUID, serverID: String, now: Date = Date()) throws -> (ServerCatalog, Report) {
        guard Self.validID(serverID) else { throw WardError("Invalid server ID.") }
        let report = try Wire.decode(data)
        let generated = (try? Date.ISO8601FormatStyle(includingFractionalSeconds: true).parse(report.generated_at))
            ?? (try? Date.ISO8601FormatStyle().parse(report.generated_at))
        guard let generated, generated <= now.addingTimeInterval(300) else {
            throw WardError("Invalid report timestamp. Check the server clock.")
        }
        let hash = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
        var next = catalog
        let key = beaconID.uuidString + ":" + serverID
        if !next.servers.contains(where: { $0.id == key }) {
            guard next.servers.count < Self.maxServers else { throw WardError("Server limit reached (64).") }
            next.servers.append(ServerRecord(beaconID: beaconID, serverID: serverID, snapshots: []))
        }
        let index = next.servers.firstIndex { $0.id == key }!
        // Identical content is one snapshot, even when fetched repeatedly.
        if next.servers[index].snapshots.contains(where: { $0.id == hash }) {
            next.servers[index].error = nil
            let existing = next.servers[index].snapshots.first { $0.id == hash }!
            // A fresh authenticated fetch also repairs a damaged local copy.
            if (try? read(next.servers[index], snapshot: hash)) == nil {
                let destination = file(next.servers[index], existing)
                try FileManager.default.createDirectory(at: destination.deletingLastPathComponent(), withIntermediateDirectories: true,
                                                        attributes: [.posixPermissions: 0o700])
                try data.write(to: destination, options: .atomic)
                try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: destination.path)
            }
            try commit(next)
            return (catalog, try read(next.servers[index], snapshot: next.servers[index].snapshots[0].id).1)
        }
        let snapshot = ServerSnapshot(id: hash, generatedAt: generated, receivedAt: now,
                                      hostname: report.hostName, system: report.systemSummary,
                                      findings: report.confirmed, review: report.requires_review,
                                      status: report.status, bytes: data.count)
        next.servers[index].snapshots.append(snapshot)
        next.servers[index].snapshots.sort { ($0.generatedAt, $0.receivedAt) > ($1.generatedAt, $1.receivedAt) }
        next.servers[index].snapshots = Array(next.servers[index].snapshots.prefix(Self.maxHistory))
        next.servers[index].error = nil
        var total = next.servers.flatMap(\.snapshots).reduce(0) { $0 + $1.bytes }
        while total > Self.maxBytes {
            let candidates = next.servers.indices.filter { next.servers[$0].snapshots.count > 1 }
            guard let oldest = candidates.min(by: {
                next.servers[$0].snapshots.last!.receivedAt < next.servers[$1].snapshots.last!.receivedAt
            }) else { throw WardError("Server history storage is full (256 MiB).") }
            total -= next.servers[oldest].snapshots.removeLast().bytes
        }
        let destination = file(next.servers[index], snapshot)
        try FileManager.default.createDirectory(at: destination.deletingLastPathComponent(), withIntermediateDirectories: true,
                                                attributes: [.posixPermissions: 0o700])
        try data.write(to: destination, options: .atomic)
        do {
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: destination.path)
            let previous = catalog
            try commit(next)
            for server in previous.servers {
                let retained = Set(next.servers.first(where: { $0.id == server.id })?.snapshots.map(\.id) ?? [])
                for old in server.snapshots where !retained.contains(old.id) {
                    try? FileManager.default.removeItem(at: file(server, old))
                }
            }
            if !next.servers[index].snapshots.contains(where: { $0.id == hash }) {
                try? FileManager.default.removeItem(at: destination)
            }
        } catch { try? FileManager.default.removeItem(at: destination); throw error }
        // A relay replay may be saved in history but never replaces a newer report.
        return (catalog, try read(next.servers[index], snapshot: next.servers[index].snapshots[0].id).1)
    }

    func read(_ server: ServerRecord, snapshot id: String) throws -> (Data, Report) {
        guard Self.validID(server.serverID), id.range(of: "^[a-f0-9]{64}$", options: .regularExpression) != nil,
              let snapshot = server.snapshots.first(where: { $0.id == id }) else {
            throw WardError("Saved server report not found.")
        }
        let url = file(server, snapshot)
        guard (try url.resourceValues(forKeys: [.fileSizeKey]).fileSize) == snapshot.bytes else {
            throw WardError("Saved server report is missing or damaged.")
        }
        let data = try Data(contentsOf: url)
        guard SHA256.hash(data: data).map({ String(format: "%02x", $0) }).joined() == id else {
            throw WardError("Saved server report failed its integrity check.")
        }
        return (data, try Wire.decode(data))
    }

    func finish(beaconID: UUID, ids: Set<String>?, errors: [String: String], error: String?, now: Date = Date()) throws -> ServerCatalog {
        var next = catalog
        guard next.relays[beaconID.uuidString] != nil || next.relays.count < 256 else {
            throw WardError("Relay status limit reached (256).")
        }
        var state = next.relays[beaconID.uuidString] ?? RelaySyncState()
        state.lastAttempt = now
        if error == nil { state.lastSuccess = now }
        state.error = error
        state.connectionFailed = ids == nil && error != nil
        next.relays[beaconID.uuidString] = state
        for index in next.servers.indices where next.servers[index].beaconID == beaconID {
            let id = next.servers[index].serverID
            if let failure = errors[id] { next.servers[index].error = failure }
            else if let ids, !ids.contains(id) { next.servers[index].error = "Server is no longer listed by the relay." }
        }
        try commit(next)
        return catalog
    }

    func setInterval(serverID: String, seconds: TimeInterval) throws -> ServerCatalog {
        guard seconds >= 60, seconds <= 604800, let index = catalog.servers.firstIndex(where: { $0.id == serverID }) else {
            throw WardError("Invalid expected scan interval.")
        }
        var next = catalog
        next.servers[index].expectedInterval = seconds
        try commit(next)
        return catalog
    }
}

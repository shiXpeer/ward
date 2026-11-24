import Foundation

// Only public update metadata goes through Ward. Package downloads continue to
// use the original vendor URL and the existing local signature/hash checks.
enum OfficialWardBackend {
    static let origin = URL(string: "https://ward.shixpeer.com")!
    static let beaconID = UUID(uuidString: "B2FAAD04-345D-4DAD-8F97-B38F1F202AB1")!
    static func metadataRequest(_ source: URL, range: String? = nil) throws -> URLRequest {
        guard source.scheme == "https", source.host != nil, source.user == nil, source.password == nil,
              source.fragment == nil, source.absoluteString.utf8.count <= 3000 else { throw URLError(.badURL) }
        struct Payload: Encodable { let url: String; let range: String? }
        var request = URLRequest(url: origin.appendingPathComponent("v1/update-metadata"), timeoutInterval: 30)
        request.httpMethod = "POST"
        request.httpBody = try JSONEncoder().encode(Payload(url: source.absoluteString, range: range))
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("shixpeer-ward", forHTTPHeaderField: "User-Agent")
        return request
    }
}

struct BackendVersionQuery: Codable, Sendable {
    let bundle_id: String
    var architecture = "x86_64"
    var channel: String? = nil
    var url: String? = nil
    var urls: [String]? = nil
    var code: String? = nil
    var platform: String? = nil
    var name: String? = nil
    var quality: String? = nil
    init(bundle: String) {
        bundle_id = bundle
#if arch(arm64)
        architecture = "arm64"
#endif
    }
}
struct BackendVersionReply: Codable, Sendable {
    let version: String
    let installable: Bool
}

actor MetadataBackend {
    static let shared = MetadataBackend()
    private var versionMemo: [String: (BackendVersionReply, String?)] = [:]
    private var active = 0
    private var waiters: [CheckedContinuation<Void, Never>] = []
    private func acquire() async {
        if active < 4 { active += 1; return }
        await withCheckedContinuation { waiters.append($0) }
    }
    private func release() {
        if waiters.isEmpty { active -= 1 } else { waiters.removeFirst().resume() }
    }
    func fetch(_ source: URL, range: String? = nil, maxBytes: Int = 512_000) async throws -> (Data, HTTPURLResponse) {
        guard maxBytes > 0, maxBytes <= 1_048_576 else { throw URLError(.dataLengthExceedsMaximum) }
        await acquire()
        defer { release() }
        try Task.checkCancellation()
        let request = try OfficialWardBackend.metadataRequest(source, range: range)
        let config = URLSessionConfiguration.ephemeral
        config.waitsForConnectivity = false
        config.timeoutIntervalForRequest = 30
        let session = URLSession(configuration: config, delegate: NoRedirect(), delegateQueue: nil)
        defer { session.finishTasksAndInvalidate() }
        let (bytes, response) = try await session.bytes(for: request)
        guard let http = response as? HTTPURLResponse,
              http.url?.scheme == "https", http.url?.host == OfficialWardBackend.origin.host,
              [200, 204, 206].contains(http.statusCode) else {
            throw WardError("Ward backend metadata check failed (HTTP \((response as? HTTPURLResponse)?.statusCode ?? 0)).")
        }
        var data = Data()
        for try await byte in bytes {
            guard data.count < maxBytes else { throw URLError(.dataLengthExceedsMaximum) }
            data.append(byte)
        }
        return (data, http)
    }
}

extension MetadataBackend {
    struct Failure: Codable, Sendable { let bundle_id: String; let reason: String }
    private struct VersionQuery: Encodable { let bundle_id: String; let architecture: String }
    private func post<T: Encodable>(_ path: String, body: T, etag: String? = nil) async throws -> (Data, Int, String?) {
        await acquire(); defer { release() }
        try Task.checkCancellation()
        var request = URLRequest(url: OfficialWardBackend.origin.appendingPathComponent(path), timeoutInterval: 40)
        request.httpMethod = "POST"
        request.httpBody = try JSONEncoder().encode(body)
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        if let etag { request.setValue(etag, forHTTPHeaderField: "If-None-Match") }
        let config = URLSessionConfiguration.ephemeral
        config.httpCookieStorage = nil
        let session = URLSession(configuration: config, delegate: NoRedirect(), delegateQueue: nil)
        defer { session.finishTasksAndInvalidate() }
        let (bytes, response) = try await session.bytes(for: request)
        guard let http = response as? HTTPURLResponse, http.url?.host == OfficialWardBackend.origin.host,
              http.url?.scheme == "https" else { throw URLError(.badServerResponse) }
        var data = Data()
        for try await b in bytes { guard data.count < 4096 else { throw URLError(.dataLengthExceedsMaximum) }; data.append(b) }
        return (data, http.statusCode, http.value(forHTTPHeaderField: "ETag"))
    }
    func version(_ query: BackendVersionQuery) async throws -> BackendVersionReply {
        let encoder = JSONEncoder(); encoder.outputFormatting = .sortedKeys
        let key = String(decoding: try encoder.encode(query), as: UTF8.self)
        let (data, status, etag) = try await post("v1/app-version", body: query, etag: versionMemo[key]?.1)
        if status == 304, let known = versionMemo[key] { return known.0 }
        guard status == 200 else { throw WardError("Ward could not determine the latest version (HTTP \(status)).") }
        let reply = try JSONDecoder().decode(BackendVersionReply.self, from: data)
        guard reply.version.range(of: "^[0-9][A-Za-z0-9.+_-]{0,79}$", options: .regularExpression) != nil else { throw URLError(.badServerResponse) }
        if versionMemo.count >= 128 { versionMemo.removeAll() }
        versionMemo[key] = (reply, etag)
        return reply
    }
    func fallbackVersion(for bundle: String) async -> String? {
        try? await version(BackendVersionQuery(bundle: bundle)).version
    }
    // One successful event per app/category/day locally; no device identifier.
    // Only the current day's bounded set is retained. Failed submissions aren't queued.
    func reportFailure(_ failure: Failure) async {
        let day = Int(Date().timeIntervalSince1970 / 86400)
        let defaults = UserDefaults.standard
        let key = "ward.failure-diagnostics.sent.v1"
        let previous = defaults.dictionary(forKey: key)
        var sent = Set((previous?["day"] as? Int == day ? previous?["items"] as? [String] : nil) ?? [])
        let item = failure.bundle_id + "/" + failure.reason
        guard sent.count < 128, !sent.contains(item) else { return }
        sent.insert(item); defaults.set(["day": day, "items": Array(sent)], forKey: key)
        _ = try? await post("v1/update-failures", body: failure)
    }
}

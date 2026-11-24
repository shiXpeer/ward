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

actor MetadataBackend {
    static let shared = MetadataBackend()
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

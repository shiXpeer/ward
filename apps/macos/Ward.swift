import SwiftUI
import CoreServices
import Combine
import CryptoKit
import Security
import ServiceManagement
import UniformTypeIdentifiers
import UserNotifications

struct WardError: LocalizedError {
    let errorDescription: String?
    init(_ message: String) { errorDescription = message }
}

/// The Homebrew command finished, but the installed version still matches. This is not a failed run.
struct FindingStaysOpen: LocalizedError {
    let message: String
    var noUpgradeAvailable = false
    var errorDescription: String? { message }
}

struct Beacon: Codable, Identifiable {
    var id = UUID()
    var name: String
    var feed: String
    var feedKey: String
    var caFile: String
    var relay: String
    var relayCertificate: Data? = nil
}

struct Report: Decodable {
    let format_version: Int
    let generated_at: String
    let hostname: String?

    var hostName: String? {
        let value = hostname?.trimmingCharacters(in: .whitespacesAndNewlines)
        return value?.isEmpty == false ? value : nil
    }

    var systemSummary: String? {
        let host = inventory.host
        let release = host.release
        let fallback = [release?["NAME"] ?? host.os, release?["VERSION_ID"]]
            .compactMap { $0 }.joined(separator: " ")
        let system = release?["PRETTY_NAME"] ?? fallback
        let parts = [system, host.architecture].compactMap { $0 }.filter { !$0.isEmpty }
        return parts.isEmpty ? nil : parts.joined(separator: " · ")
    }
    let database: Database?
    struct Database: Decodable { let revision: Int64 }
    let status: String
    let confirmed: Int
    let requires_review: Int
    let review_scopes: [String: Int]?
    let review_reasons: [String: Int]?

    func reviewBreakdown() -> String {
        guard let review_scopes else { return "Applicability to verify" }
        let host = (review_scopes["Host packages and applications"] ?? 0) + (review_scopes["Running kernel"] ?? 0)
        let containers = review_scopes["Containers"] ?? 0
        return "Mac \(host.formatted()) · Docker \(containers.formatted())"
    }
    let components: [Component]?
    let findings: [Finding]
    let coverage: [Note]
    let inventory: Inventory
    struct Component: Decodable {
        let name, version, origin, result: String
        let reason: String?
        var rowID: String { origin + "\t" + name + "\t" + version }
    }
    struct Finding: Decodable {
        let component, installed_version, severity, status, id, reason: String
        let recommendation, origin: String?
        let fixed_versions, aliases, references: [String]?
        let summary, source, ecosystem: String?
        let known_exploited: Bool?
        let epss: Double?
        let evidence: Evidence?
        struct Evidence: Decodable {
            let context: Context?
            struct Context: Decodable {
                let cpe: CPE?
                struct CPE: Decodable {
                    let match: Match?
                    struct Match: Decodable {
                        let versionEndIncluding, versionEndExcluding: String?
                    }
                }
            }
        }
    }
    struct Note: Decodable { let source, code, detail: String }
    struct Inventory: Decodable {
        let host: Host
        let firewall: [Port]?
        let listeners: [Port]?
        let containers: [Container]?
        let applications: [Application]
        let packages: [Package]
        struct Application: Decodable, Hashable {
            let name: String
            let version: String
            let identifier: String
            let versionKind: String
            var key: String { identifier + "\t" + name + "\t" + version }
            var isApple: Bool { identifier.hasPrefix("com.apple.") }
            enum CodingKeys: String, CodingKey {
                case name, version, identifier
                case versionKind = "version_kind"
            }
            init(name: String, version: String, identifier: String, versionKind: String) {
                self.name = name
                self.version = version
                self.identifier = identifier
                self.versionKind = versionKind
            }
            init(from decoder: Decoder) throws {
                let c = try decoder.container(keyedBy: CodingKeys.self)
                name = try c.decodeIfPresent(String.self, forKey: .name) ?? "Unnamed application"
                version = try c.decodeIfPresent(String.self, forKey: .version) ?? ""
                identifier = try c.decodeIfPresent(String.self, forKey: .identifier) ?? ""
                versionKind = try c.decodeIfPresent(String.self, forKey: .versionKind) ?? ""
            }
        }
        struct Package: Decodable, Hashable {
            let name: String
            let version: String
            let manager: String
            let provenance, upstream_version, status: String?
            var key: String { manager + "\t" + name + "\t" + version }
            enum CodingKeys: String, CodingKey { case name, version, manager, provenance, upstream_version, status }
            init(from decoder: Decoder) throws {
                let c = try decoder.container(keyedBy: CodingKeys.self)
                name = try c.decodeIfPresent(String.self, forKey: .name) ?? ""
                version = try c.decodeIfPresent(String.self, forKey: .version) ?? ""
                manager = try c.decodeIfPresent(String.self, forKey: .manager) ?? ""
                provenance = try c.decodeIfPresent(String.self, forKey: .provenance)
                upstream_version = try c.decodeIfPresent(String.self, forKey: .upstream_version)
                status = try c.decodeIfPresent(String.self, forKey: .status)
            }
        }
        struct Container: Decodable {
            let name: String
            let id, image, image_id, digest, os, architecture, started_at: String?
            let release: [String: String]?

            var imageKey: String { image_id ?? digest ?? image ?? "unknown:" + name }
            var system: String {
                if let label = release?["PRETTY_NAME"] { return label }
                let fields = [release?["NAME"] ?? os, release?["VERSION_ID"], release?["VERSION_CODENAME"]]
                let label = fields.compactMap { $0 }.joined(separator: " ")
                return label.isEmpty ? "OS version unavailable" : label
            }
        }
        struct Host: Decodable { let os, architecture: String?; let release: [String: String]? }
        struct Port: Decodable {
            let port: Int
            let protocolName: String
            let family: String
            let status, reason, bind_scope: String?
            enum CodingKeys: String, CodingKey {
                case port, family, status, reason, bind_scope
                case protocolName = "protocol"
            }
        }
        enum CodingKeys: String, CodingKey {
            case host, firewall, listeners, containers, applications, packages
        }
        init(from decoder: Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            host = try c.decode(Host.self, forKey: .host)
            firewall = try c.decodeIfPresent([Port].self, forKey: .firewall)
            listeners = try c.decodeIfPresent([Port].self, forKey: .listeners)
            containers = try c.decodeIfPresent([Container].self, forKey: .containers)
            applications = try c.decodeIfPresent([Application].self, forKey: .applications) ?? []
            packages = try c.decodeIfPresent([Package].self, forKey: .packages) ?? []
        }
    }
}

extension Report {
    var portProblems: [(key: String, details: [String])] {
        let sensitive: [Int: String] = [22: "SSH", 2222: "SSH", 2375: "Docker API", 3306: "MySQL", 5432: "PostgreSQL",
                                         6379: "Redis", 8080: "Web or monitoring", 9090: "Monitoring", 9100: "Monitoring", 27017: "MongoDB"]
        var problems: [String: Set<String>] = [:]
        let verdicts = inventory.firewall ?? []
        for port in verdicts where port.status == "ALLOWED" && (sensitive[port.port] != nil || port.reason?.contains("DNAT") == true) {
            let key = String(port.port) + "/" + port.protocolName
            problems[key, default: []].insert(port.family + ": local firewall allows incoming traffic for at least one source")
        }
        for port in inventory.listeners ?? [] {
            guard let service = sensitive[port.port], ["wildcard", "public-address"].contains(port.bind_scope ?? ""),
                  !verdicts.contains(where: { $0.port == port.port && $0.protocolName == port.protocolName &&
                      $0.family == port.family && ($0.status == "ALLOWED" || $0.status == "BLOCKED") }) else { continue }
            let key = String(port.port) + "/" + port.protocolName
            problems[key, default: []].insert(port.family + ": " + service + " listens broadly; access restrictions are unverified")
        }
        return problems.sorted { $0.key.localizedStandardCompare($1.key) == .orderedAscending }
            .map { ($0.key, $0.value.sorted()) }
    }

    var hostReviewCount: Int {
        guard let review_scopes else { return requires_review }
        return (review_scopes["Host packages and applications"] ?? 0) + (review_scopes["Running kernel"] ?? 0)
    }

    var containerReviewCount: Int { review_scopes?["Containers"] ?? 0 }

    fileprivate func appFindings(for app: Report.Inventory.Application) -> [Report.Finding] {
        findings.filter {
            ($0.origin ?? "") == "application-bundle" && $0.component == app.name && $0.installed_version == app.version
        }
    }

    var userApplications: [Inventory.Application] {
        inventory.applications.filter { !$0.isApple }
    }
}

struct Device: Identifiable {
    let id: String
    let name: String
    let report: Report
}

enum Vault {
    static func query(_ account: String) -> [String: Any] {
        [kSecClass as String: kSecClassGenericPassword,
         kSecAttrService as String: "com.shixpeer.ward", kSecAttrAccount as String: account]
    }
    static func read(_ account: String) throws -> Data? {
        var q = query(account)
        q[kSecReturnData as String] = true
        var value: CFTypeRef?
        let status = SecItemCopyMatching(q as CFDictionary, &value)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = value as? Data else { throw WardError("Keychain read failed (\(status)).") }
        return data
    }
    static func store(_ data: Data, _ account: String) throws {
        var q = query(account)
        q[kSecValueData as String] = data
        var status = SecItemAdd(q as CFDictionary, nil)
        if status == errSecDuplicateItem {
            status = SecItemUpdate(query(account) as CFDictionary, [kSecValueData as String: data] as CFDictionary)
        }
        guard status == errSecSuccess else { throw WardError("Keychain write failed (\(status)).") }
    }
    static func recipient() throws -> Curve25519.KeyAgreement.PrivateKey {
        if let data = try read("recipient-v1") { return try .init(rawRepresentation: data) }
        let key = Curve25519.KeyAgreement.PrivateKey()
        try store(key.rawRepresentation, "recipient-v1")
        return key
    }
}

final class NoRedirect: NSObject, URLSessionTaskDelegate {
    let certificate: Data?
    init(certificate: Data? = nil) { self.certificate = certificate }
    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        guard let certificate else { completionHandler(.performDefaultHandling, nil); return }
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              let trust = challenge.protectionSpace.serverTrust,
              let anchor = SecCertificateCreateWithData(nil, certificate as CFData) else {
            completionHandler(.cancelAuthenticationChallenge, nil); return
        }
        if Self.accepts(trust, host: challenge.protectionSpace.host, anchor: anchor) {
            completionHandler(.useCredential, URLCredential(trust: trust))
        } else { completionHandler(.cancelAuthenticationChallenge, nil) }
    }
    static func accepts(_ trust: SecTrust, host: String, anchor: SecCertificate) -> Bool {
        guard SecTrustSetPolicies(trust, SecPolicyCreateSSL(true, host as CFString)) == errSecSuccess,
              SecTrustSetAnchorCertificates(trust, [anchor] as CFArray) == errSecSuccess,
              SecTrustSetAnchorCertificatesOnly(trust, true) == errSecSuccess else { return false }
        SecTrustSetNetworkFetchAllowed(trust, false)
        return SecTrustEvaluateWithError(trust, nil)
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) {
        completionHandler(nil)
    }
}

enum Wire {
    static let maxReport = 32 << 20
    static func origin(_ input: String) throws -> URL {
        guard let parts = URLComponents(string: input), parts.scheme == "https", let host = parts.host, !host.isEmpty,
              parts.user == nil, parts.password == nil, parts.query == nil, parts.fragment == nil,
              parts.path.isEmpty || parts.path == "/", let url = parts.url else { throw WardError("Enter an HTTPS origin, such as https://beacon.example:8444.") }
        return url
    }
    static func fetch(_ url: URL, token: Data, limit: Int, certificate: Data? = nil) async throws -> Data {
        let session = URLSession(configuration: .ephemeral, delegate: NoRedirect(certificate: certificate), delegateQueue: nil)
        defer { session.finishTasksAndInvalidate() }
        var request = URLRequest(url: url, timeoutInterval: 30)
        request.setValue("Bearer " + String(decoding: token, as: UTF8.self), forHTTPHeaderField: "Authorization")
        let (bytes, response) = try await session.bytes(for: request)
        guard let http = response as? HTTPURLResponse, http.statusCode == 200 else {
            throw WardError("Relay request failed (HTTP \((response as? HTTPURLResponse)?.statusCode ?? 0)).")
        }
        var data = Data()
        for try await byte in bytes {
            guard data.count < limit else { throw WardError("Relay response exceeds the size limit.") }
            data.append(byte)
        }
        return data
    }
    static func open(_ envelope: Data, id: String, key: Curve25519.KeyAgreement.PrivateKey) throws -> Data {
        guard envelope.count >= 61, envelope.first == 1 else { throw WardError("Unsupported encrypted report.") }
        let ephemeral = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: envelope[1..<33])
        let shared = try key.sharedSecretFromKeyAgreement(with: ephemeral)
        let symmetric = shared.hkdfDerivedSymmetricKey(using: SHA256.self, salt: Data(),
            sharedInfo: Data("shixpeer-ward/report/v1".utf8), outputByteCount: 32)
        let sealed = try AES.GCM.SealedBox(combined: Data(envelope.dropFirst(33)))
        return try AES.GCM.open(sealed, using: symmetric, authenticating: Data(id.utf8))
    }
    static func decode(_ data: Data) throws -> Report {
        guard data.count <= maxReport else { throw WardError("Report exceeds 32 MiB.") }
        let report = try JSONDecoder().decode(Report.self, from: data)
        guard report.format_version == 1 else { throw WardError("Unsupported report format.") }
        return report
    }
}

struct ScanProgress: Decodable, Sendable {
    let stage: String
    let component: String?
    let done, total: Int
    let matches, review: Int?
    let seconds: Int?

    var title: String {
        switch stage {
        case "database": return "Verifying the signed database"
        case "matching": return component.map { "Checking " + $0 } ?? "Checking components"
        case "report": return "Saving report"
        default: return "Collecting installed software and local ports"
        }
    }
}

private struct WardPreferences: Codable {
    var menuBar = false
    var databaseMinutes = 0
    var downloadDatabase = false
    var scanMinutes = 0
    var scanAfterDatabaseUpdate: Bool? = nil
    var applicationMinutes = 0
    var checksOnLaunch: Bool? = nil
    var launchChecks: Bool {
        get { checksOnLaunch ?? true }
        set { checksOnLaunch = newValue }
    }
    var notifyApplicationUpdates: Bool? = nil
    var notifyNewFindings: Bool? = nil

    var applicationNotifications: Bool {
        get { notifyApplicationUpdates ?? false }
        set { notifyApplicationUpdates = newValue }
    }

    var findingNotifications: Bool {
        get { notifyNewFindings ?? false }
        set { notifyNewFindings = newValue }
    }

    var scanNewDatabase: Bool {
        get { scanAfterDatabaseUpdate ?? false }
        set { scanAfterDatabaseUpdate = newValue }
    }

    static let key = "ward.maintenance.preferences.v1"

    static func load() -> Self {
        guard let data = UserDefaults.standard.data(forKey: key),
              let value = try? JSONDecoder().decode(Self.self, from: data) else { return .init() }
        return value
    }
}

@MainActor private final class LaunchChecks {
    enum Step: CaseIterable { case database, scan, applications }
    private(set) var started = false
    func run(enabled: Bool, ready: () async -> Bool, perform: (Step) async -> Void) async {
        guard enabled, !started else { return }
        started = true
        for step in Step.allCases {
            guard !Task.isCancelled, await ready() else { return }
            await perform(step)
        }
    }
}

@MainActor final class WardModel: ObservableObject {
    @Published fileprivate var preferences = WardPreferences.load() {
        didSet {
            if let data = try? JSONEncoder().encode(preferences) {
                UserDefaults.standard.set(data, forKey: WardPreferences.key)
            }
            if (preferences.applicationNotifications && !oldValue.applicationNotifications) ||
                (preferences.findingNotifications && !oldValue.findingNotifications) {
                Task {
                    _ = try? await UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound])
                }
            }
            if preferences.databaseMinutes != oldValue.databaseMinutes { schedule(.database) }
            if preferences.scanMinutes != oldValue.scanMinutes { schedule(.scan) }
            if preferences.applicationMinutes != oldValue.applicationMinutes { schedule(.applications) }
        }
    }
    @Published private(set) var serverCatalog = ServerCatalog()
    @Published private(set) var syncingServerReports = false
    @Published private(set) var serverStorageError = ""
    @Published var automaticServerSync = UserDefaults.standard.object(forKey: "ward.servers.autoSync") as? Bool ?? true {
        didSet {
            UserDefaults.standard.set(automaticServerSync, forKey: "ward.servers.autoSync")
            if automaticServerSync { Task { await syncServerReports() } }
        }
    }
    let serverArchive = ServerReportArchive(root: FileManager.default.homeDirectoryForCurrentUser
        .appendingPathComponent(".shixpeer.ward/macos/server-reports", isDirectory: true))
    private var serverSyncTask: Task<Void, Never>?
    private var serverArchiveReady = false
    private var nextServerSync = Date.distantPast
    var servers: [ServerRecord] {
        let connected = Set(beacons.map(\.id))
        return serverCatalog.servers.filter { connected.contains($0.beaconID) }
            .sorted { $0.name.localizedStandardCompare($1.name) == .orderedAscending }
    }

    private func restoreServerReports() async {
        do {
            serverCatalog = try await serverArchive.load()
            for server in servers {
                guard let latest = server.latest else { continue }
                do {
                    let (_, report) = try await serverArchive.read(server, snapshot: latest.id)
                    put(Device(id: server.id, name: server.name, report: report))
                } catch {
                    if let index = serverCatalog.servers.firstIndex(where: { $0.id == server.id }) {
                        serverCatalog.servers[index].error = error.localizedDescription
                    }
                }
            }
            serverArchiveReady = true
        } catch { serverStorageError = "Could not restore server history: " + error.localizedDescription }
    }

    func syncServerReports(_ only: Beacon? = nil) async {
        guard serverArchiveReady, !syncingServerReports else { return }
        let sources = only.map { [$0] } ?? beacons.filter { !$0.relay.isEmpty }
        guard !sources.isEmpty else { return }
        syncingServerReports = true
        nextServerSync = Date().addingTimeInterval(300)
        defer { syncingServerReports = false }
        for beacon in sources {
            var receivedIDs: Set<String>?
            var failures: [String: String] = [:]
            var failure: String?
            do {
                let origin = try Wire.origin(beacon.relay)
                let key = try Vault.recipient()
                guard let token = try Vault.read(beacon.id.uuidString) else { throw WardError("Relay read token missing.") }
                let base = origin.appendingPathComponent("v1/reports")
                let raw = try await Wire.fetch(base, token: token, limit: 1 << 20, certificate: beacon.relayCertificate)
                let ids = try ServerReportArchive.relayIDs(raw)
                receivedIDs = Set(ids)
                for id in ids {
                    do {
                        let envelope = try await Wire.fetch(base.appendingPathComponent(id), token: token, limit: Wire.maxReport + 61, certificate: beacon.relayCertificate)
                        let data = try await Task.detached { try Wire.open(envelope, id: id, key: key) }.value
                        let previous = devices.first { $0.id == beacon.id.uuidString + ":" + id }?.report
                        let (catalog, report) = try await serverArchive.accept(data, beaconID: beacon.id, serverID: id)
                        serverCatalog = catalog
                        let server = catalog.servers.first { $0.beaconID == beacon.id && $0.serverID == id }!
                        put(Device(id: server.id, name: server.name, report: report))
                        if preferences.findingNotifications, let previous {
                            func matches(_ report: Report) -> Set<[String]> {
                                Set(report.findings.filter { $0.status == "affected" }.map { [$0.component, $0.origin ?? "", $0.source ?? "", $0.id] })
                            }
                            let count = matches(report).subtracting(matches(previous)).count
                            if count > 0 {
                                postSystemNotification(title: "New server findings", body: "\(server.name): \(count) new advisory matches.")
                            }
                        }
                    } catch { failures[id] = error.localizedDescription }
                }
                if !failures.isEmpty { failure = "\(failures.count) reports could not be fetched or verified." }
            } catch { failure = error.localizedDescription }
            do {
                serverCatalog = try await serverArchive.finish(beaconID: beacon.id, ids: receivedIDs, errors: failures, error: failure)
            } catch { serverStorageError = "Could not save sync status: " + error.localizedDescription }
        }
    }

    func openServerReport(_ server: ServerRecord, snapshot: ServerSnapshot) async {
        do {
            let (_, report) = try await serverArchive.read(server, snapshot: snapshot.id)
            let id = snapshot.id == server.latest?.id ? server.id : "server-history:" + server.id + ":" + snapshot.id
            devices.removeAll { $0.id.hasPrefix("server-history:") && $0.id != id }
            put(Device(id: id, name: server.name, report: report))
            selection = id
        } catch { message = error.localizedDescription }
    }

    func setServerInterval(_ server: ServerRecord, seconds: TimeInterval) {
        Task {
            do { serverCatalog = try await serverArchive.setInterval(serverID: server.id, seconds: seconds) }
            catch { message = error.localizedDescription }
        }
    }

    private let launchChecks = LaunchChecks()
    private var launchChecksTask: Task<Void, Never>?
    private var runningLaunchChecks = false
    @Published fileprivate var notificationIssue = ""

    fileprivate func startLaunchChecks() {
        guard preferences.launchChecks, !launchChecks.started, launchChecksTask == nil else { return }
        runningLaunchChecks = true
        launchChecksTask = Task { [weak self] in
            guard let self else { return }
            defer { runningLaunchChecks = false; launchChecksTask = nil }
            await launchChecks.run(enabled: preferences.launchChecks, ready: {
                while self.busy || self.checkingAppVersions || self.installingApplication {
                    do { try await Task.sleep(for: .milliseconds(100)) } catch { return false }
                }
                return self.preferences.launchChecks && !Task.isCancelled
            }, perform: { step in
                switch step {
                case .database:
                    await self.localScan(update: true, updateOnly: true, checkOnly: !self.preferences.downloadDatabase, background: true, followUp: false)
                    self.schedule(.database)
                case .scan:
                    await self.localScan(update: false, background: true, followUp: false)
                    self.schedule(.scan)
                case .applications:
                    await self.checkApplicationVersions()
                    self.schedule(.applications)
                }
            })
        }
    }

    fileprivate func sendTestNotification() async {
        let sent = await deliverSystemNotification(title: "Ward notifications", body: "Notifications for new application and system updates are working.")
        if sent { showNotice("Test notification sent.") }
    }

    private var localVersionTimer: Task<Void, Never>?
    private var localVersionObservers = Set<AnyCancellable>()
    private var reconcilingLocalVersions = false
    private var nextSystemReconciliation = Date.distantPast

    private var hasPendingLocalVersions: Bool {
        appUpdateChecks.contains { id, record in
            record.newer && (availableAppUpdateIDs.contains(id) || NSWorkspace.shared.urlForApplication(withBundleIdentifier: id) != nil)
        } || systemSoftwareUpdates.contains { $0.pendingRestart != true }
    }

    private var versionsForeground: Bool {
        NSApp.isActive && NSApp.windows.contains { $0.isVisible && $0.canBecomeKey && $0.styleMask.contains(.titled) }
    }

    private func scheduleLocalVersionCheck(immediate: Bool = false) {
        localVersionTimer?.cancel()
        localVersionTimer = nil
        guard hasPendingLocalVersions else { return }
        let delay: Duration = immediate ? .zero : versionsForeground ? .seconds(5) : .seconds(60)
        localVersionTimer = Task { [weak self] in
            do { try await Task.sleep(for: delay) } catch { return }
            guard !Task.isCancelled else { return }
            await self?.reconcileInstalledVersions()
            guard !Task.isCancelled else { return }
            self?.scheduleLocalVersionCheck()
        }
    }

    fileprivate func reconcileInstalledVersions() async {
        guard hasPendingLocalVersions, !checkingAppVersions, !installingApplication, !reconcilingLocalVersions else { return }
        reconcilingLocalVersions = true
        defer { reconcilingLocalVersions = false }
        let snapshot = appUpdateChecks
        let changes = await Task.detached {
            var changed: [String: AppUpdateRecord] = [:]
            for (id, record) in snapshot {
                guard let url = NSWorkspace.shared.urlForApplication(withBundleIdentifier: id) else { continue }
                let updated = AppUpdateReconciliation.reconcile(record, installed: AppUpdateReconciliation.installedVersion(at: url))
                if updated != record { changed[id] = updated }
            }
            return changed
        }.value
        guard !checkingAppVersions, !installingApplication else { return }
        var updated = appUpdateChecks
        for (id, record) in changes where updated[id] == snapshot[id] { updated[id] = record }
        if updated != appUpdateChecks {
            let checkedAt = AppUpdateStore.load()?.date ?? Date(timeIntervalSince1970: 1)
            appUpdateChecks = updated
            // Local observations must not extend the remote check cache TTL.
            AppUpdateStore.save(updated, at: checkedAt)
        }
        updateAppBadge(appUpdateChecks, for: Set(appUpdateChecks.keys))
        if !systemSoftwareUpdates.isEmpty, Date() >= nextSystemReconciliation {
            nextSystemReconciliation = Date().addingTimeInterval(versionsForeground ? 10 : 60)
            let before = systemSoftwareUpdates
            let cachedCatalog = Task.detached { try SystemSoftwareUpdate.check(cachedOnly: true) }
            if let remaining = try? await cachedCatalog.value,
               !checkingAppVersions, !installingApplication, before == systemSoftwareUpdates {
                systemSoftwareUpdates = SystemSoftwareUpdate.mergingRestartPending(remaining)
                if let data = try? JSONEncoder().encode(systemSoftwareUpdates) { UserDefaults.standard.set(data, forKey: "ward.system-software-updates.v1") }
                updateAppBadge(appUpdateChecks, for: Set(appUpdateChecks.keys))
            }
        }
    }

    private func watchInstalledVersions() {
        let workspace = NSWorkspace.shared.notificationCenter
        for name in [NSWorkspace.didLaunchApplicationNotification, NSWorkspace.didTerminateApplicationNotification] {
            workspace.publisher(for: name).sink { [weak self] event in
                guard let application = event.userInfo?[NSWorkspace.applicationUserInfoKey] as? NSRunningApplication,
                      let id = application.bundleIdentifier else { return }
                Task { @MainActor in
                    guard let self, self.appUpdateChecks[id]?.newer == true else { return }
                    self.scheduleLocalVersionCheck(immediate: true)
                }
            }.store(in: &localVersionObservers)
        }
        NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification).sink { [weak self] _ in
            Task { @MainActor in
                guard let self else { return }
                self.nextSystemReconciliation = .distantPast
                self.scheduleLocalVersionCheck(immediate: true)
            }
        }.store(in: &localVersionObservers)
        for name in [NSApplication.didResignActiveNotification, NSWindow.willCloseNotification] {
            NotificationCenter.default.publisher(for: name).sink { [weak self] _ in
                Task { @MainActor in
                    await Task.yield()
                    self?.scheduleLocalVersionCheck()
                }
            }.store(in: &localVersionObservers)
        }
        // Property publishers emit before assignment: defer scheduling until the
        // new pending set is visible. No pending versions means no timer at all.
        $appUpdateChecks.map { _ in () }
            .merge(with: $availableAppUpdateIDs.map { _ in () }, $systemSoftwareUpdates.map { _ in () })
            .sink { [weak self] _ in
                Task { @MainActor in self?.scheduleLocalVersionCheck() }
            }.store(in: &localVersionObservers)
        scheduleLocalVersionCheck(immediate: true)
    }

    private enum Maintenance: CaseIterable, Hashable { case database, scan, applications }
    private var nextMaintenance: [Maintenance: Date] = [:]
    private var maintenanceTimer: Task<Void, Never>?
    @Published private(set) var databaseUpdateAvailable = false
    @Published fileprivate var appUpdateChecks = AppUpdateStore.load()?.results ?? [:]
    @Published private(set) var checkingAppVersions = false
    @Published private(set) var applicationUpdateNote = ""
    @Published fileprivate var installingApplication = false

    private func interval(_ job: Maintenance) -> Int {
        switch job {
        case .database: preferences.databaseMinutes
        case .scan: preferences.scanMinutes
        case .applications: preferences.applicationMinutes
        }
    }

    private func schedule(_ job: Maintenance) {
        let minutes = interval(job)
        nextMaintenance[job] = minutes > 0 ? Date().addingTimeInterval(Double(minutes) * 60) : nil
    }

    private func runScheduledMaintenance() async {
        guard !runningLaunchChecks, !busy, !checkingAppVersions, !installingApplication else { return }
        let now = Date()
        guard let due = nextMaintenance.min(by: { $0.value < $1.value }), due.value <= now else { return }
        let job = due.key
        schedule(job)
        switch job {
        case .database:
            await localScan(update: true, updateOnly: true, checkOnly: !preferences.downloadDatabase, background: true)
        case .scan:
            await localScan(update: false, background: true)
        case .applications:
            await checkApplicationVersions()
        }
    }

    @Published private(set) var loginStatus = SMAppService.mainApp.status

    func refreshLoginStatus() {
        let status = SMAppService.mainApp.status
        if status != loginStatus { loginStatus = status }
    }

    func setLaunchAtLogin(_ enabled: Bool) {
        let service = SMAppService.mainApp
        defer { refreshLoginStatus() }
        do {
            if enabled { try service.register() }
            else { try service.unregister() }
        } catch {
            message = "Could not change launch at login: " + error.localizedDescription
        }
    }

    var launchAtLogin: Bool { loginStatus == .enabled || loginStatus == .requiresApproval }

    @Published var beacons: [Beacon] = []
    @Published var devices: [Device] = []
    @Published var selection: String? = "home"
    @Published var pageTravel: CGFloat = 0
    @Published var activeFeed: UUID? {
        didSet { UserDefaults.standard.set(activeFeed?.uuidString, forKey: "activeBeacon") }
    }
    struct ScanIssue {
        let title: String
        let detail: String
        var showsCoverage = false
    }

    @Published private(set) var scanIssue: ScanIssue?
    @Published private(set) var updatingScanDatabase = false
    struct Notice: Hashable {
        let text: String
        let expiry: Date
    }

    @Published private(set) var notice: Notice?
    @Published private(set) var scanningMac = false
    @Published private(set) var cancellingScan = false
    private var scanProcess: Process?
    @Published private(set) var scanProgress: ScanProgress?
    @Published var activity = ""
    @Published var message = ""
    @Published private(set) var availableAppUpdateIDs = Set((AppUpdateStore.load()?.results ?? [:]).compactMap {
        currentlyNeedsAppUpdate($0.key, record: $0.value) ? $0.key : nil
    })

    @Published fileprivate var systemSoftwareUpdates = SystemSoftwareUpdate.load()
    @Published fileprivate var systemUpdateCheckNote = ""
    fileprivate func updateAppBadge(_ results: [String: AppUpdateRecord], for identifiers: Set<String>) {
        let ids = Set(results.compactMap { identifiers.contains($0.key) && currentlyNeedsAppUpdate($0.key, record: $0.value) ? $0.key : nil }).union(systemSoftwareUpdates.map(\.id))
        if ids != availableAppUpdateIDs {
            availableAppUpdateIDs = ids
            if !checkingAppVersions {
                applicationUpdateNote = ids.isEmpty ? "No pending updates." : "\(ids.count.formatted()) updates available."
            }
        }
    }

    @Published var applicationCheckProgress: (completed: Int, total: Int)?
    @Published var busy = false
    @Published var devicePath: [DevicePage] = []
    @Published private(set) var verifiedFormulas: [[String]: Int] = [:]

    var resolvedMatches: Int { verifiedFormulas.values.reduce(0, +) }

    func isVerified(_ finding: Report.Finding) -> Bool {
        finding.origin == "homebrew-formula" && verifiedFormulas[[finding.component, finding.installed_version]] != nil
    }
    private let root = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".shixpeer.ward/macos")
    private struct SavedImport: Codable {
        let name: String
        let report: Data
    }

    private static let maxImports = 32
    private var importedDigests: [String: SHA256.Digest] = [:]
    private var importsDirectory: URL { root.appendingPathComponent("imports", isDirectory: true) }
    var importedReports: [Device] { devices.reversed().filter { $0.id.hasPrefix("import:") } }

    init() {
        if let raw = try? Data(contentsOf: root.appendingPathComponent("beacons.json")),
           let saved = try? JSONDecoder().decode([Beacon].self, from: raw) { beacons = saved }
        if let raw = UserDefaults.standard.string(forKey: "activeBeacon"), let id = UUID(uuidString: raw),
           beacons.contains(where: { $0.id == id }) { activeFeed = id }
        configureOfficialBeacon()
        let local = root.appendingPathComponent("local/report.json")
        if let raw = try? Data(contentsOf: local), let report = try? Wire.decode(raw) {
            devices.append(Device(id: "local", name: "This Mac", report: report))
        }
        loadImports()
        serverSyncTask = Task { [weak self] in
            await self?.restoreServerReports()
            while !Task.isCancelled {
                if let self, self.automaticServerSync, Date() >= self.nextServerSync {
                    await self.syncServerReports()
                }
                do { try await Task.sleep(for: .seconds(30)) } catch { return }
                guard self != nil else { return }
            }
        }
        for job in Maintenance.allCases { schedule(job) }
        maintenanceTimer = Task { [weak self] in
            while !Task.isCancelled {
                do { try await Task.sleep(for: .seconds(15)) } catch { return }
                guard self != nil else { return }
                await self?.runScheduledMaintenance()
            }
        }
        watchInstalledVersions()
        Task { [weak self] in self?.startLaunchChecks() }
    }
    private func configureOfficialBeacon() {
        guard let key = Bundle.main.url(forResource: "OfficialFeed", withExtension: "pub") else { return }
        let id = OfficialWardBackend.beaconID
        var configured = beacons
        if let index = configured.firstIndex(where: { $0.id == id }) {
            configured[index].feed = OfficialWardBackend.origin.absoluteString
            configured[index].feedKey = key.path
            configured[index].caFile = ""
        } else {
            configured.insert(Beacon(id: id, name: "Ward", feed: OfficialWardBackend.origin.absoluteString,
                feedKey: key.path, caFile: "", relay: ""), at: 0)
        }
        do {
            try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
            try JSONEncoder().encode(configured).write(to: root.appendingPathComponent("beacons.json"), options: .atomic)
            beacons = configured
            let migration = "ward.official-source-default.v1"
            if activeFeed == nil || !UserDefaults.standard.bool(forKey: migration) { activeFeed = id }
            UserDefaults.standard.set(true, forKey: migration)
        } catch { message = "Could not configure the Ward database source: " + error.localizedDescription }
    }

    func add(_ beacon: Beacon, token: String) throws {
        _ = try Wire.origin(beacon.feed)
        if !beacon.relay.isEmpty {
            _ = try Wire.origin(beacon.relay)
            guard token.utf8.count >= 32 else { throw WardError("Enter the relay read token.") }
            try Vault.store(Data(token.utf8), beacon.id.uuidString)
        }
        let all = beacons + [beacon]
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        try JSONEncoder().encode(all).write(to: root.appendingPathComponent("beacons.json"), options: .atomic)
        beacons = all
    }
    func connectRelay(to beaconID: UUID, address: String, readToken: String, certificate: Data? = nil) async throws {
        let origin = try Wire.origin(address.trimmingCharacters(in: .whitespacesAndNewlines))
        let token = Data(readToken.trimmingCharacters(in: .whitespacesAndNewlines).utf8)
        guard token.count >= 32 else { throw WardError("Enter the relay reader token (at least 32 bytes).") }

        let endpoint = origin.appendingPathComponent("v1/reports")
        let response = try await Wire.fetch(endpoint, token: token, limit: 1 << 20, certificate: certificate)
        _ = try JSONDecoder().decode([String].self, from: response)

        guard let index = beacons.firstIndex(where: { $0.id == beaconID }), beacons[index].relay.isEmpty else {
            throw WardError("The Beacon settings changed. Select the connection again.")
        }
        var updated = beacons
        updated[index].relay = origin.absoluteString
        updated[index].relayCertificate = certificate
        let config = try JSONEncoder().encode(updated)
        let account = beaconID.uuidString
        let previous = try Vault.read(account)
        try Vault.store(token, account)
        do {
            try config.write(to: root.appendingPathComponent("beacons.json"), options: .atomic)
        } catch {
            if let previous { try? Vault.store(previous, account) }
            else { SecItemDelete(Vault.query(account) as CFDictionary) }
            throw error
        }
        beacons = updated
    }

    func removeBeacon(_ beacon: Beacon) throws {
        let remaining = beacons.filter { $0.id != beacon.id }
        try JSONEncoder().encode(remaining).write(to: root.appendingPathComponent("beacons.json"), options: .atomic)
        beacons = remaining
        devices.removeAll { $0.id.hasPrefix(beacon.id.uuidString + ":") }
        if activeFeed == beacon.id { activeFeed = nil }
        selection = "local"
        for account in [beacon.id.uuidString, beacon.id.uuidString + ".enrollment"] {
            let result = SecItemDelete(Vault.query(account) as CFDictionary)
            if result != errSecSuccess && result != errSecItemNotFound {
                throw WardError("Beacon removed. Keychain token cleanup failed (\(result)).")
            }
        }
    }
    func removeReport(_ device: Device) {
        guard device.id != "local" else { return }
        let imported = device.id.hasPrefix("import:")
        if imported {
            guard let id = UUID(uuidString: String(device.id.dropFirst("import:".count))) else { return }
            do { try FileManager.default.removeItem(at: importURL(id)) }
            catch {
                message = "Could not remove the saved report. " + error.localizedDescription
                return
            }
        }
        devices.removeAll { $0.id == device.id }
        importedDigests.removeValue(forKey: device.id)
        selection = imported ? "imports" : "local"
    }

    func renameImportedReport(_ device: Device, to proposedName: String) {
        let name = proposedName.trimmingCharacters(in: .whitespacesAndNewlines)
        guard device.id.hasPrefix("import:"), !name.isEmpty, name.count <= 120,
              let id = UUID(uuidString: String(device.id.dropFirst("import:".count))) else { return }
        do {
            let url = importURL(id)
            let data = try readImportFile(url, limit: Wire.maxReport + 4096)
            let entry = try PropertyListDecoder().decode(SavedImport.self, from: data)
            try saveImport(SavedImport(name: name, report: entry.report), to: url)
            put(Device(id: device.id, name: name, report: device.report))
        } catch {
            message = "Could not rename the report. " + error.localizedDescription
        }
    }

    func importReports(_ urls: [URL]) {
        var errors: [String] = []
        var openedReport: String?
        for url in urls {
            do { openedReport = try importReport(url) }
            catch { errors.append(url.lastPathComponent + " · " + error.localizedDescription) }
        }
        selection = openedReport ?? "imports"
        message = errors.prefix(3).joined(separator: "\n")
        if errors.count > 3 { message += "\n\(errors.count - 3) more files could not be imported." }
    }

    private func importURL(_ id: UUID) -> URL {
        importsDirectory.appendingPathComponent(id.uuidString).appendingPathExtension("plist")
    }

    private func readImportFile(_ url: URL, limit: Int) throws -> Data {
        guard url.isFileURL, try url.resourceValues(forKeys: [.isRegularFileKey]).isRegularFile == true else {
            throw WardError("Choose a Ward report JSON file.")
        }
        let file = try FileHandle(forReadingFrom: url)
        defer { try? file.close() }
        let data = try file.read(upToCount: limit + 1) ?? Data()
        guard data.count <= limit else { throw WardError("Report file is too large.") }
        return data
    }

    private func loadImports() {
        let keys: Set<URLResourceKey> = [.contentModificationDateKey]
        guard let files = try? FileManager.default.contentsOfDirectory(at: importsDirectory,
            includingPropertiesForKeys: Array(keys), options: [.skipsHiddenFiles]) else { return }
        let saved = files.compactMap { url -> (URL, UUID, Date)? in
            guard url.pathExtension == "plist",
                  let id = UUID(uuidString: url.deletingPathExtension().lastPathComponent) else { return nil }
            let date = (try? url.resourceValues(forKeys: keys).contentModificationDate) ?? .distantPast
            return (url, id, date)
        }.sorted { ($0.2, $0.1.uuidString) < ($1.2, $1.1.uuidString) }
        var failures = 0
        for (url, id, _) in saved.suffix(Self.maxImports) {
            do {
                let data = try readImportFile(url, limit: Wire.maxReport + 4096)
                let entry = try PropertyListDecoder().decode(SavedImport.self, from: data)
                let report = try Wire.decode(entry.report)
                let device = Device(id: "import:" + id.uuidString, name: entry.name, report: report)
                devices.append(device)
                importedDigests[device.id] = SHA256.hash(data: entry.report)
            } catch { failures += 1 }
        }
        if failures > 0 { message = "\(failures) saved reports could not be opened." }
    }

    private func importReport(_ url: URL) throws -> String {
        let access = url.startAccessingSecurityScopedResource()
        defer { if access { url.stopAccessingSecurityScopedResource() } }
        let data = try readImportFile(url, limit: Wire.maxReport)
        let digest = SHA256.hash(data: data)
        if let existing = importedReports.first(where: { importedDigests[$0.id] == digest }) {
            return existing.id
        }
        guard importedReports.count < Self.maxImports else {
            throw WardError("The library holds up to \(Self.maxImports) reports. Remove a saved report first.")
        }
        let report = try Wire.decode(data)
        let id = UUID()
        let name = url.deletingPathExtension().lastPathComponent
        try FileManager.default.createDirectory(at: importsDirectory, withIntermediateDirectories: true,
                                                attributes: [.posixPermissions: 0o700])
        try saveImport(SavedImport(name: name, report: data), to: importURL(id))
        let device = Device(id: "import:" + id.uuidString, name: name, report: report)
        put(device)
        importedDigests[device.id] = digest
        return device.id
    }
    private func saveImport(_ entry: SavedImport, to url: URL) throws {
        let encoder = PropertyListEncoder()
        encoder.outputFormat = .binary
        try encoder.encode(entry).write(to: url, options: .atomic)
    }

    private func put(_ device: Device) {
        if let index = devices.firstIndex(where: { $0.id == device.id }) { devices[index] = device }
        else { devices.append(device) }
    }
    func createServerEnrollment(_ beacon: Beacon, serverID: String, interval: String,
                                managementToken: String, relayCAPath: String) async throws -> (String, Date) {
        let token = managementToken.trimmingCharacters(in: .whitespacesAndNewlines)
        guard token.utf8.count >= 32 else { throw WardError("Enter the separate relay enrollment token.") }
        let feed = try Wire.origin(beacon.feed).absoluteString.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        let relay = try Wire.origin(beacon.relay)
        let feedKey = try ServerEnrollmentCommand.readPublicFile(trustFile(beacon.feedKey, named: "feed.pub"), maximum: 4096)
        let feedCA = beacon.caFile.isEmpty ? nil : try ServerEnrollmentCommand.readPublicFile(trustFile(beacon.caFile, named: "ca.crt"), maximum: 65536)
        let relayCA: Data?
        if let certificate = beacon.relayCertificate {
            relayCA = Data(("-----BEGIN CERTIFICATE-----\n" + certificate.base64EncodedString(options: .lineLength64Characters) + "\n-----END CERTIFICATE-----\n").utf8)
        } else { relayCA = relayCAPath.isEmpty ? nil : try ServerEnrollmentCommand.readPublicFile(relayCAPath, maximum: 65536) }
        guard let installerURL = Bundle.main.url(forResource: "InstallAgent", withExtension: "sh") else {
            throw WardError("Bundled agent installer missing. Rebuild Ward.")
        }
        let installer = try Data(contentsOf: installerURL)
        let recipient = try Vault.recipient().publicKey.rawRepresentation.base64EncodedString()
        var request = URLRequest(url: relay.appendingPathComponent("v1/enrollments"), timeoutInterval: 30)
        request.httpMethod = "POST"
        request.setValue("Bearer " + token, forHTTPHeaderField: "Authorization")
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try JSONSerialization.data(withJSONObject: ["server_id": serverID, "recipient_public_key": recipient])
        let session = URLSession(configuration: .ephemeral, delegate: NoRedirect(certificate: beacon.relayCertificate), delegateQueue: nil)
        defer { session.finishTasksAndInvalidate() }
        let (bytes, response) = try await session.bytes(for: request)
        guard let http = response as? HTTPURLResponse else { throw WardError("Invalid relay response.") }
        switch http.statusCode {
        case 201: break
        case 401: throw WardError("Enrollment token rejected. Use the management token, not the reader or writer token.")
        case 404: throw WardError("Update the relay and enable enrollment first. Open Relay setup for the command.")
        case 409: throw WardError("Server ID is already registered or the relay is full. Choose a new ID; existing credentials will not be replaced.")
        default: throw WardError("Relay enrollment failed (HTTP \(http.statusCode)).")
        }
        var data = Data()
        for try await byte in bytes {
            guard data.count < 16384 else { throw WardError("Enrollment response exceeds its size limit.") }
            data.append(byte)
        }
        let grant = try JSONDecoder().decode(ServerEnrollmentCommand.Grant.self, from: data)
        let command = try ServerEnrollmentCommand.build(installer: installer, feed: feed, feedKey: feedKey, feedCA: feedCA,
            relay: relay.absoluteString.trimmingCharacters(in: CharacterSet(charactersIn: "/")), relayCA: relayCA,
            serverID: serverID, interval: interval, recipient: recipient, grant: grant)
        try Vault.store(Data(token.utf8), beacon.id.uuidString + ".enrollment")
        return (command, grant.expiry!)
    }

    func verifyServerReport(_ beacon: Beacon, id: String, since: Date) async throws -> (Device, Data) {
        guard id.range(of: "^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$", options: .regularExpression) != nil else {
            throw WardError("Enter a valid server ID.")
        }
        let origin = try Wire.origin(beacon.relay)
        let key = try Vault.recipient()
        guard let token = try Vault.read(beacon.id.uuidString) else { throw WardError("Relay read token missing.") }
        let url = origin.appendingPathComponent("v1/reports").appendingPathComponent(id)
        let envelope = try await Wire.fetch(url, token: token, limit: Wire.maxReport + 61, certificate: beacon.relayCertificate)
        let raw = try Wire.open(envelope, id: id, key: key)
        let report = try Wire.decode(raw)
        let date = (try? Date.ISO8601FormatStyle(includingFractionalSeconds: true).parse(report.generated_at))
            ?? (try? Date.ISO8601FormatStyle().parse(report.generated_at))
        guard let date, date >= since else {
            throw WardError("This report predates the test. Run a new scan and check that the server clock is correct.")
        }
        guard serverArchiveReady else { throw WardError("Server history is not ready. Reopen Ward and check Servers.") }
        let (catalog, latest) = try await serverArchive.accept(raw, beaconID: beacon.id, serverID: id)
        serverCatalog = catalog
        let device = Device(id: beacon.id.uuidString + ":" + id, name: latest.hostName ?? id, report: latest)
        put(device)
        return (device, raw)
    }

    func refresh(_ beacon: Beacon) async {
        await syncServerReports(beacon)
    }
    private func trustFile(_ input: String, named filename: String) throws -> String {
        var path = (input.trimmingCharacters(in: .whitespacesAndNewlines) as NSString).expandingTildeInPath
        var directory: ObjCBool = false
        if FileManager.default.fileExists(atPath: path, isDirectory: &directory), directory.boolValue {
            path = URL(fileURLWithPath: path).appendingPathComponent(filename).path
        }
        guard path.hasPrefix("/"), FileManager.default.fileExists(atPath: path, isDirectory: &directory),
              !directory.boolValue, FileManager.default.isReadableFile(atPath: path) else {
            throw WardError("Cannot read \(filename). Check the file or folder path: \(path)")
        }
        return path
    }
    private func deliverSystemNotification(title: String, body: String) async -> Bool {
        let center = UNUserNotificationCenter.current()
        var settings = await center.notificationSettings()
        if settings.authorizationStatus == .notDetermined {
            _ = try? await center.requestAuthorization(options: [.alert, .sound])
            settings = await center.notificationSettings()
        }
        guard settings.authorizationStatus == .authorized || settings.authorizationStatus == .provisional else {
            notificationIssue = "macOS blocks Ward notifications. Enable them in System Settings → Notifications."
            return false
        }
        notificationIssue = settings.alertSetting == .enabled ? "" : "macOS banners are off. Notifications may appear only in Notification Center."
        let content = UNMutableNotificationContent()
        content.title = title; content.body = body; content.sound = .default
        do {
            try await center.add(UNNotificationRequest(identifier: UUID().uuidString, content: content, trigger: nil))
            return true
        } catch {
            notificationIssue = "Could not send a system notification: " + error.localizedDescription
            return false
        }
    }
    private func postSystemNotification(title: String, body: String) {
        Task { _ = await deliverSystemNotification(title: title, body: body) }
    }

    private func notifyNewFindings(previous: Report?, current: Report) {
        guard preferences.findingNotifications, current.database != nil else { return }
        func keys(_ report: Report) -> Set<[String]> {
            Set(report.findings.filter { $0.status == "affected" }.map {
                [$0.origin ?? "", $0.ecosystem ?? "", $0.component, $0.source ?? "", $0.id]
            })
        }
        if let previous {
            guard previous.database != nil,
                  previous.findings.lazy.filter({ $0.status == "affected" }).count >= previous.confirmed else { return }
        }
        let count = keys(current).subtracting(previous.map(keys) ?? []).count
        if count > 0 {
            postSystemNotification(title: "New security findings",
                                   body: "\(count.formatted()) new advisory matches on This Mac. Open Findings for details.")
        }
    }

    fileprivate func checkApplicationVersions(_ provided: [Report.Inventory.Application]? = nil, showProgress: Bool = false) async {
        guard !checkingAppVersions, !installingApplication, !busy else { return }
        checkingAppVersions = true
        defer {
            checkingAppVersions = false
            if showProgress { applicationCheckProgress = nil }
        }
        let apps: [Report.Inventory.Application]
        if let provided {
            apps = provided
        } else {
            let scanned = devices.first(where: { $0.id == "local" })?.report.inventory.applications ?? []
            apps = scanned + outsideApplications(known: Set(scanned.map(\.identifier)), includeStandardLocations: true)
        }
        let minimumEnd = ContinuousClock.now + .milliseconds(900)
        let jobs = await Task.detached { updateJobs(for: apps) }.value
        async let systemCheck: Result<[SystemSoftwareUpdate], Error> = Task.detached {
            Result { try SystemSoftwareUpdate.check() }
        }.value
        if showProgress { applicationCheckProgress = (0, jobs.count + 1) }
        applicationUpdateNote = "Checking \(jobs.count.formatted()) application update channels."
        var results = await withTaskGroup(of: (String, AppUpdateRecord).self) { group in
            for job in jobs { group.addTask { (job.id, await job.lookup()) } }
            var found: [String: AppUpdateRecord] = [:]
            for await (id, record) in group {
                found[id] = record
                if showProgress { applicationCheckProgress = (found.count, jobs.count + 1) }
            }
            return found
        }
        for (id, failed) in results where failed.reported.isEmpty {
            if var known = appUpdateChecks[id], known.newer, known.installed == failed.installed {
                if !known.text.hasPrefix("Could not refresh.") { known.text = "Could not refresh. " + known.text }
                results[id] = known
            }
        }
        applicationUpdateNote = "Checking macOS software updates…"
        switch await systemCheck {
        case .success(let updates):
            systemSoftwareUpdates = SystemSoftwareUpdate.mergingRestartPending(updates)
            systemUpdateCheckNote = ""
            if let data = try? JSONEncoder().encode(updates) { UserDefaults.standard.set(data, forKey: "ward.system-software-updates.v1") }
        case .failure(let error):
            systemUpdateCheckNote = error.localizedDescription + " Previous results retained."
        }
        if showProgress { applicationCheckProgress = (jobs.count + 1, jobs.count + 1) }
        for (id, record) in results {
            let installed = NSWorkspace.shared.urlForApplication(withBundleIdentifier: id).flatMap { AppUpdateReconciliation.installedVersion(at: $0) }
            results[id] = AppUpdateReconciliation.reconcile(record, installed: installed)
        }
        var notificationResults = results
        for update in systemSoftwareUpdates {
            notificationResults[update.id] = AppUpdateRecord(text: "Available in Software Update", newer: true, canInstall: false, reported: update.version, installed: "")
        }
        // Track delivered notifications separately from discovery/cache. A check
        // while notifications were disabled must not suppress a later alert.
        let observationKey = "ward.application-update-notifications.v2"
        var notified = UserDefaults.standard.dictionary(forKey: observationKey) as? [String: String] ?? [:]
        let installedIDs = Set(apps.map(\.identifier)).union(systemSoftwareUpdates.map(\.id))
        notified = notified.filter { installedIDs.contains($0.key) }
        for (id, record) in notificationResults where !record.reported.isEmpty && !record.newer { notified.removeValue(forKey: id) }
        let pending = AppUpdateAlerts.pending(notificationResults, notified: notified)
        if preferences.applicationNotifications, !pending.isEmpty,
           await deliverSystemNotification(title: "Updates available",
                body: "\(pending.count.formatted()) updates available. Open Applications for details.") {
            for (id, record) in pending { notified[id] = record.reported }
        }
        UserDefaults.standard.set(notified, forKey: observationKey)
        appUpdateChecks.merge(results) { _, new in new }
        AppUpdateStore.save(appUpdateChecks)
        updateAppBadge(appUpdateChecks, for: Set(apps.map(\.identifier)))
        let available = results.values.filter(\.newer).count + systemSoftwareUpdates.count
        applicationUpdateNote = "Checked \(jobs.count.formatted()) channels · \(available.formatted()) updates available."
        if showProgress, ContinuousClock.now < minimumEnd { try? await ContinuousClock().sleep(until: minimumEnd) }
    }

    func dismissScanIssue() { scanIssue = nil }

    private func trackScanProcess(_ process: Process) {
        scanProcess = process
        if cancellingScan && process.isRunning { process.terminate() }
    }

    func showNotice(_ text: String) {
        notice = Notice(text: text, expiry: Date().addingTimeInterval(10))
    }

    func dismissNotice() { notice = nil }

    func cancelScan() {
        guard (scanningMac || updatingScanDatabase), !cancellingScan,
              !updatingScanDatabase || scanProgress?.stage != "updated" else { return }
        cancellingScan = true
        if let scanProcess, scanProcess.isRunning { scanProcess.terminate() }
    }

    func localScan(update: Bool, updateOnly: Bool = false, checkOnly: Bool = false, background: Bool = false, followUp: Bool = true) async {
        guard !busy, !checkingAppVersions, !installingApplication else { return }
        busy = true
        message = ""
        let minimumUpdateEnd = ContinuousClock.now + .milliseconds(900)
        if update { dismissNotice() }
        updatingScanDatabase = update
        scanProgress = nil
        if !updateOnly {
            scanningMac = true
            scanIssue = nil
        }
        activity = update ? (checkOnly ? "Checking for a database update…" : "Updating signed database…") : "Scanning this Mac…"
        var scanAfterUpdate = false
        var checkAppsAfterScan = false
        defer {
            scanProcess = nil
            updatingScanDatabase = false
            cancellingScan = false
            busy = false
            scanningMac = false
            activity = ""
            if checkAppsAfterScan {
                Task { await self.checkApplicationVersions(showProgress: !background) }
            }
        }
        do {
            guard let agent = Bundle.main.url(forAuxiliaryExecutable: "shixpeer-ward-agent") else { throw WardError("Bundled agent missing.") }
            let dest = root.appendingPathComponent("local")
            try FileManager.default.createDirectory(at: dest, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
            let beacon = beacons.first { $0.id == activeFeed }
            var options: [String] = []
            if let beacon {
                guard !beacon.feedKey.isEmpty else { throw WardError("Set the trusted Beacon feed public key path.") }
                let state = root.appendingPathComponent(beacon.id.uuidString)
                options = ["-config", state.appendingPathComponent("agent.json").path, "-state", state.path,
                           "-feed-url", try Wire.origin(beacon.feed).appendingPathComponent("v1/manifest.json").absoluteString,
                           "-trusted-key", try trustFile(beacon.feedKey, named: "feed.pub")]
                if !beacon.caFile.isEmpty { options += ["-ca-file", try trustFile(beacon.caFile, named: "ca.crt")] }
            }
            if update {
                let result = try await Self.run(agent, [checkOnly ? "check-update" : "update", "-progress-json"] + options,
                                                onStart: { [weak self] process in
                    self?.trackScanProcess(process)
                }, onProgress: { [weak self] event in
                    self?.scanProgress = event
                })
                guard !cancellingScan else { return }
                guard result == 0 else { throw WardError("Signed database update failed. Check the Beacon address, TLS CA and signing key.") }
                if checkOnly {
                    databaseUpdateAvailable = scanProgress?.stage == "available"
                    showNotice(databaseUpdateAvailable ? "A signed database update is available." : "Signed database is up to date.")
                    return
                }
                databaseUpdateAvailable = false
                let installedNewRevision = scanProgress?.stage == "updated" && scanProgress?.component == "new-revision"
                scanAfterUpdate = followUp && updateOnly && installedNewRevision && preferences.scanNewDatabase
                if ContinuousClock.now < minimumUpdateEnd {
                    scanProgress = ScanProgress(stage: "updated", component: nil,
                                                done: scanProgress?.done ?? 0, total: scanProgress?.total ?? 0,
                                                matches: nil, review: nil, seconds: nil)
                    try await ContinuousClock().sleep(until: minimumUpdateEnd)
                }
                if updateOnly && !scanAfterUpdate {
                    showNotice(installedNewRevision ? "Signed database updated." : "Signed database is up to date.")
                    return
                }
                scanProgress = nil
                updatingScanDatabase = false
                scanningMac = true
                scanIssue = nil
                activity = scanAfterUpdate ? "Scanning this Mac with the new database…" : "Scanning this Mac…"
            }
            let reportURL = dest.appendingPathComponent("report.json")
            let previous = try? reportURL.resourceValues(forKeys: [.contentModificationDateKey]).contentModificationDate
            let result = try await Self.run(agent, ["scan", "-progress-json", "-report-dir", dest.path] + options,
                                            onStart: { [weak self] process in
                self?.trackScanProcess(process)
            }, onProgress: { [weak self] event in
                self?.scanProgress = event
            })
            guard !cancellingScan else { return }
            let current = try? reportURL.resourceValues(forKeys: [.contentModificationDateKey]).contentModificationDate
            guard current != nil, current != previous else { throw WardError("The agent did not produce a fresh report.") }
            let report = try Wire.decode(Data(contentsOf: reportURL))
            let previousReport = devices.first(where: { $0.id == "local" })?.report
            verifiedFormulas.removeAll()
            if !background && !scanAfterUpdate { devicePath = [] }
            put(Device(id: "local", name: "This Mac", report: report))
            checkAppsAfterScan = followUp
            if result == 0 {
                notifyNewFindings(previous: previousReport, current: report)
                if !background && !scanAfterUpdate { selection = "local" }
                if scanAfterUpdate { showNotice("System scan completed with the new database.") }
            } else {
                scanIssue = ScanIssue(title: "Scan incomplete",
                                      detail: "See Coverage for details. Use Update Database if the signed database is missing or expired.",
                                      showsCoverage: true)
            }
        } catch {
            guard !cancellingScan else { return }
            if updateOnly && !scanAfterUpdate {
                message = error.localizedDescription
            } else {
                scanIssue = ScanIssue(title: updatingScanDatabase ? "Database update failed" : "Scan failed",
                                      detail: error.localizedDescription)
            }
        }
    }
    fileprivate func upgrade(_ action: HomebrewAction, report: Report,
                             log: @escaping @MainActor @Sendable (String) -> Void) async throws {
        guard !busy, verifiedFormulas[[action.formula, action.version]] == nil else {
            throw WardError("This upgrade is unavailable.")
        }
        busy = true
        defer { busy = false; activity = "" }
        activity = "Verifying \(action.formula)…"
        guard let revision = report.database?.revision,
              let agent = Bundle.main.url(forAuxiliaryExecutable: "shixpeer-ward-agent") else {
            throw WardError("Run a fresh local scan before upgrading.")
        }
        let prefix = URL(fileURLWithPath: action.executable).deletingLastPathComponent().deletingLastPathComponent().path
        var options = ["scan", "-verify-formula", action.formula, "-brew-prefix", prefix]
        if let beacon = beacons.first(where: { $0.id == activeFeed }) {
            let state = root.appendingPathComponent(beacon.id.uuidString)
            options += ["-config", state.appendingPathComponent("agent.json").path, "-state", state.path,
                        "-trusted-key", try trustFile(beacon.feedKey, named: "feed.pub")]
        }
        let singleVersion = action.olderCopy || action.alreadyChanged
        let tracked = report.findings.filter {
            $0.status == "affected" && $0.origin == "homebrew-formula" && $0.component == action.formula
                && !isVerified($0) && (!singleVersion || $0.installed_version == action.version)
        }
        let ids = Set(tracked.map(\.id)).sorted()
        guard !ids.isEmpty, ids.allSatisfy({ $0.range(of: "^[A-Za-z0-9][A-Za-z0-9._:+~-]*$", options: .regularExpression) != nil }) else {
            throw WardError("No valid advisory IDs to recheck.")
        }
        let verifyArgs = options + ["-verify-advisories", ids.joined(separator: ",")]
        let before = try await Self.verifyFormula(agent, verifyArgs)
        guard before.database?.revision == revision else {
            throw WardError("The database changed. Scan This Mac again before upgrading.")
        }
        var after = before
        if action.alreadyChanged {
            guard before.components?.contains(where: { $0.version == action.version }) == false else {
                throw WardError("The installed package changed again. Run a fresh scan.")
            }
        } else {
            let priorMatches = before.findings.filter {
                $0.status == "affected" && (!singleVersion || $0.installed_version == action.version)
            }
            guard before.components?.contains(where: { $0.version == action.version }) == true,
                  (singleVersion || before.confirmed == tracked.count),
                  Set(priorMatches.map { [$0.id, $0.installed_version] })
                    == Set(tracked.map { [$0.id, $0.installed_version] }) else {
                throw WardError("The installed package changed. Scan This Mac again before upgrading.")
            }
            log("Installed before: " + (before.components ?? []).map(\.version).joined(separator: ", "))
            var noUpgradeAvailable = false
            if action.olderCopy {
                activity = "Checking the cleanup plan…"
                let preview = try await Self.runHomebrew(action, arguments: ["cleanup", "-n", action.formula], log: log)
                let expected = "Would remove: \(prefix)/Cellar/\(action.formula)/\(action.version)"
                let removals = preview.lines.filter { $0.hasPrefix("Would remove:") }
                guard preview.status == 0, removals.count == 1,
                      removals.first.map({ $0 == expected || $0.hasPrefix(expected + " (") }) == true else {
                    throw WardError("The cleanup plan must remove only the selected old version. See command output.")
                }
                let active = URL(fileURLWithPath: prefix + "/opt/" + action.formula).resolvingSymlinksInPath()
                guard active.deletingLastPathComponent().path == prefix + "/Cellar/" + action.formula,
                      active.lastPathComponent != action.version,
                      FileManager.default.fileExists(atPath: active.path) else {
                    throw WardError("The active Homebrew version could not be verified. Cleanup cancelled.")
                }
                activity = "Removing \(action.formula) \(action.version)…"
                let cleanup = try await Self.runHomebrew(action, arguments: ["cleanup", action.formula], log: log)
                guard cleanup.status == 0 else {
                    throw WardError("Homebrew cleanup failed (exit \(cleanup.status)). See command output.")
                }
            } else {
                activity = "Checking Homebrew for \(action.formula) updates…"
                try await Self.requireHomebrewUpgrade(action, log: log)
                activity = "Upgrading \(action.formula)…"
                let upgrade = try await Self.runHomebrew(action, arguments: ["upgrade", "--formula", action.formula], log: log)
                noUpgradeAvailable = upgrade.lines.contains("Warning: \(action.formula) \(action.version) already installed")
                guard upgrade.status == 0 else {
                    throw WardError("Homebrew upgrade failed (exit \(upgrade.status)). See command output.")
                }
            }
            activity = "Rechecking \(action.formula)…"
            after = try await Self.verifyFormula(agent, verifyArgs)
            log("Installed after: " + (after.components ?? []).map(\.version).joined(separator: ", "))
            guard Set(after.components?.map(\.version) ?? []) != Set(before.components?.map(\.version) ?? []) else {
                let detail = noUpgradeAvailable
                    ? "Homebrew reports that this version is already installed and offered no upgrade."
                    : "The installed versions did not change."
                throw FindingStaysOpen(message: detail + " The database finding remains open.",
                                       noUpgradeAvailable: noUpgradeAvailable)
            }
        }
        guard after.database?.revision == revision,
              let components = after.components, !components.isEmpty,
              components.allSatisfy({ !["NOT_CHECKED", "INCOMPLETE"].contains($0.result) }),
              singleVersion ? !components.contains(where: { $0.version == action.version })
                            : (after.confirmed == 0 && after.requires_review == 0) else {
            throw FindingStaysOpen(message: "The tracked advisories still match or need review. The finding remains open.")
        }
        if singleVersion {
            log("Targeted scan: \(action.formula) \(action.version) is no longer installed. Other versions remain tracked separately.")
        } else {
            log("Targeted scan: \(after.confirmed) matches, \(after.requires_review) to review.")
        }
        for (version, findings) in Dictionary(grouping: tracked, by: \.installed_version) {
            verifiedFormulas[[action.formula, version]] = findings.count
        }
    }

    nonisolated private static func verifyFormula(_ agent: URL, _ args: [String]) async throws -> Report {
        try await Task.detached {
            let process = Process()
            let output = Pipe()
            process.executableURL = agent
            process.arguments = args
            process.standardOutput = output
            process.standardError = FileHandle.nullDevice
            try process.run()
            try output.fileHandleForWriting.close()
            let data = try output.fileHandleForReading.readToEnd() ?? Data()
            process.waitUntilExit()
            guard process.terminationStatus == 0 else { throw WardError("Targeted Homebrew scan failed.") }
            return try Wire.decode(data)
        }.value
    }

    nonisolated private static func requireHomebrewUpgrade(
        _ action: HomebrewAction, log: @escaping @MainActor @Sendable (String) -> Void
    ) async throws {
        struct Catalog: Decodable {
            struct Formula: Decodable {
                let name: String
                let pinned: Bool
            }
            let formulae: [Formula]
        }
        let check = try await runHomebrew(action, arguments: ["outdated", "--json=v2", "--formula", action.formula],
                                         log: log, captureJSON: true)
        guard let catalog = try? JSONDecoder().decode(Catalog.self, from: Data(check.json.utf8)) else {
            throw WardError("Could not read the Homebrew catalog check. See command output.")
        }
        if check.status == 0 && catalog.formulae.isEmpty {
            throw FindingStaysOpen(message: "The local Homebrew catalog offers no newer build. The database finding remains open.",
                                   noUpgradeAvailable: true)
        }
        // Named outdated queries can exit 1 when a newer version exists.
        guard [0, 1].contains(check.status), catalog.formulae.count == 1,
              let formula = catalog.formulae.first,
              [action.formula, "homebrew/core/" + action.formula].contains(formula.name) else {
            throw WardError("Homebrew could not confirm an update for this formula. See command output.")
        }
        if formula.pinned {
            throw FindingStaysOpen(message: "Homebrew has a newer build, but this formula is pinned. Review the pin before upgrading.",
                                   noUpgradeAvailable: true)
        }
    }

    nonisolated private static func runHomebrew(_ action: HomebrewAction, arguments: [String],
                                               log: @escaping @MainActor @Sendable (String) -> Void,
                                               captureJSON: Bool = false)
        async throws -> (status: Int32, lines: Set<String>, json: String) {
        await log("$ " + ([action.executable] + arguments).joined(separator: " "))
        return try await Task.detached {
            let process = Process()
            let brewBin = URL(fileURLWithPath: action.executable).deletingLastPathComponent().path
            process.executableURL = URL(fileURLWithPath: action.executable)
            process.arguments = arguments
            process.currentDirectoryURL = URL(fileURLWithPath: "/")
            guard let curl = Bundle.main.url(forResource: "BrewCurl", withExtension: "sh") else { throw WardError("Bundled Homebrew metadata transport missing. Rebuild Ward.") }
            let env = [
                "HOMEBREW_CURL_PATH": curl.path,
                "HOMEBREW_API_DOMAIN": OfficialWardBackend.origin.appendingPathComponent("v1/homebrew").absoluteString,
                "HOMEBREW_NO_AUTO_UPDATE": "1",
                "HOME": FileManager.default.homeDirectoryForCurrentUser.path,
                "PATH": brewBin + ":/usr/bin:/bin:/usr/sbin:/sbin",
                "HOMEBREW_NO_ANALYTICS": "1",
                "HOMEBREW_NO_INSTALL_CLEANUP": "1",
            ]
            process.environment = env
            process.standardInput = FileHandle.nullDevice
            let output = Pipe()
            process.standardOutput = output
            if !captureJSON { process.standardError = output }
            try process.run()
            try output.fileHandleForWriting.close()
            var json = ""
            var jsonOverflow = false
            var matches: Set<String> = []
            for try await line in output.fileHandleForReading.bytes.lines {
                if captureJSON && !jsonOverflow {
                    if json.utf8.count + line.utf8.count < 64 * 1024 {
                        json += line + "\n"
                    } else {
                        jsonOverflow = true
                    }
                }
                let trimmed = line.trimmingCharacters(in: .whitespaces)
                if trimmed == "Warning: \(action.formula) \(action.version) already installed" {
                    matches.insert(trimmed)
                }
                if trimmed == action.formula || (trimmed.hasPrefix("Would remove:") && matches.count < 2) {
                    matches.insert(trimmed)
                }
                await log(line)
            }
            process.waitUntilExit()
            await log("Exit code: \(process.terminationStatus)")
            return (process.terminationStatus, matches, jsonOverflow ? "" : json)
        }.value
    }

    nonisolated private static func run(_ url: URL, _ args: [String],
                                        onStart: (@MainActor @Sendable (Process) -> Void)? = nil,
                                        onProgress: (@MainActor @Sendable (ScanProgress) -> Void)? = nil) async throws -> Int32 {
        try await Task.detached {
            let p = Process()
            p.executableURL = url
            p.arguments = args
            var env = ProcessInfo.processInfo.environment
            let home = FileManager.default.homeDirectoryForCurrentUser.path
            let paths = ["/opt/homebrew/bin", "/usr/local/bin", home + "/.docker/bin", "/usr/bin", "/bin", "/usr/sbin", "/sbin"]
            env["PATH"] = paths.joined(separator: ":")
            p.environment = env
            p.standardOutput = FileHandle.nullDevice
            let progressPipe = onProgress.map { _ in Pipe() }
            if let progressPipe { p.standardError = progressPipe }
            else { p.standardError = FileHandle.nullDevice }
            try p.run()
            await onStart?(p)
            if let progressPipe, let onProgress {
                try progressPipe.fileHandleForWriting.close()
                let decoder = JSONDecoder()
                for try await line in progressPipe.fileHandleForReading.bytes.lines {
                    if let event = try? decoder.decode(ScanProgress.self, from: Data(line.utf8)) {
                        await onProgress(event)
                    }
                }
            }
            p.waitUntilExit()
            return p.terminationStatus
        }.value
    }
}

@MainActor final class WardAppDelegate: NSObject, NSApplicationDelegate, UNUserNotificationCenterDelegate {
    private var statusMenu: WardStatusMenu?
    private weak var model: WardModel?
    private var explicitlyQuitting = false
    static weak var current: WardAppDelegate?
    override init() {
        super.init()
        Self.current = self
        UNUserNotificationCenter.current().delegate = self
    }

    func connectStatusMenu(to model: WardModel, openPage: @escaping (String) -> Void) {
        self.model = model
        if let statusMenu {
            statusMenu.openPage = openPage
        } else {
            statusMenu = WardStatusMenu(model: model, openPage: openPage)
        }
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { false }

    func quitCompletely() {
        explicitlyQuitting = true
        model?.cancelScan()
        NSApp.terminate(nil)
    }

    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        let reason = NSAppleEventManager.shared().currentAppleEvent?.paramDescriptor(forKeyword: AEKeyword(kAEQuitReason))?.enumCodeValue
        // Never obstruct logout, shutdown, restart or an explicit Quit Ward.
        let systemQuitReasons = [kAEQuitAll, kAEShutDown, kAERestart, kAEReallyLogOut, kAELogOut].map { OSType($0) }
        if explicitlyQuitting || reason.map({ systemQuitReasons.contains($0) }) == true { return .terminateNow }
        statusMenu?.enterBackground()
        return .terminateCancel
    }

    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows: Bool) -> Bool {
        guard !hasVisibleWindows, let statusMenu else { return true }
        statusMenu.reopen()
        return false
    }

    nonisolated func userNotificationCenter(_ center: UNUserNotificationCenter,
                                           willPresent notification: UNNotification) async -> UNNotificationPresentationOptions {
        [.banner, .list, .sound]
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        UNUserNotificationCenter.current().delegate = self
        if let url = Bundle.main.url(forResource: "WardMatte", withExtension: "icns"),
           let icon = NSImage(contentsOf: url) {
            NSApplication.shared.applicationIconImage = icon
        }
    }
}

@main struct WardApp: App {
    @NSApplicationDelegateAdaptor(WardAppDelegate.self) private var appDelegate
    @StateObject private var model = WardModel()
    var body: some Scene {
        WindowGroup("Shixpeer Ward", id: "ward-main") {
            WardMainWindow(model: model, appDelegate: appDelegate)
        }
        .windowStyle(.hiddenTitleBar)
        .commands {
            CommandGroup(replacing: .appTermination) {
                Button("Quit Ward") { appDelegate.quitCompletely() }.keyboardShortcut("q")
            }
        }
    }
}

private struct WardMainWindow: View {
    @ObservedObject var model: WardModel
    let appDelegate: WardAppDelegate
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        Dashboard(model: model)
            .environmentObject(model)
            .frame(minWidth: 820, minHeight: 540)
            .focusEffectDisabled()
            .onAppear {
                model.startLaunchChecks()
                if NSApp.activationPolicy() != .regular { NSApp.setActivationPolicy(.regular) }
                appDelegate.connectStatusMenu(to: model) { page in
                    model.selection = page
                    if let window = NSApp.windows.first(where: { $0.title == "Shixpeer Ward" && $0.canBecomeKey }) {
                        window.makeKeyAndOrderFront(nil)
                    } else {
                        openWindow(id: "ward-main")
                    }
                    NSApp.activate(ignoringOtherApps: true)
                }
            }
    }
}

@MainActor private final class WardStatusMenu: NSObject, NSMenuDelegate {
    private weak var model: WardModel?
    var openPage: (String) -> Void
    private var observer: AnyCancellable?
    private var windowObserver: AnyCancellable?
    private var item: NSStatusItem?
    private var refreshPending = false
    private let menu = NSMenu()

    init(model: WardModel, openPage: @escaping (String) -> Void) {
        self.model = model
        self.openPage = openPage
        super.init()
        menu.delegate = self
        menu.autoenablesItems = false
        observer = model.objectWillChange.sink { [weak self] in
            self?.scheduleRefresh()
        }
        windowObserver = NotificationCenter.default.publisher(for: NSWindow.willCloseNotification)
            .sink { [weak self] _ in self?.scheduleDockRefresh() }
        refresh()
    }

    private func scheduleDockRefresh() {
        Task { @MainActor [weak self] in
            await Task.yield()
            self?.refresh()
            self?.refreshDockVisibility()
        }
    }

    func enterBackground() {
        for window in NSApp.windows where window.styleMask.contains(.titled) { window.orderOut(nil) }
        refresh()
        refreshDockVisibility()
    }

    func reopen() { show("home") }

    private func refreshDockVisibility() {
        guard model != nil else { return }
        let hasWindow = NSApp.windows.contains { $0.isVisible && $0.canBecomeKey && $0.styleMask.contains(.titled) }
        let policy: NSApplication.ActivationPolicy = !hasWindow ? .accessory : .regular
        if NSApp.activationPolicy() != policy { NSApp.setActivationPolicy(policy) }
    }

    private func scheduleRefresh() {
        guard !refreshPending else { return }
        refreshPending = true
        Task { @MainActor [weak self] in
            guard let self else { return }
            refreshPending = false
            refresh()
        }
    }

    private func refresh() {
        guard let model else { return }
        let hasWindow = NSApp.windows.contains { $0.isVisible && $0.canBecomeKey && $0.styleMask.contains(.titled) }
        guard model.preferences.menuBar || !hasWindow else {
            if let item {
                NSStatusBar.system.removeStatusItem(item)
                self.item = nil
                if NSApp.activationPolicy() != .regular { NSApp.setActivationPolicy(.regular) }
            }
            return
        }
        if item == nil {
            item = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
            item?.menu = menu
        }
        let count = model.availableAppUpdateIDs.filter { id in
            model.appUpdateChecks[id].map { currentlyNeedsAppUpdate(id, record: $0) } == true
        }.count + model.systemSoftwareUpdates.count
        let image = NSImage(size: NSSize(width: 22, height: 20), flipped: false) { _ in
            NSImage(systemSymbolName: "shield", accessibilityDescription: nil)?
                .draw(in: NSRect(x: 1, y: 1, width: 16, height: 18))
            if count > 0 {
                NSImage(systemSymbolName: "exclamationmark.circle.fill", accessibilityDescription: nil)?
                    .draw(in: NSRect(x: 12, y: 10, width: 10, height: 10))
            }
            return true
        }
        image.isTemplate = true
        item?.button?.image = image
        item?.button?.toolTip = count > 0 ? "Shixpeer Ward · \(count) application updates available" : "Shixpeer Ward · Ready"
        item?.button?.setAccessibilityLabel(count > 0 ? "Ward: \(count) application updates available" : "Ward")
    }

    func menuNeedsUpdate(_ menu: NSMenu) {
        guard let model else { return }
        menu.removeAllItems()
        model.refreshLoginStatus()
        let unavailable = model.busy || model.checkingAppVersions || model.installingApplication
        add("Open Ward", action: #selector(showWard))
        add("Available Application Updates", action: #selector(showUpdates))
        menu.addItem(.separator())
        add("Update Database Now", action: #selector(update), enabled: !unavailable)
        add("Check for Database Update", action: #selector(checkDatabase), enabled: !unavailable)
        add("Scan This Mac", action: #selector(scan), enabled: !unavailable)
        add("Check Application Versions", action: #selector(checkApps), enabled: !unavailable)
        add("Cancel Current Task", action: #selector(stop), enabled: (model.scanningMac || model.updatingScanDatabase) && !model.cancellingScan)
        menu.addItem(.separator())
        add("Launch at Login", action: #selector(toggleLogin))
        menu.items.last?.state = model.launchAtLogin ? .on : .off
        if model.loginStatus == .requiresApproval {
            add("Approve in Login Items…", action: #selector(openLoginItems))
        }
        add("Settings…", action: #selector(settings))
        add("Quit Ward", action: #selector(quit))
    }

    private func add(_ title: String, action: Selector?, enabled: Bool = true) {
        let entry = NSMenuItem(title: title, action: action, keyEquivalent: "")
        entry.target = self
        entry.isEnabled = action != nil && enabled
        menu.addItem(entry)
    }

    private func show(_ page: String) {
        menu.cancelTracking()
        if NSApp.activationPolicy() != .regular { NSApp.setActivationPolicy(.regular) }
        openPage(page)
    }
    @objc private func showWard() { show("home") }
    @objc private func showUpdates() { show("local:applications") }
    @objc private func update() { show("database"); Task { await model?.localScan(update: true, updateOnly: true) } }
    @objc private func checkDatabase() { show("database"); Task { await model?.localScan(update: true, updateOnly: true, checkOnly: true) } }
    @objc private func scan() { show("local"); Task { await model?.localScan(update: false) } }
    @objc private func checkApps() { show("local:applications"); Task { await model?.checkApplicationVersions(showProgress: true) } }
    @objc private func stop() { show("local"); model?.cancelScan() }
    @objc private func toggleLogin() {
        show("settings")
        guard let model else { return }
        model.setLaunchAtLogin(!model.launchAtLogin)
    }
    @objc private func openLoginItems() { show("settings"); SMAppService.openSystemSettingsLoginItems() }
    @objc private func settings() { show("settings") }
    @objc private func quit() { WardAppDelegate.current?.quitCompletely() }
}

private struct WardSettingsPage: View {
    @ObservedObject var model: WardModel
    @State private var notificationAuthorization: UNAuthorizationStatus?
    @State private var notificationBanners = true

    private func refreshNotificationPermission() async {
        let settings = await UNUserNotificationCenter.current().notificationSettings()
        notificationAuthorization = settings.authorizationStatus
        notificationBanners = settings.alertSetting == .enabled
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                Text("Settings").font(.largeTitle.weight(.semibold))
                section("Menu bar", symbol: "menubar.rectangle") {
                    Toggle("Show Ward in the menu bar", isOn: $model.preferences.menuBar)
                    Text("Closing the window or quitting from the Dock keeps Ward in the menu bar. Use Quit Ward to exit completely.")
                        .font(.caption).foregroundStyle(.secondary)
                }
                section("Startup", symbol: "power") {
                    Toggle("Check database, scan and application versions on launch", isOn: $model.preferences.launchChecks)
                    Toggle("Launch Ward at login", isOn: Binding(get: { model.launchAtLogin }, set: model.setLaunchAtLogin))
                    if model.loginStatus == .requiresApproval {
                        Button("Approve in Login Items…") { SMAppService.openSystemSettingsLoginItems() }
                    }
                }
                section("Signed database", symbol: "externaldrive.fill") {
                    interval("Check for database updates", selection: $model.preferences.databaseMinutes)
                    Toggle("Download available database updates automatically", isOn: $model.preferences.downloadDatabase)
                        .disabled(model.preferences.databaseMinutes == 0 && !model.preferences.launchChecks)
                    Text("Uses your selected Beacon. With automatic downloads off, Ward checks the signed manifest only.")
                        .font(.caption).foregroundStyle(.secondary)
                    if model.databaseUpdateAvailable {
                        Label("Database update available", systemImage: "arrow.down.circle")
                            .foregroundStyle(.orange)
                    }
                }
                section("System scan", symbol: "magnifyingglass") {
                    interval("Scan this Mac using the local database", selection: $model.preferences.scanMinutes)
                    Toggle("Scan once after installing a new database", isOn: $model.preferences.scanNewDatabase)
                    Text("Scans run offline. The after-update scan starts only after a newer signed revision is installed, independently of the schedule.")
                        .font(.caption).foregroundStyle(.secondary)
                    if model.scanningMac {
                        Label(model.activity, systemImage: "magnifyingglass").foregroundStyle(.secondary)
                    } else if let last = model.devices.first(where: { $0.id == "local" })?.report.generated_at,
                              let date = (try? Date.ISO8601FormatStyle(includingFractionalSeconds: true).parse(last))
                                    ?? (try? Date.ISO8601FormatStyle().parse(last)) {
                        LabeledContent("Last system scan", value: date.formatted(date: .abbreviated, time: .shortened))
                    }
                }
                section("Notifications", symbol: "bell") {
                    Toggle("Application and system updates", isOn: $model.preferences.applicationNotifications)
                    Toggle("New security findings", isOn: $model.preferences.findingNotifications)
                    Button("Send test notification", systemImage: "bell.badge") {
                        Task { await model.sendTestNotification(); await refreshNotificationPermission() }
                    }.wardGlassButton()
                    if !model.notificationIssue.isEmpty {
                        Label(model.notificationIssue, systemImage: "exclamationmark.triangle").font(.callout).foregroundStyle(.orange)
                    }
                    Text("Applies to launch, manual and scheduled checks.")
                        .font(.caption).foregroundStyle(.secondary)
                    if notificationAuthorization == .denied {
                        Label("macOS blocks Ward notifications. Enable them in System Settings → Notifications.", systemImage: "bell.slash")
                            .font(.caption).foregroundStyle(.orange)
                    } else if notificationAuthorization == .authorized && !notificationBanners {
                        Label("macOS banners are off. Enable banners for Ward in System Settings → Notifications.", systemImage: "bell.badge")
                            .font(.caption).foregroundStyle(.orange)
                    } else if notificationAuthorization == .authorized {
                        Text("macOS notifications allowed").font(.caption).foregroundStyle(.secondary)
                    }
                }
                section("Application versions", symbol: "macwindow") {
                    interval("Check installed applications for new versions", selection: $model.preferences.applicationMinutes)
                    Text("Checks supported update channels while Ward is running.")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }
            .frame(maxWidth: 720, alignment: .leading)
            .padding(28)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .onAppear { model.refreshLoginStatus() }
        .task { await refreshNotificationPermission() }
        .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)) { _ in
            model.refreshLoginStatus()
            Task { await refreshNotificationPermission() }
        }
    }

    private func interval(_ title: String, selection: Binding<Int>) -> some View {
        Picker(title, selection: selection) {
            Text("Manual only").tag(0)
            Text("Every 15 minutes").tag(15)
            Text("Every 30 minutes").tag(30)
            Text("Every hour").tag(60)
            Text("Every 6 hours").tag(360)
            Text("Every day").tag(1440)
        }
        .pickerStyle(.menu)
    }

    private func section<Content: View>(_ title: String, symbol: String, @ViewBuilder content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            Label(title, systemImage: symbol).font(.headline)
            content()
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .wardGlass(radius: 16)
    }
}


private struct MenuGlyph: View {
    let symbol: String
    let tint: Color
    let selected: Bool

    var body: some View {
        ZStack {
            if selected {
                Circle().fill(Color.white.opacity(0.85)).frame(width: 8, height: 8).blur(radius: 3.5).offset(x: -13, y: -13)
                Circle().fill(tint.opacity(0.95)).frame(width: 7, height: 7).blur(radius: 3).offset(x: 13, y: 12)
            }
            RoundedRectangle(cornerRadius: 9, style: .continuous)
                .fill(LinearGradient(colors: [tint, tint.opacity(0.62)], startPoint: .top, endPoint: .bottom))
                .frame(width: 28, height: 28)
                .overlay {
                    LinearGradient(colors: [Color.white.opacity(0.5), Color.white.opacity(0)], startPoint: .top, endPoint: .center)
                        .clipShape(RoundedRectangle(cornerRadius: 9, style: .continuous))
                }
                .overlay {
                    Image(systemName: symbol)
                        .font(.system(size: 13, weight: .semibold))
                        .foregroundStyle(.white)
                        .shadow(color: .black.opacity(0.28), radius: 1, y: 1)
                }
                .shadow(color: tint.opacity(selected ? 0.75 : 0.28), radius: selected ? 8 : 3, y: 1)
        }
        .frame(width: 34, height: 34)
    }
}

private struct MenuRow: View {
    let title: String
    let symbol: String
    let tint: Color
    let count: Int?
    let selected: Bool
    let action: () -> Void
    @State private var hovering = false

    var body: some View {
        Button(action: action) {
            HStack(spacing: 10) {
                MenuGlyph(symbol: symbol, tint: tint, selected: selected)
                Text(title)
                    .font(.system(size: 13.5, weight: selected ? .semibold : .medium))
                    .foregroundStyle(selected ? Color.primary : Color.primary.opacity(0.86))
                    .lineLimit(1)
                Spacer(minLength: 6)
                if let count {
                    Text(count.formatted())
                        .font(.caption.monospacedDigit())
                        .foregroundStyle(.secondary)
                }
            }
            .padding(.horizontal, 8)
            .padding(.vertical, 4)
            .background {
                if selected || hovering {
                    RoundedRectangle(cornerRadius: 13, style: .continuous)
                        .fill(Color.white.opacity(selected ? 0.10 : 0.05))
                        .overlay {
                            RoundedRectangle(cornerRadius: 13, style: .continuous)
                                .strokeBorder(Color.white.opacity(selected ? 0.16 : 0.06))
                        }
                }
            }
            .contentShape(RoundedRectangle(cornerRadius: 13, style: .continuous))
        }
        .buttonStyle(.plain).wardPointer()
        .onHover { hovering = $0 }
    }
}

private struct SplitSeam: NSViewRepresentable {
    func makeNSView(context: Context) -> NSView { SeamView() }
    func updateNSView(_ nsView: NSView, context: Context) {}

    final class SeamView: NSView {
        private var applying = false

        override func viewDidMoveToWindow() {
            super.viewDidMoveToWindow()
            restyle()
        }

        override func layout() {
            super.layout()
            restyle()
        }

        private func restyle() {
            guard !applying, let root = window?.contentView else { return }
            applying = true
            defer { applying = false }
            if let split = findSplit(root) {
                split.dividerStyle = .thick
                for column in split.arrangedSubviews {
                    clearMaterial(column)
                }
            }
            hideSidebarToggle()
            unifyTitlebar()
            clearMaterial(root)
        }

        private func unifyTitlebar() {
            guard let window else { return }
            window.titlebarAppearsTransparent = true
            window.titlebarSeparatorStyle = .none
            window.styleMask.insert(.fullSizeContentView)
            window.toolbar?.showsBaselineSeparator = false
            window.backgroundColor = NSColor(srgbRed: 0.20, green: 0.11, blue: 0.36, alpha: 1)
            window.titleVisibility = .hidden
            guard let content = window.contentView else { return }
            func walk(_ view: NSView) {
                let name = String(describing: type(of: view))
                if name == "NSTitlebarBackgroundView" || name.contains("TitlebarSeparator") || name.contains("ToolbarSeparator") {
                    if view.alphaValue != 0 { view.alphaValue = 0 }
                } else if name == "_NSGraphicsView" {
                    view.wantsLayer = true
                    view.layer?.backgroundColor = NSColor.clear.cgColor
                }
                for child in view.subviews { walk(child) }
            }
            walk(content)
        }

        private func hideSidebarToggle() {
            guard let root = window?.contentView else { return }
            if let toolbar = window?.toolbar {
                while let index = toolbar.items.firstIndex(where: { item in
                    let text = item.label + " " + (item.toolTip ?? "") + " " + item.itemIdentifier.rawValue
                    return text.localizedCaseInsensitiveContains("sidebar")
                }) {
                    toolbar.removeItem(at: index)
                }
            }
            hideSidebarButtons(root)
        }

        private func hideSidebarButtons(_ view: NSView) {
            if let button = view as? NSButton {
                let text = button.title + " " + (button.toolTip ?? "") + " " + (button.identifier?.rawValue ?? "")
                if text.localizedCaseInsensitiveContains("sidebar") { button.isHidden = true }
            }
            for child in view.subviews { hideSidebarButtons(child) }
        }

        private func findSplit(_ view: NSView) -> NSSplitView? {
            if let split = view as? NSSplitView { return split }
            for child in view.subviews {
                if let found = findSplit(child) { return found }
            }
            return nil
        }

        private func clearMaterial(_ view: NSView) {
            if let effect = view as? NSVisualEffectView, effect.maskImage == nil {
                // The mask hides the sidebar material and leaves the rows in place.
                let clear = NSImage(size: NSSize(width: 1, height: 1), flipped: false) { _ in true }
                effect.maskImage = clear
            }
            for child in view.subviews { clearMaterial(child) }
        }
    }
}

struct Dashboard: View {
    @ObservedObject var model: WardModel
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var importing = false
    @State private var renamingReport: Device?
    @State private var reportName = ""
    @State private var importDropTarget = false
    @State private var beaconDraft: Beacon?
    @State private var connectingServer = false
    @State private var beaconProfiles: [BeaconProfile] = []
    @State private var profileProblems: [String] = []
    @State private var removing: Beacon?
    @State private var menuSection: MenuSection?
    @State private var menuDrill = false
    private var showsLocalMac: Bool { LocalRoute.isLocal(model.selection) }
    private var localReport: Report? { model.devices.first { $0.id == "local" }?.report }
    private var applicationAttentionCount: Int? {
        let updates = model.availableAppUpdateIDs
        let apps = localReport?.inventory.applications ?? []
        let matching = apps.filter { updates.contains($0.identifier) || localReport?.appFindings(for: $0).isEmpty == false }
        let extra = updates.subtracting(apps.map(\.identifier))
        let count = matching.count + extra.union(model.systemSoftwareUpdates.map(\.id)).count
        return count > 0 ? count : nil
    }

    var body: some View {
        Group {
            if model.scanningMac || model.updatingScanDatabase || model.scanIssue != nil {
                MacScanView(progress: model.scanProgress, updating: model.updatingScanDatabase,
                            startsScan: model.scanningMac,
                            issue: model.scanIssue, cancelling: model.cancellingScan,
                            cancel: model.cancelScan, close: model.dismissScanIssue,
                            update: { Task { await model.localScan(update: true) } },
                            showCoverage: {
                                openPage("local:coverage")
                                model.dismissScanIssue()
                            })
            } else {
                HStack(spacing: 0) {
                    sidebar
                        .frame(width: 236)
                    detail
                        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
                }
                .opacity(model.applicationCheckProgress == nil ? 1 : 0)
                .allowsHitTesting(model.applicationCheckProgress == nil)
                .accessibilityHidden(model.applicationCheckProgress != nil)
                .overlay {
                    if let progress = model.applicationCheckProgress {
                        ApplicationCheckScreen(completed: progress.completed, total: progress.total)
                    }
                }
            }
        }
        .ignoresSafeArea(edges: .top)
        .background {
            ZStack {
                AlignedCanvas()
                pageWash
            }
            .ignoresSafeArea()
        }
        .background { SplitSeam() }
        .toolbar(removing: .sidebarToggle)
        .tint(.indigo)
        .onChange(of: model.selection) { _, newValue in
            if let routed = LocalRoute.path(for: newValue) {
                if newValue == "local" {
                    if !model.devicePath.isEmpty { model.devicePath = [] }
                } else if model.devicePath.first != routed.first {
                    model.devicePath = routed
                }
            }
            if newValue == "settings" {
                menuDrill = false
                menuSection = nil
            } else if let section = section(for: newValue), menuSection != section {
                menuDrill = true
                menuSection = section
            }
        }
        .overlay(alignment: .bottomTrailing) {
            if let notice = model.notice {
                HStack(spacing: 12) {
                    Image(systemName: "checkmark.circle.fill").foregroundStyle(.mint)
                        .accessibilityHidden(true)
                    Text(notice.text).font(.callout.weight(.medium))
                    Button(action: model.dismissNotice) {
                        Image(systemName: "xmark").font(.caption.weight(.semibold))
                            .frame(width: 28, height: 28)
                            .contentShape(Rectangle())
                    }
                    .buttonStyle(.plain).wardPointer()
                    .accessibilityLabel("Dismiss notification")
                }
                .padding(.leading, 16)
                .padding(.trailing, 8)
                .padding(.vertical, 9)
                .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 14))
                .wardBanner(tint: .mint)
                .shadow(color: .black.opacity(0.25), radius: 12, y: 4)
                .padding(24)
                .transition(reduceMotion ? .opacity : .opacity.combined(with: .offset(y: 14)))
                .task(id: notice) {
                    do {
                        try await Task.sleep(for: .seconds(max(0, notice.expiry.timeIntervalSinceNow)))
                        if model.notice == notice { model.dismissNotice() }
                    } catch {}
                }
            }
        }
        .animation(.easeInOut(duration: 0.24), value: model.notice)
        .sheet(isPresented: $connectingServer) {
            ServerSetupWizard(model: model) { id in
                connectingServer = false
                openPage(id)
            }
        }
        .sheet(item: $beaconDraft) { draft in BeaconForm(model: model, draft: draft) }
        .confirmationDialog("Remove Beacon from this app?", isPresented: Binding(
            get: { removing != nil }, set: { if !$0 { removing = nil } }), presenting: removing) { beacon in
            Button("Remove " + beacon.name, role: .destructive) {
                do { try model.removeBeacon(beacon) }
                catch { model.message = error.localizedDescription }
            }
            Button("Cancel", role: .cancel) {}
        } message: { _ in
            Text("The connection and fetched reports will disappear from this app. Files in the trust folder and data on the server are kept.")
        }
        .alert("Rename Report", isPresented: Binding(
            get: { renamingReport != nil },
            set: { if !$0 { renamingReport = nil } }
        ), presenting: renamingReport) { device in
            TextField("Report name", text: $reportName)
            Button("Cancel", role: .cancel) {}
            Button("Save") { model.renameImportedReport(device, to: reportName) }
                .disabled(reportName.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ||
                          reportName.trimmingCharacters(in: .whitespacesAndNewlines).count > 120)
        }
        .fileImporter(isPresented: $importing, allowedContentTypes: [.json], allowsMultipleSelection: true) { result in
            do { model.importReports(try result.get()) }
            catch { model.message = error.localizedDescription }
        }
    }

    private func renameReport(_ device: Device) {
        reportName = device.name
        renamingReport = device
    }

    private var sidebar: some View {
        GeometryReader { proxy in
            ScrollView {
                Group {
                    if let section = menuSection {
                        VStack(alignment: .leading, spacing: 10) {
                            backButton
                            innerRows(section)
                        }
                        .transition(menuSlide)
                    } else {
                        VStack(alignment: .leading, spacing: 16) {
                            rootRow(.mac, "This Mac", "display", Color(red: 0.62, green: 0.68, blue: 0.98))
                            rootRow(.reports, "Imported Reports", "doc.on.doc.fill", Color(red: 0.72, green: 0.62, blue: 0.90))
                            rootRow(.data, "Data", "externaldrive.fill", Color(red: 0.45, green: 0.70, blue: 0.78))
                            rootRow(.servers, "Servers", "server.rack", .mint)
                            rootRow(.beacons, "Beacons", "antenna.radiowaves.left.and.right", Color(red: 0.78, green: 0.48, blue: 0.72))
                            menuRow("settings", "Settings", "gearshape.fill", Color(red: 0.62, green: 0.64, blue: 0.78))
                        }
                        .transition(menuSlide)
                    }
                }
                .padding(.horizontal, 12)
                .frame(maxWidth: .infinity, minHeight: proxy.size.height, alignment: .center)
            }
        }
    }

    private var menuSlide: AnyTransition {
        let edge: CGFloat = menuDrill ? 1 : -1
        return .asymmetric(
            insertion: .opacity.combined(with: .offset(x: edge * 36)),
            removal: .opacity.combined(with: .offset(x: -edge * 36))
        )
    }

    private var backButton: some View {
        SidebarBackButton(action: leaveMenu)
    }

    @ViewBuilder
    private func innerRows(_ section: MenuSection) -> some View {
        switch section {
        case .mac:
            menuRow("local", "Overview", "display", Color(red: 0.62, green: 0.68, blue: 0.98))
            menuRow("local:findings", "Findings", "shield.lefthalf.filled", Color(red: 0.90, green: 0.34, blue: 0.42), count: localFindingCount)
            menuRow("local:review", "Needs review", "eye", Color(red: 0.66, green: 0.46, blue: 0.96), count: localReport?.hostReviewCount)
            menuRow("local:ports", "Port warnings", "network", Color(red: 0.96, green: 0.58, blue: 0.30), count: localReport?.portProblems.count)
            menuRow("local:coverage", "Coverage", "checklist", Color(red: 0.32, green: 0.74, blue: 0.68), count: localCoverageCount)
            menuRow("local:applications", "Applications", "macwindow", Color(red: 0.42, green: 0.58, blue: 0.98), count: applicationAttentionCount)
            menuRow("local:packages", "Packages", "shippingbox.fill", Color(red: 0.34, green: 0.72, blue: 0.88), count: localReport?.inventory.packages.count)
            menuRow("local:containers", "Containers", "cube.box.fill", Color(red: 0.50, green: 0.52, blue: 0.96), count: localReport?.inventory.containers?.count)
        case .reports:
            menuRow("imports", "Report Library", "doc.on.doc.fill", .purple, count: model.importedReports.count)
            MenuRow(title: "Import Reports…", symbol: "square.and.arrow.down", tint: .indigo,
                    count: nil, selected: false) { importing = true }
            if !model.importedReports.isEmpty {
                Text("Recently imported")
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(.secondary)
                    .padding(.leading, 10)
                    .padding(.top, 8)
            }
            ForEach(model.importedReports.prefix(5)) { report in
                menuRow(report.id, report.name, "doc.text.fill", Color(red: 0.62, green: 0.64, blue: 0.78))
                    .contextMenu {
                        Button("Rename Report…", systemImage: "pencil") { renameReport(report) }
                    }
            }
            ForEach(model.devices.filter { device in
                device.id != "local" && !device.id.hasPrefix("import:") && !device.id.hasPrefix("server-history:") &&
                    !model.servers.contains(where: { $0.id == device.id })
            }) { device in
                menuRow(device.id, device.name, "server.rack", Color(red: 0.55, green: 0.62, blue: 0.82), count: device.report.confirmed > 0 ? device.report.confirmed : nil)
            }
        case .data:
            menuRow("database", "Database", "externaldrive.fill", databaseTint)
            MenuRow(title: "Manage Beacons", symbol: "antenna.radiowaves.left.and.right", tint: .purple,
                    count: model.beacons.count, selected: false) { openPage("beacons") }
        case .servers:
            menuRow("servers", "Servers", "server.rack", .mint, count: model.servers.count)
            ForEach(model.servers) { server in
                menuRow(server.id, server.name, "server.rack", .mint,
                        count: server.latest.map { $0.findings > 0 ? $0.findings : nil } ?? nil)
            }
        case .beacons:
            menuRow("beacons", "Manage Beacons", "antenna.radiowaves.left.and.right", Color(red: 0.78, green: 0.48, blue: 0.72))
            menuRow("beacon-profiles", "Trust Profiles", "folder.badge.plus", .purple)
            ForEach(model.beacons) { beacon in
                menuRow("beacon:" + beacon.id.uuidString, beacon.name, "dot.radiowaves.left.and.right", Color(red: 0.70, green: 0.50, blue: 0.78))
            }
        }
    }

    private func rootRow(_ section: MenuSection, _ title: String, _ symbol: String, _ tint: Color) -> some View {
        MenuRow(title: title, symbol: symbol, tint: tint, count: nil, selected: self.section(for: model.selection) == section) {
            enter(section)
        }
    }

    private let contentTopInset: CGFloat = 32

    private var detail: some View {
            VStack(alignment: .leading, spacing: 12) {
                if !model.message.isEmpty {
                    HStack {
                        Label(model.message, systemImage: "info.circle").textSelection(.enabled)
                        Spacer()
                        Button("Dismiss") { model.message = "" }.buttonStyle(.plain).wardPointer()
                    }.padding(10).wardGlass(radius: 12)
                        .padding(.horizontal, showsLocalMac ? 24 : 0)
                        .padding(.top, contentTopInset)
                }
                if model.selection == "home" || model.selection == nil {
                    globalPage
                } else if showsLocalMac {
                    DeviceBrowser(device: model.devices.first { $0.id == "local" }, tracksLocalSidebar: true)
                } else if model.selection == "imports" {
                    importedReportsPage
                } else if model.selection == "servers" {
                    serversPage
                } else if model.selection == "beacons" {
                    beaconsPage
                } else if model.selection == "beacon-profiles" {
                    beaconProfilesPage
                } else if model.selection == "settings" {
                    WardSettingsPage(model: model)
                } else if model.selection == "database" {
                    databasePage
                } else if let beacon = model.beacons.first(where: { "beacon:" + $0.id.uuidString == model.selection }) {
                    beaconDetailPage(beacon)
                } else if let device = model.devices.first(where: { $0.id == model.selection }) {
                    if model.servers.contains(where: { $0.id == device.id }) || device.id.hasPrefix("server-history:") {
                        VStack(alignment: .leading, spacing: 0) {
                            Button("Servers", systemImage: "chevron.left") { openPage("servers") }
                                .wardGlassButton().padding(.horizontal, 24).padding(.top, 32)
                            DeviceBrowser(device: device).id(device.id)
                        }
                    } else {
                        DeviceBrowser(device: device, onRename: renameReport).id(device.id)
                    }
                } else {
                    ContentUnavailableView("Ready to scan", systemImage: "laptopcomputer.and.arrow.down",
                                           description: Text("Scan this Mac or import a server’s report.json."))
                }
                if model.busy {
                    ActivityStatus(activity: model.activity, visible: true)
                        .padding(.horizontal, showsLocalMac ? 24 : 0)
                }
            }
            .padding(showsLocalMac || model.selection == "home" || model.selection == nil || model.devices.contains { $0.id == model.selection } ? 0 : 24)
            .padding(.top, fillsUnderHeader ? 0 : contentTopInset)
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
            .id(model.selection ?? "")
            .transition(pageMove)
    }

    private func beaconPage<Content: View>(@ViewBuilder content: () -> Content) -> some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20, content: content)
                .frame(maxWidth: 1080)
                .padding(.bottom, 28)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    private func beaconBanner(_ title: String, subtitle: String, symbol: String,
                              actionTitle: String, disabled: Bool = false, action: @escaping () -> Void) -> some View {
        HStack(spacing: 20) {
            VStack(alignment: .leading, spacing: 8) {
                Text(title).font(.largeTitle.weight(.semibold))
                Text(subtitle).foregroundStyle(.secondary)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            BannerAction(title: actionTitle, symbol: symbol, tint: .pink, action: action)
                .disabled(disabled)
        }
        .padding(24)
        .wardBanner(tint: .pink)
    }

    private var serversPage: some View {
        ServersDashboard(model: model, connect: { connectingServer = true })
    }

    private var beaconsPage: some View {
        beaconPage {
            beaconBanner("Beacons", subtitle: "Manage signed database sources and encrypted report relays.",
                         symbol: "antenna.radiowaves.left.and.right", actionTitle: "Add Beacon…") {
                openPage("beacon-profiles")
            }
            VStack(alignment: .leading, spacing: 12) {
                Label("Connections", systemImage: "point.3.connected.trianglepath.dotted")
                    .font(.title3.weight(.semibold))
                if model.beacons.isEmpty {
                    Text("No Beacons configured. Add one from Trust Profiles or enter its details manually.")
                        .foregroundStyle(.secondary)
                }
                ForEach(model.beacons) { beacon in
                    Button { openPage("beacon:" + beacon.id.uuidString) } label: {
                        HStack {
                            VStack(alignment: .leading, spacing: 4) {
                                Text(beacon.name).font(.headline)
                                Text(beacon.relay.isEmpty ? "Database source" : "Database source and report relay")
                                    .font(.callout).foregroundStyle(.secondary)
                            }
                            Spacer()
                            if model.activeFeed == beacon.id {
                                Text("Selected for This Mac").font(.caption).foregroundStyle(.secondary)
                            }
                            Image(systemName: "chevron.right").font(.caption).foregroundStyle(.secondary)
                        }
                        .padding(12)
                        .contentShape(Rectangle())
                        .wardGlass(radius: 12)
                    }
                    .buttonStyle(.plain).wardPointer()
                }
            }
            .padding(18)
            .frame(maxWidth: .infinity, alignment: .leading)
            .wardGlass(radius: 16)

            VStack(alignment: .leading, spacing: 10) {
                Label("Encrypted reports", systemImage: "lock.shield").font(.title3.weight(.semibold))
                Text("Share this Mac’s public key with agents that upload reports. Ward decrypts received reports with this Mac’s private key.")
                    .foregroundStyle(.secondary)
                Button("Copy Report Encryption Public Key", systemImage: "key", action: copyReportKey)
                    .wardGlassButton()
            }
            .padding(18)
            .frame(maxWidth: .infinity, alignment: .leading)
            .wardGlass(radius: 16)
        }
    }

    private var beaconProfilesPage: some View {
        let available = beaconProfiles.filter { profile in
            !model.beacons.contains { $0.feed == profile.beacon.feed && $0.feedKey == profile.beacon.feedKey }
        }
        return beaconPage {
            beaconBanner("Trust Profiles", subtitle: "Add a profile from ~/.shixpeer.ward/trust/ or enter the connection details manually.",
                         symbol: "folder.badge.plus", actionTitle: "Add Manually…") {
                beaconDraft = Beacon(name: "", feed: "", feedKey: "", caFile: "", relay: "")
            }
            VStack(alignment: .leading, spacing: 12) {
                HStack {
                    Text("Available profiles").font(.title3.weight(.semibold))
                    Spacer()
                    Button("Refresh", systemImage: "arrow.clockwise", action: reloadBeaconProfiles).wardGlassButton()
                }
                if available.isEmpty {
                    Text("No new profiles found.").foregroundStyle(.secondary)
                }
                ForEach(available) { profile in
                    HStack(spacing: 12) {
                        VStack(alignment: .leading, spacing: 4) {
                            Text(profile.beacon.name).font(.headline)
                            Text(profile.beacon.feed).font(.callout).foregroundStyle(.secondary)
                        }
                        Spacer()
                        Button("Add…", systemImage: "plus") { beaconDraft = profile.beacon }
                            .wardGlassButton()
                    }
                    .padding(12)
                    .wardGlass(radius: 12)
                }
                ForEach(profileProblems, id: \.self) { problem in
                    Label(problem, systemImage: "exclamationmark.triangle").foregroundStyle(.secondary)
                }
            }
            .padding(18)
            .frame(maxWidth: .infinity, alignment: .leading)
            .wardGlass(radius: 16)
        }
        .onAppear(perform: reloadBeaconProfiles)
    }

    private func reloadBeaconProfiles() {
        (beaconProfiles, profileProblems) = BeaconProfile.discover()
    }

    private func beaconDetailPage(_ beacon: Beacon) -> some View {
        beaconPage {
            beaconBanner(beacon.name, subtitle: "Signed database and encrypted report relay settings.",
                         symbol: "antenna.radiowaves.left.and.right",
                         actionTitle: model.activeFeed == beacon.id ? "Selected for This Mac" : "Use as Local Database",
                         disabled: model.busy || beacon.feedKey.isEmpty || model.activeFeed == beacon.id) {
                model.activeFeed = beacon.id
                model.selection = "database"
            }
            VStack(alignment: .leading, spacing: 12) {
                LabeledContent("Signed database", value: beacon.feed).textSelection(.enabled)
                LabeledContent("Report relay", value: beacon.relay.isEmpty ? "Unconfigured" : beacon.relay).textSelection(.enabled)
                if beacon.relay.isEmpty {
                    Text("Configure a relay to fetch encrypted reports. The signed database can be used independently.")
                        .foregroundStyle(.secondary)
                } else {
                    Button("Fetch Encrypted Reports", systemImage: "arrow.down.circle") {
                        Task { await model.refresh(beacon) }
                    }
                    .wardGlassButton()
                    .disabled(model.busy || model.syncingServerReports)
                }
            }
            .padding(18)
            .frame(maxWidth: .infinity, alignment: .leading)
            .wardGlass(radius: 16)
            Button("Remove Beacon…", systemImage: "trash", role: .destructive) { removing = beacon }
                .wardGlassButton().disabled(model.busy)
        }
    }

    private var databaseTint: Color { Color(red: 0.35, green: 0.70, blue: 0.78) }
    private var databaseSource: Beacon? { model.beacons.first { $0.id == model.activeFeed } }

    private var databasePage: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                VStack(alignment: .leading, spacing: 14) {
                    HStack(spacing: 16) {
                        VStack(alignment: .leading, spacing: 6) {
                            Text("Scan data").font(.callout.weight(.semibold)).foregroundStyle(.secondary)
                            Text("Database").font(.largeTitle.weight(.semibold))
                            Text("Manage the signed vulnerability data used by local scans.")
                                .foregroundStyle(.secondary)
                        }
                        Spacer(minLength: 12)
                        BannerAction(title: "Update Database", symbol: "externaldrive.fill", tint: databaseTint) {
                            Task { await model.localScan(update: true, updateOnly: true) }
                        }
                        .disabled(model.busy)
                    }
                }
                .padding(24)
                .wardBanner(tint: databaseTint)

                VStack(alignment: .leading, spacing: 12) {
                    Label("Update source", systemImage: "antenna.radiowaves.left.and.right")
                        .font(.title3.weight(.semibold))
                    Picker("Source", selection: $model.activeFeed) {
                        Text("Agent settings").tag(nil as UUID?)
                        ForEach(model.beacons) { Text($0.name).tag(Optional($0.id)) }
                    }
                    .fixedSize(horizontal: true, vertical: false)
                    .disabled(model.busy)
                    if let source = databaseSource {
                        Text(source.feed)
                            .font(.callout.monospaced())
                            .textSelection(.enabled)
                            .foregroundStyle(.secondary)
                    } else {
                        Text("Ward uses the feed configured in the local agent settings.")
                            .foregroundStyle(.secondary)
                    }
                }
                .padding(18)
                .frame(maxWidth: .infinity, alignment: .leading)
                .wardGlass(radius: 16)

                VStack(alignment: .leading, spacing: 10) {
                    Label("Last local scan", systemImage: "clock")
                        .font(.title3.weight(.semibold))
                    if let revision = localReport?.database?.revision {
                        LabeledContent("Database revision") {
                            Text(String(revision)).monospacedDigit().textSelection(.enabled)
                        }
                    } else {
                        Text("No database revision was recorded in the last scan.")
                            .foregroundStyle(.secondary)
                    }
                    Text("This is the revision recorded in the report. Run a new scan to see which revision it uses.")
                        .font(.callout).foregroundStyle(.secondary)
                }
                .padding(18)
                .frame(maxWidth: .infinity, alignment: .leading)
                .wardGlass(radius: 16)
            }
            .frame(maxWidth: 1080)
            .padding(.bottom, 28)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    private var importedReportsPage: some View {
        let reports = model.importedReports
        let groups = Dictionary(grouping: reports) { $0.report.hostName?.lowercased() ?? "" }
        let hosts = groups.keys.sorted { ($0.isEmpty ? 1 : 0, $0) < ($1.isEmpty ? 1 : 0, $1) }
        return Group {
            if reports.isEmpty {
                importBanner(empty: true)
                    .frame(maxWidth: 520)
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                ScrollView {
                    VStack(alignment: .leading, spacing: 22) {
                        importBanner(empty: false)
                        Text("Saved reports").font(.title2.weight(.semibold))
                        ForEach(hosts, id: \.self) { host in
                            let group = groups[host] ?? []
                            VStack(alignment: .leading, spacing: 10) {
                                Label(group.first?.report.hostName ?? "Host not recorded", systemImage: "server.rack")
                                    .font(.headline)
                                    .foregroundStyle(.secondary)
                                ForEach(group) { device in
                                    let report = device.report
                                    let date = (try? Date.ISO8601FormatStyle(includingFractionalSeconds: true).parse(report.generated_at))
                                        ?? (try? Date.ISO8601FormatStyle().parse(report.generated_at))
                                    Button { openPage(device.id) } label: {
                                        HStack(spacing: 14) {
                                            Image(systemName: "doc.text.fill")
                                                .foregroundStyle(Color.purple)
                                                .frame(width: 38, height: 38)
                                                .background(Color.purple.opacity(0.15), in: RoundedRectangle(cornerRadius: 10))
                                                .accessibilityHidden(true)
                                            VStack(alignment: .leading, spacing: 4) {
                                                Text(device.name).font(.headline)
                                                if let system = report.systemSummary {
                                                    Text(system).font(.caption).foregroundStyle(.secondary)
                                                }
                                                Text(date?.formatted(date: .abbreviated, time: .shortened) ?? report.generated_at)
                                                    .font(.callout).foregroundStyle(.secondary)
                                            }
                                            Spacer()
                                            Text(report.confirmed == 1 ? "1 finding" : "\(report.confirmed.formatted()) findings")
                                                .font(.callout).foregroundStyle(.secondary)
                                            Image(systemName: "chevron.right").font(.caption).foregroundStyle(.secondary)
                                                .accessibilityHidden(true)
                                        }
                                        .padding(14)
                                        .contentShape(Rectangle())
                                        .wardGlass(radius: 14)
                                    }
                                    .buttonStyle(.plain).wardPointer()
                                }
                            }
                        }
                    }
                    .frame(maxWidth: 960)
                    .padding(.bottom, 24)
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
            }
        }
        .contentShape(Rectangle())
        .dropDestination(for: URL.self) { urls, _ in
            let files = urls.filter(\.isFileURL)
            guard !files.isEmpty else { return false }
            model.importReports(files)
            return true
        } isTargeted: { importDropTarget = $0 }
    }

    private func importBanner(empty: Bool) -> some View {
        HStack(spacing: 20) {
            VStack(alignment: .leading, spacing: 8) {
                Text(empty ? "Import your first report" : "Imported Reports")
                    .font(.largeTitle.weight(.semibold))
                Text(importDropTarget ? "Drop files to add them to your library." :
                     "Drag a Ward report.json here or choose files to save them on this Mac.")
                    .foregroundStyle(.secondary)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            BannerAction(title: "Import Reports…", symbol: "doc.on.doc.fill", tint: .purple) {
                importing = true
            }
        }
        .padding(24)
        .wardBanner(tint: .purple)
        .overlay {
            if importDropTarget {
                RoundedRectangle(cornerRadius: 22)
                    .strokeBorder(Color.purple, style: StrokeStyle(lineWidth: 2, dash: [6, 4]))
                    .allowsHitTesting(false)
            }
        }
    }

    private var fillsUnderHeader: Bool {
        model.selection == "home" || model.selection == nil || showsLocalMac
            || model.devices.contains { $0.id == model.selection }
    }
    private struct AlignedCanvas: NSViewRepresentable {
        func makeNSView(context: Context) -> CanvasView { CanvasView() }
        func updateNSView(_ nsView: CanvasView, context: Context) { nsView.needsDisplay = true }

        final class CanvasView: NSView {
            override var isOpaque: Bool { false }

            override func draw(_ dirtyRect: NSRect) {
                guard let content = window?.contentView else { return }
                let inWindow = convert(bounds, to: nil)
                let size = content.bounds.size
                let dark = effectiveAppearance.bestMatch(from: [.darkAqua, .aqua]) != .aqua
                let colors = dark
                    ? [NSColor(srgbRed: 0.20, green: 0.11, blue: 0.36, alpha: 1),
                       NSColor(srgbRed: 0.11, green: 0.07, blue: 0.22, alpha: 1),
                       NSColor(srgbRed: 0.07, green: 0.05, blue: 0.13, alpha: 1)]
                    : [NSColor(srgbRed: 0.86, green: 0.87, blue: 0.96, alpha: 1),
                       NSColor(srgbRed: 0.94, green: 0.94, blue: 0.98, alpha: 1),
                       NSColor(srgbRed: 0.97, green: 0.97, blue: 0.99, alpha: 1)]
                guard let gradient = NSGradient(colors: colors) else { return }
                NSGraphicsContext.current?.cgContext.saveGState()
                NSGraphicsContext.current?.cgContext.translateBy(x: -inWindow.minX, y: -inWindow.minY)
                gradient.draw(from: NSPoint(x: 0, y: size.height), to: NSPoint(x: size.width, y: 0), options: [])
                NSGraphicsContext.current?.cgContext.restoreGState()
            }
        }
    }

    private var pageWash: some View {
        RadialGradient(colors: [pageTint.opacity(0.32), .clear],
                       center: .topLeading, startRadius: 30, endRadius: 780)
            .allowsHitTesting(false)
    }

    private var pageTint: Color {
        switch model.selection {
        case "local:findings": return Color(red: 0.78, green: 0.18, blue: 0.28)
        case "local:review": return Color(red: 0.52, green: 0.30, blue: 0.86)
        case "local:ports": return Color(red: 0.86, green: 0.46, blue: 0.18)
        case "local:coverage": return Color(red: 0.16, green: 0.55, blue: 0.52)
        case "local:applications": return Color(red: 0.24, green: 0.38, blue: 0.86)
        case "local:packages": return Color(red: 0.12, green: 0.48, blue: 0.62)
        case "local:containers": return Color(red: 0.32, green: 0.32, blue: 0.78)
        case "database": return Color(red: 0.18, green: 0.46, blue: 0.52)
        case "beacons": return Color(red: 0.55, green: 0.24, blue: 0.48)
        default: return Color(red: 0.32, green: 0.20, blue: 0.62)
        }
    }

    private var pageMove: AnyTransition {
        if reduceMotion { return .opacity }
        let direction: CGFloat = model.pageTravel == 0 ? 1 : model.pageTravel
        return .asymmetric(
            insertion: .opacity.combined(with: .offset(y: -direction * 42)),
            removal: .opacity.combined(with: .offset(y: direction * 42))
        )
    }

    private func select(_ tag: String) {
        guard model.selection != tag else { return }
        let travel = LocalRoute.direction(from: model.selection, to: tag)
        withAnimation(reduceMotion ? nil : .spring(response: 0.52, dampingFraction: 0.84)) {
            model.pageTravel = travel
            if let routed = LocalRoute.path(for: tag) { model.devicePath = routed }
            model.selection = tag
        }
    }

    private func enter(_ section: MenuSection) {
        let animation = reduceMotion ? nil : Animation.spring(response: 0.42, dampingFraction: 0.86)
        withAnimation(animation) {
            menuDrill = true
            menuSection = section
            guard self.section(for: model.selection) != section else { return }
            let tag = section.home
            model.pageTravel = LocalRoute.direction(from: model.selection, to: tag)
            if let routed = LocalRoute.path(for: tag) { model.devicePath = routed }
            model.selection = tag
        }
    }

    private func leaveMenu() {
        withAnimation(reduceMotion ? nil : .spring(response: 0.42, dampingFraction: 0.86)) {
            menuDrill = false
            menuSection = nil
            model.pageTravel = -1
            model.devicePath = []
            model.selection = "home"
        }
    }

    private func openPage(_ tag: String) {
        withAnimation(reduceMotion ? nil : .spring(response: 0.42, dampingFraction: 0.86)) {
            menuDrill = true
            if let section = section(for: tag) { menuSection = section }
            model.pageTravel = LocalRoute.direction(from: model.selection, to: tag)
            if let routed = LocalRoute.path(for: tag) { model.devicePath = routed }
            else { model.devicePath = [] }
            model.selection = tag
        }
    }

    private func section(for tag: String?) -> MenuSection? {
        guard let tag else { return nil }
        if LocalRoute.isLocal(tag) { return .mac }
        if tag == "imports" || tag.hasPrefix("import:") { return .reports }
        if tag == "database" { return .data }
        if tag == "servers" || tag.hasPrefix("server-history:") || model.servers.contains(where: { $0.id == tag }) { return .servers }
        if tag == "beacons" || tag == "beacon-profiles" || tag.hasPrefix("beacon:") { return .beacons }
        if model.devices.contains(where: { $0.id == tag }) { return .reports }
        return nil
    }

    private enum MenuSection: Equatable {
        case mac, reports, data, servers, beacons

        var home: String {
            switch self {
            case .mac: return "local"
            case .reports: return "imports"
            case .data: return "database"
            case .servers: return "servers"
            case .beacons: return "beacons"
            }
        }
    }

    private func menuRow(_ tag: String, _ title: String, _ symbol: String, _ tint: Color, count: Int? = nil) -> some View {
        MenuRow(title: title, symbol: symbol, tint: tint, count: count, selected: model.selection == tag) {
            select(tag)
        }
    }

    private var localFindingCount: Int? {
        guard let report = localReport else { return nil }
        return max(0, report.confirmed - model.resolvedMatches)
    }

    private var localCoverageCount: Int? {
        guard let report = localReport else { return nil }
        return (report.components ?? []).filter { ["NOT_CHECKED", "INCOMPLETE"].contains($0.result) }.count
    }

    private var dashboardColumns: [GridItem] {
        Array(repeating: GridItem(.flexible(), spacing: 12), count: 3)
    }

    private var globalPage: some View {
        let report = localReport
        let findings = localFindingCount
        let imported = model.devices.filter { $0.id.hasPrefix("import:") }.count
        let others = model.devices.filter { $0.id != "local" && !$0.id.hasPrefix("import:") }.count
        return ScrollView {
            VStack(alignment: .leading, spacing: 26) {
                HStack(spacing: 20) {
                    VStack(alignment: .leading, spacing: 8) {
                        Label("This Mac", systemImage: "display")
                            .font(.callout.weight(.semibold))
                            .foregroundStyle(.secondary)
                        Text("Security overview")
                            .font(.largeTitle.weight(.semibold))
                        Text(report == nil ? "Run your first scan to see findings and installed software." :
                            "Review findings and inventory from your latest local scan.")
                            .foregroundStyle(.secondary)
                        if let when = report?.generated_at, !when.isEmpty {
                            let date = (try? Date.ISO8601FormatStyle(includingFractionalSeconds: true).parse(when))
                                ?? (try? Date.ISO8601FormatStyle().parse(when))
                            Label("Last scan · " + (date?.formatted(date: .abbreviated, time: .shortened) ?? when),
                                  systemImage: "clock")
                                .font(.callout)
                                .foregroundStyle(.secondary)
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    MacScanButton(title: "Scan", model: model)
                }
                .padding(24)
                .wardBanner(tint: .indigo)
                VStack(alignment: .leading, spacing: 12) {
                    Text("Scan results").font(.title2.weight(.semibold))
                    LazyVGrid(columns: dashboardColumns, spacing: 12) {
                        globalLink("Findings", "Advisories matched to installed versions.", findings.map { $0.formatted() } ?? "—",
                                   "exclamationmark.shield.fill", Color(red: 0.86, green: 0.32, blue: 0.42), "local:findings")
                        globalLink("Needs review", "Matches still waiting on a person.", report.map { $0.hostReviewCount.formatted() } ?? "—",
                                   "questionmark.circle.fill", Color(red: 0.62, green: 0.46, blue: 0.92), "local:review")
                        globalLink("Port warnings", "Listeners and firewall rules that look too open.", report.map { $0.portProblems.count.formatted() } ?? "—",
                                   "network", Color(red: 0.93, green: 0.58, blue: 0.28), "local:ports")
                    }
                }
                VStack(alignment: .leading, spacing: 12) {
                    Text("Inventory").font(.title2.weight(.semibold))
                    LazyVGrid(columns: dashboardColumns, spacing: 12) {
                        globalLink("Applications", "Apps from the last scan.", report.map { $0.userApplications.count.formatted() } ?? "—",
                                   "macwindow", Color(red: 0.38, green: 0.56, blue: 0.95), "local:applications")
                        globalLink("Packages", "Formulas, casks, and other packages.", report.map { $0.inventory.packages.count.formatted() } ?? "—",
                                   "shippingbox.fill", Color(red: 0.28, green: 0.70, blue: 0.86), "local:packages")
                        globalLink("Containers", "Images and the containers started from them.", report.map { ($0.inventory.containers?.count ?? 0).formatted() } ?? "—",
                                   "cube.box.fill", Color(red: 0.46, green: 0.50, blue: 0.95), "local:containers")
                    }
                }
                VStack(alignment: .leading, spacing: 12) {
                    Text("Reports and data").font(.title2.weight(.semibold))
                    LazyVGrid(columns: dashboardColumns, spacing: 12) {
                        globalLink("Imported Reports", others > 0 ? "\(imported.formatted()) imported, \(others.formatted()) from other computers." : "Reports opened from another computer.",
                                   imported.formatted(), "doc.on.doc.fill", Color(red: 0.72, green: 0.62, blue: 0.90), "imports")
                        globalLink("Database", report?.database.map { "Signed revision \($0.revision)" } ?? "No revision recorded in the last scan.",
                                   report?.database == nil ? "—" : "Ready", "externaldrive.fill", Color(red: 0.45, green: 0.70, blue: 0.78), "database")
                        globalLink("Beacons", model.beacons.isEmpty ? "None configured." : model.beacons.map(\.name).joined(separator: ", "),
                                   model.beacons.count.formatted(), "antenna.radiowaves.left.and.right", Color(red: 0.78, green: 0.48, blue: 0.72), "beacons")
                    }
                }
            }
            .frame(maxWidth: 1080)
            .padding(.horizontal, 22)
            .padding(.top, contentTopInset)
            .padding(.bottom, 28)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .ignoresSafeArea(edges: .top)
    }

    private func globalLink(_ title: String, _ detail: String, _ value: String, _ symbol: String, _ tint: Color, _ tag: String) -> some View {
        WardOverviewCard(title: title, detail: detail, value: value, icon: symbol, tint: tint, enabled: true) {
            openPage(tag)
        }
    }

    private func copyReportKey() {
        do {
            let key = try Vault.recipient().publicKey.rawRepresentation.base64EncodedString()
            NSPasteboard.general.clearContents()
            NSPasteboard.general.setString(key, forType: .string)
            model.showNotice("Report encryption public key copied.")
        } catch { model.message = error.localizedDescription }
    }

}

struct BeaconProfile: Identifiable {
    let folder: URL
    let beacon: Beacon
    var id: URL { folder }
    struct Settings: Decodable {
        let name: String?
        let origin: String
        let relay: String?
    }

    static func discover() -> ([BeaconProfile], [String]) {
        let root = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".shixpeer.ward/trust")
        guard let folders = try? FileManager.default.contentsOfDirectory(at: root, includingPropertiesForKeys: [.isDirectoryKey], options: [.skipsHiddenFiles]) else { return ([], []) }
        var profiles: [BeaconProfile] = []
        var problems: [String] = []
        for folder in folders.sorted(by: { $0.lastPathComponent < $1.lastPathComponent }) {
            guard (try? folder.resourceValues(forKeys: [.isDirectoryKey]).isDirectory) == true else { continue }
            do {
                let file = try FileHandle(forReadingFrom: folder.appendingPathComponent("beacon.json"))
                defer { try? file.close() }
                let data = try file.read(upToCount: 16_385) ?? Data()
                guard data.count <= 16_384 else { throw WardError("beacon.json exceeds 16 KiB") }
                let settings = try JSONDecoder().decode(Settings.self, from: data)
                _ = try Wire.origin(settings.origin)
                if let relay = settings.relay, !relay.isEmpty { _ = try Wire.origin(relay) }
                let key = folder.appendingPathComponent("feed.pub").path
                let ca = folder.appendingPathComponent("ca.crt").path
                guard FileManager.default.isReadableFile(atPath: key) else { throw WardError("feed.pub is missing") }
                profiles.append(.init(folder: folder, beacon: .init(name: settings.name ?? folder.lastPathComponent,
                    feed: settings.origin, feedKey: key, caFile: FileManager.default.fileExists(atPath: ca) ? ca : "",
                    relay: settings.relay ?? "")))
            } catch {
                problems.append(folder.lastPathComponent + ": " + error.localizedDescription)
            }
        }
        return (profiles, problems)
    }
}

private struct ServersDashboard: View {
    @ObservedObject var model: WardModel
    let connect: () -> Void
    @State private var query = ""
    @State private var onlyAttention = false
    @State private var expanded: Set<String> = []

    private var sources: [Beacon] { model.beacons.filter { !$0.relay.isEmpty } }
    private func syncError(_ server: ServerRecord) -> String? {
        let relay = model.serverCatalog.relays[server.beaconID.uuidString]
        return server.error ?? (relay?.connectionFailed == true ? relay?.error : nil)
    }
    private func status(_ server: ServerRecord, at now: Date) -> (String, Color) {
        if syncError(server) != nil { return ("Sync error", .orange) }
        if server.stale(at: now) { return ("Report overdue", .orange) }
        return ("Report current", .mint)
    }
    private func sourceName(_ server: ServerRecord) -> String {
        model.beacons.first { $0.id == server.beaconID }?.name ?? "Relay"
    }

    var body: some View {
        TimelineView(.periodic(from: .now, by: 60)) { context in
            ScrollView {
                VStack(alignment: .leading, spacing: 20) {
                    HStack(spacing: 20) {
                        VStack(alignment: .leading, spacing: 8) {
                            Text("Servers").font(.largeTitle.weight(.semibold))
                            Text("Encrypted reports, delivery status, and scan history.").foregroundStyle(.secondary)
                            Text("\(model.servers.count) servers · \(model.servers.filter { $0.stale(at: context.date) || syncError($0) != nil }.count) need attention")
                                .font(.callout).foregroundStyle(.secondary)
                        }.frame(maxWidth: .infinity, alignment: .leading)
                        BannerAction(title: model.syncingServerReports ? "Syncing…" : "Sync reports", symbol: "arrow.triangle.2.circlepath", tint: .mint) {
                            Task { await model.syncServerReports() }
                        }.disabled(model.syncingServerReports || sources.isEmpty)
                        BannerAction(title: "Connect a Server…", symbol: "server.rack", tint: .mint, action: connect)
                    }.padding(24).wardBanner(tint: .mint)

                    HStack {
                        Toggle("Automatic sync", isOn: $model.automaticServerSync).toggleStyle(.switch)
                        Spacer()
                        Text("Every 5 minutes while Ward is running").font(.caption).foregroundStyle(.secondary)
                    }.padding(14).wardGlass(radius: 14)
                    if !model.serverStorageError.isEmpty {
                        Label(model.serverStorageError, systemImage: "exclamationmark.triangle.fill")
                            .foregroundStyle(.orange).textSelection(.enabled)
                    }
                    ForEach(sources) { beacon in
                        let state = model.serverCatalog.relays[beacon.id.uuidString]
                        HStack(alignment: .top, spacing: 12) {
                            Image(systemName: state?.error == nil ? "antenna.radiowaves.left.and.right" : "exclamationmark.triangle")
                                .foregroundStyle(state?.error == nil ? Color.mint : Color.orange)
                            VStack(alignment: .leading, spacing: 4) {
                                Text(beacon.name).font(.callout.weight(.semibold))
                                if let error = state?.error {
                                    Text(error).font(.caption).foregroundStyle(.orange).textSelection(.enabled)
                                }
                                if let date = state?.lastSuccess {
                                    Text("Last successful sync · " + date.formatted(date: .abbreviated, time: .shortened))
                                        .font(.caption).foregroundStyle(.secondary)
                                } else {
                                    Text(model.syncingServerReports ? "Connecting…" : "No successful sync yet")
                                        .font(.caption).foregroundStyle(.secondary)
                                }
                                if state?.lastSuccess != nil && !model.servers.contains(where: { $0.beaconID == beacon.id }) {
                                    Text("Waiting for the first server report.").font(.caption).foregroundStyle(.secondary)
                                }
                            }
                            Spacer()
                        }.padding(14).frame(maxWidth: .infinity, alignment: .leading).wardGlass(radius: 14)
                    }
                    if model.servers.isEmpty {
                        VStack(spacing: 12) {
                            Image(systemName: "server.rack").font(.system(size: 36)).foregroundStyle(.mint)
                            Text("Your servers will appear here").font(.title3.bold())
                            Text(sources.isEmpty ? "Connect a server and configure its report relay." : "Reports appear after the first scan is delivered and synced.")
                                .foregroundStyle(.secondary).multilineTextAlignment(.center)
                            Button("Connect a Server…", action: connect).wardGlassButton(prominent: true)
                        }.frame(maxWidth: .infinity).padding(32).wardGlass(radius: 20)
                    } else {
                        HStack(spacing: 12) {
                            Image(systemName: "magnifyingglass").foregroundStyle(.secondary)
                            TextField("Search servers, systems or relays", text: $query).textFieldStyle(.plain)
                        }.padding(12).wardGlass(radius: 12)
                        HStack(spacing: 10) {
                            Button("All servers") { onlyAttention = false }.wardGlassButton(prominent: !onlyAttention)
                            Button("Needs attention") { onlyAttention = true }.wardGlassButton(prominent: onlyAttention)
                        }
                        let visible = model.servers.filter { server in
                            let matches = query.isEmpty || [server.name, server.serverID, sourceName(server), server.latest?.system ?? ""]
                                .contains { $0.localizedCaseInsensitiveContains(query) }
                            return matches && (!onlyAttention || server.stale(at: context.date) || syncError(server) != nil)
                        }
                        if visible.isEmpty { Text("No servers match this filter.").foregroundStyle(.secondary) }
                        ForEach(visible) { server in serverCard(server, now: context.date) }
                    }
                    Text("History: up to 20 received reports per server, 256 MiB total. Identical reports are saved once. Relay currently exposes the latest report; scans overwritten between syncs cannot be recovered.")
                        .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                }.frame(maxWidth: .infinity, alignment: .leading).padding(.bottom, 24)
            }
        }
    }

    private func serverCard(_ server: ServerRecord, now: Date) -> some View {
        let state = status(server, at: now)
        let open = expanded.contains(server.id)
        return VStack(alignment: .leading, spacing: 0) {
            Button {
                if open { expanded.remove(server.id) } else { expanded.insert(server.id) }
            } label: {
                HStack(alignment: .center, spacing: 14) {
                    Image(systemName: "server.rack").font(.title2).foregroundStyle(.mint)
                        .frame(width: 48, height: 48).background(Color.mint.opacity(0.12), in: RoundedRectangle(cornerRadius: 12))
                    VStack(alignment: .leading, spacing: 6) {
                        Text(server.name).font(.title3.bold())
                        Text(server.serverID + " · " + sourceName(server)).font(.caption).foregroundStyle(.secondary)
                        if let latest = server.latest {
                            Text(latest.system ?? "System information unavailable").font(.callout).foregroundStyle(.secondary)
                            Text("Last report · " + latest.generatedAt.formatted(date: .abbreviated, time: .shortened))
                                .font(.caption).foregroundStyle(.secondary)
                        }
                    }.frame(maxWidth: .infinity, alignment: .leading)
                    VStack(alignment: .trailing, spacing: 8) {
                        Text(state.0).font(.caption.weight(.semibold)).foregroundStyle(state.1)
                        Text("\(server.latest?.findings ?? 0) findings · \(server.latest?.review ?? 0) to review")
                            .font(.caption).foregroundStyle(.secondary)
                        Image(systemName: open ? "chevron.up" : "chevron.down").foregroundStyle(.secondary)
                    }
                }.padding(18).frame(maxWidth: .infinity, alignment: .leading).contentShape(Rectangle())
            }.buttonStyle(.plain).wardPointer()
            if let error = syncError(server) {
                Text(error).font(.caption).foregroundStyle(.orange).textSelection(.enabled)
                    .padding(.horizontal, 18).padding(.bottom, 12)
            }
            if ["partial", "incomplete"].contains(server.latest?.status ?? "") {
                Label("Scan coverage is incomplete. Review Coverage in the report.", systemImage: "exclamationmark.circle")
                    .font(.caption).foregroundStyle(.orange).padding(.horizontal, 18).padding(.bottom, 12)
            }
            HStack {
                Text("\(server.snapshots.count) saved reports").font(.caption).foregroundStyle(.secondary)
                Spacer()
                if let latest = server.latest {
                    Button("Open latest", systemImage: "doc.text") { Task { await model.openServerReport(server, snapshot: latest) } }
                        .wardGlassButton(prominent: true)
                }
            }.padding(.horizontal, 18).padding(.bottom, 14)
            if open {
                Divider().padding(.horizontal, 18)
                VStack(alignment: .leading, spacing: 12) {
                    Picker("Expected scan interval", selection: Binding(get: { server.expectedInterval }, set: { model.setServerInterval(server, seconds: $0) })) {
                        Text("15 minutes").tag(TimeInterval(900))
                        Text("1 hour").tag(TimeInterval(3600))
                        Text("6 hours").tag(TimeInterval(21600))
                        Text("24 hours").tag(TimeInterval(86400))
                    }.fixedSize(horizontal: true, vertical: false)
                    Text("Marked overdue after two missed intervals. This does not change the agent schedule.")
                        .font(.caption).foregroundStyle(.secondary)
                    Text("Report history").font(.headline)
                    ForEach(server.snapshots) { snapshot in
                        HStack(spacing: 12) {
                            VStack(alignment: .leading, spacing: 4) {
                                Text(snapshot.generatedAt.formatted(date: .abbreviated, time: .standard)).font(.callout.weight(.medium))
                                Text("\(snapshot.findings) findings · \(snapshot.review) to review").font(.caption).foregroundStyle(.secondary)
                            }
                            Spacer()
                            Button("Open") { Task { await model.openServerReport(server, snapshot: snapshot) } }.wardGlassButton()
                            Button("Save JSON…", systemImage: "square.and.arrow.down") { export(server, snapshot: snapshot) }.wardGlassButton()
                        }.padding(12).wardGlass(radius: 12)
                    }
                }.padding(18)
            }
        }.wardGlass(radius: 18)
    }

    private func export(_ server: ServerRecord, snapshot: ServerSnapshot) {
        Task {
            do {
                let (data, _) = try await model.serverArchive.read(server, snapshot: snapshot.id)
                let panel = NSSavePanel()
                panel.allowedContentTypes = [.json]
                panel.nameFieldStringValue = server.serverID + "-" + String(snapshot.id.prefix(8)) + ".json"
                guard await panel.begin() == .OK, let url = panel.url else { return }
                try data.write(to: url, options: .atomic)
            } catch { model.message = error.localizedDescription }
        }
    }
}

private struct ServerSetupWizard: View {
    @Environment(\.dismiss) private var dismiss
    @ObservedObject var model: WardModel
    let openReport: (String) -> Void
    @State private var beaconID: UUID?
    @State private var showingRelayGuide = false
    @State private var relayGuideHostname = ""
    @State private var relayGuidePort = "8444"
    @State private var relayGuideExistingCheckout = false
    @State private var relayGuideCertificate = ""
    @State private var relayGuidePrivateKey = ""
    @State private var setupContentHeight: CGFloat = 360
    @State private var relayAddress = ""
    @State private var relayReadToken = ""
    @State private var relayConnected = false
    @State private var serverID = ""
    @State private var step = 0
    @State private var started = Date()
    @State private var checking = false
    @State private var error = ""
    @State private var verified: (Device, Data)?
    @State private var interval = "1h"
    @State private var enrollmentToken = ""
    @State private var relayConnectionCode = ""
    @State private var relayCAPath = ""
    @State private var installationCommand: String?
    @State private var commandExpiry: Date?

    private let titles = ["Choose a connection", "Install and connect", "Verify delivery"]
    private var source: Beacon? { model.beacons.first { $0.id == beaconID } }
    private var sourceReady: Bool {
        guard let source else { return false }
        return !source.relay.isEmpty && !source.feedKey.isEmpty
    }
    private var validID: Bool { serverID.range(of: "^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$", options: .regularExpression) != nil }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            VStack(alignment: .leading, spacing: 6) {
                Text("Connect a Server · Step \(step + 1) of \(titles.count)").foregroundStyle(.secondary)
                Text(titles[step]).font(.title2.weight(.semibold))
            }
            .padding(18)
            .frame(maxWidth: .infinity, alignment: .leading)
            .frame(height: 88)
            .wardBanner(tint: .pink)

            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    switch step {
                    case 0: connection
                    case 1: preparation
                    default: verification
                    }
                    if !error.isEmpty {
                        Label(error, systemImage: "exclamationmark.triangle")
                            .foregroundStyle(.red).textSelection(.enabled)
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.bottom, 8)
                .background(GeometryReader { proxy in
                    Color.clear.onAppear { if proxy.size.height > 10 { setupContentHeight = proxy.size.height } }
                        .onChange(of: proxy.size.height) { _, height in
                            if height > 10 && abs(setupContentHeight - height) > 1 { setupContentHeight = height }
                        }
                })
            }
            HStack {
                Button("Close") { dismiss() }.wardGlassButton().keyboardShortcut(.cancelAction)
                Spacer()
                if step > 0 {
                    Button("Back") { step -= 1; error = "" }.wardGlassButton().disabled(checking)
                }
                if step < 2 {
                    Button("Next") {
                        error = ""
                        step += 1
                    }
                    .wardGlassButton(prominent: true)
                    .disabled(!sourceReady || !validID || (step == 1 && installationCommand == nil) || checking)
                } else if let verified {
                    Button("Open Report") { openReport(verified.0.id) }.wardGlassButton(prominent: true)
                }
            }.frame(height: 32)
        }
        .font(.system(size: 14))
        .padding(24)
        .frame(width: 700, height: min(max(480, setupContentHeight + 208), max(480, (NSScreen.main?.visibleFrame.height ?? 900) - 100)))
        .sheet(isPresented: $showingRelayGuide) { relayGuide }
        .interactiveDismissDisabled(checking)
        .onAppear {
            if beaconID == nil {
                beaconID = model.beacons.first { !$0.relay.isEmpty && !$0.feedKey.isEmpty }?.id
                    ?? model.beacons.first?.id
            }
        }
    }

    private var connection: some View {
        VStack(alignment: .leading, spacing: 12) {
            if model.beacons.isEmpty {
                Text("Add a Beacon with a signed database and a report relay, then reopen this wizard.")
            }
            Picker("Beacon and relay", selection: $beaconID) {
                Text("Select a Beacon").tag(nil as UUID?)
                ForEach(model.beacons) { beacon in
                    Text(beacon.relay.isEmpty ? beacon.name + " (no relay)" : beacon.name)
                        .tag(Optional(beacon.id))
                }
            }
            .disabled(checking)
            .onChange(of: beaconID) { _, _ in
                relayAddress = ""
                relayReadToken = ""
                relayConnected = false
                installationCommand = nil
                commandExpiry = nil
                enrollmentToken = beaconID.flatMap { try? Vault.read($0.uuidString + ".enrollment") }
                    .map { String(decoding: $0, as: UTF8.self) } ?? ""
                error = ""
            }
            if let source, !sourceReady {
                VStack(alignment: .leading, spacing: 10) {
                    Label("Connect a relay to continue", systemImage: "exclamationmark.triangle.fill")
                        .font(.headline)
                        .foregroundStyle(.orange)
                    if source.relay.isEmpty {
                        Button("Setup instructions & command", systemImage: "terminal") {
                            showingRelayGuide = true
                        }
                        .wardGlassButton()
                        SecureField("Paste relay connection code", text: $relayConnectionCode)
                            .textFieldStyle(.roundedBorder)
                        Text("Copy the WARD-RELAY-1 code from the server terminal. No Keychain certificate import needed.")
                            .foregroundStyle(.secondary)
                        if let code = try? RelayConnectionCode.parse(relayConnectionCode) {
                            Text("Connect to " + code.origin).font(.headline)
                        }
                        Button(checking ? "Connecting…" : "Connect Relay", systemImage: "checkmark.shield") {
                            checking = true
                            error = ""
                            Task {
                                defer { checking = false }
                                do {
                                    let code = try RelayConnectionCode.parse(relayConnectionCode)
                                    guard SecCertificateCreateWithData(nil, code.certificate as CFData) != nil else {
                                        throw WardError("Invalid relay certificate.")
                                    }
                                    try await model.connectRelay(to: source.id, address: code.origin,
                                        readToken: code.reader, certificate: code.certificate)
                                    try Vault.store(Data(code.enrollment.utf8), source.id.uuidString + ".enrollment")
                                    enrollmentToken = code.enrollment
                                    relayConnectionCode = ""
                                    relayConnected = true
                                } catch { self.error = error.localizedDescription }
                            }
                        }.wardGlassButton(prominent: true)
                            .disabled(checking || (try? RelayConnectionCode.parse(relayConnectionCode)) == nil)
                        DisclosureGroup("Manual connection") {
                            TextField("Relay URL", text: $relayAddress).textFieldStyle(.roundedBorder)
                            SecureField("Reader token", text: $relayReadToken).textFieldStyle(.roundedBorder)
                            Button("Verify and Save Relay") { saveRelay(for: source) }
                                .disabled(checking || relayReadToken.utf8.count < 32)
                        }
                    }
                    if source.feedKey.isEmpty {
                        Text("Add this Beacon’s trusted feed.pub in Beacons.")
                            .foregroundStyle(.secondary)
                    }
                }
                .padding(14)
                .frame(maxWidth: .infinity, alignment: .leading)
                .wardBanner(tint: .orange)
                .disabled(checking)
            } else if relayConnected {
                Label("Relay verified and saved to this Beacon.", systemImage: "checkmark.circle.fill")
                    .foregroundStyle(.mint)
            }
            TextField("Server ID, e.g. prod-web-01", text: $serverID).textFieldStyle(.roundedBorder)
                .onChange(of: serverID) { _, _ in installationCommand = nil; commandExpiry = nil; verified = nil }
            Picker("Scan interval", selection: $interval) {
                ForEach(["15m", "1h", "6h", "24h"], id: \.self) { Text($0).tag($0) }
            }.onChange(of: interval) { _, _ in installationCommand = nil; commandExpiry = nil; verified = nil }
        }
    }

    private var relayGuide: some View {
        RelaySetupGuide(relayGuideHostname: $relayGuideHostname, relayGuidePort: $relayGuidePort,
            relayGuideExistingCheckout: $relayGuideExistingCheckout, relayGuideCertificate: $relayGuideCertificate,
            relayGuidePrivateKey: $relayGuidePrivateKey, initialAddress: source?.relay.isEmpty == false ? source!.relay : relayAddress) { origin in
                if let origin, source?.relay.isEmpty == true { relayAddress = origin }
                showingRelayGuide = false
            }
    }

    private func saveRelay(for beacon: Beacon) {
        checking = true
        error = ""
        Task {
            defer { checking = false }
            do {
                try await model.connectRelay(to: beacon.id, address: relayAddress, readToken: relayReadToken)
                relayReadToken = ""
                relayConnected = true
            } catch {
                self.error = error.localizedDescription
            }
        }
    }

    @ViewBuilder private var preparation: some View {
        if let source {
            Text("Run one command on a Linux server with systemd. It installs the signed agent, connects the relay and enables scans every " + interval + ".")
                .foregroundStyle(.secondary)
            Text("Requires Linux amd64/arm64, systemd, curl and OpenSSL. Other installed software is not updated.")
                .font(.caption).foregroundStyle(.secondary)
            let savedToken = (try? Vault.read(source.id.uuidString + ".enrollment")).map { String(decoding: $0, as: UTF8.self) } ?? ""
            if savedToken.isEmpty {
            SecureField("Relay enrollment token", text: $enrollmentToken).textFieldStyle(.roundedBorder)
                .disabled(installationCommand != nil)
            Text("Use the separate management token once; Ward keeps it in Keychain. It is never sent to the server.")
                .font(.caption).foregroundStyle(.secondary)
            }
            Button("Relay setup", systemImage: "questionmark.circle") { showingRelayGuide = true }.wardGlassButton()
            if source.relayCertificate == nil { HStack {
                TextField("Relay CA certificate (optional for private TLS)", text: $relayCAPath).textFieldStyle(.roundedBorder)
                Button("Choose…") {
                    let panel = NSOpenPanel()
                    panel.canChooseDirectories = false
                    panel.begin { result in if result == .OK { relayCAPath = panel.url?.path ?? "" } }
                }.wardGlassButton()
            }.disabled(installationCommand != nil) }
            Button(checking ? "Creating…" : (installationCommand == nil ? "Create installation command" : "Generate new command"), systemImage: "terminal") {
                checking = true
                error = ""
                let requestedAt = Date()
                Task {
                    defer { checking = false }
                    do {
                        let result = try await model.createServerEnrollment(source, serverID: serverID, interval: interval,
                            managementToken: savedToken.isEmpty ? enrollmentToken : savedToken, relayCAPath: relayCAPath)
                        installationCommand = result.0
                        commandExpiry = result.1
                        started = requestedAt
                        verified = nil
                    } catch { self.error = error.localizedDescription }
                }
            }.wardGlassButton(prominent: true).disabled(checking || (savedToken.isEmpty ? enrollmentToken : savedToken).utf8.count < 32)
            if let command = installationCommand, let expiry = commandExpiry {
                VStack(alignment: .leading, spacing: 12) {
                    Button("Change settings") { installationCommand = nil; commandExpiry = nil; verified = nil }.wardGlassButton()
                    Label("Installation command ready", systemImage: "checkmark.shield.fill").foregroundStyle(.mint)
                    Text("Paste it into the server terminal. sudo will ask for permission. No configuration editing is needed.")
                        .font(.callout)
                    TimelineView(.periodic(from: .now, by: 1)) { context in
                        VStack(alignment: .leading, spacing: 8) {
                            Text(context.date < expiry ? "Valid until " + expiry.formatted(date: .omitted, time: .standard) : "Expired — regenerate if not installed")
                                .font(.caption).foregroundStyle(context.date < expiry ? Color.secondary : Color.orange)
                            Button("Copy installation command", systemImage: "doc.on.doc") {
                                NSPasteboard.general.clearContents()
                                NSPasteboard.general.setString(command, forType: .string)
                            }.wardGlassButton(prominent: true).disabled(context.date >= expiry)
                        }
                    }
                    Text("Includes a short-lived registration token. Do not share it. The first scan follows the initial database download.")
                        .font(.caption).foregroundStyle(.secondary)
                    DisclosureGroup("View command") {
                        ScrollView([.horizontal, .vertical]) {
                            Text(command).font(.caption.monospaced()).textSelection(.enabled)
                        }.frame(height: 120)
                    }
                }.padding(16).wardGlass(radius: 16)
            }
        }
    }

    private var verification: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("After the installation command finishes, verify the first report. The initial database download may take a few minutes.")
                .foregroundStyle(.secondary)
            Button(checking ? "Checking…" : "Verify Report", systemImage: "checkmark.shield") {
                guard let source else { return }
                checking = true
                verified = nil
                error = ""
                Task {
                    defer { checking = false }
                    do {
                        verified = try await model.verifyServerReport(source, id: serverID, since: started)
                        if let server = model.servers.first(where: { $0.id == verified?.0.id }) {
                            let seconds: TimeInterval = ["15m": 900, "1h": 3600, "6h": 21600, "24h": 86400][interval] ?? 3600
                            model.setServerInterval(server, seconds: seconds)
                        }
                    }
                    catch { self.error = error.localizedDescription }
                }
            }
            .wardGlassButton(prominent: true)
            .disabled(checking)
            if let verified {
                Label("Fresh report received and decrypted.", systemImage: "checkmark.circle.fill")
                    .foregroundStyle(.mint)
                LabeledContent("Generated at", value: verified.0.report.generated_at)
                    .textSelection(.enabled)
                Button("Save JSON…") { saveReport(verified.1) }.wardGlassButton()
            }
        }
    }

    private func snippet(_ text: String, copyEnabled: Bool = true) -> some View {
        VStack(alignment: .trailing, spacing: 6) {
            Button("Copy", systemImage: "doc.on.doc") {
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString(text, forType: .string)
            }
            .wardGlassButton().disabled(!copyEnabled)
            Text(text).font(.system(size: 14, design: .monospaced)).textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
        .padding(12).wardGlass(radius: 12)
    }

    private func saveReport(_ data: Data) {
        let panel = NSSavePanel()
        panel.allowedContentTypes = [.json]
        panel.nameFieldStringValue = serverID + "-report.json"
        panel.begin { response in
            guard response == .OK, let url = panel.url else { return }
            do { try data.write(to: url, options: .atomic) }
            catch { self.error = error.localizedDescription }
        }
    }
}

private struct RelaySetupGuide: View {
    @Binding var relayGuideHostname: String
    @Binding var relayGuidePort: String
    @Binding var relayGuideExistingCheckout: Bool
    @Binding var relayGuideCertificate: String
    @Binding var relayGuidePrivateKey: String
    let initialAddress: String
    let done: (String?) -> Void
    @State private var relayContentHeight: CGFloat = 380
    @State private var relayOptionsOpen = false
    @State private var copied = false
    @State private var copyFailed = false

    var body: some View {
        let command = ServerEnrollmentCommand.relaySetupCommand(hostname: relayGuideHostname,
            port: relayGuidePort, existingCheckout: relayGuideExistingCheckout,
            certificate: relayGuideCertificate, privateKey: relayGuidePrivateKey)
        let preview = command ?? ServerEnrollmentCommand.relaySetupPreview(hostname: relayGuideHostname,
            port: relayGuidePort, existingCheckout: relayGuideExistingCheckout,
            certificate: relayGuideCertificate, privateKey: relayGuidePrivateKey)
        return VStack(alignment: .leading, spacing: 16) {
            VStack(alignment: .leading, spacing: 6) {
                Text("Set Up a Report Relay").font(.title2.bold())
                Text("Receives encrypted reports from your servers.").foregroundStyle(.secondary)
            }.padding(18).frame(maxWidth: .infinity, alignment: .leading).frame(height: 88).wardBanner(tint: .pink)
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    Text("1. Open SSH on the relay server. Enter its IP or hostname and run the command below.")
                        .fixedSize(horizontal: false, vertical: true)
                    HStack {
                        TextField("IP or hostname · relay.example.com", text: $relayGuideHostname).textFieldStyle(.roundedBorder)
                        TextField("Port", text: $relayGuidePort).textFieldStyle(.roundedBorder).frame(width: 90)
                    }
                    VStack(alignment: .trailing, spacing: 8) {
                        Button(copied ? "Copied" : "Copy command", systemImage: copied ? "checkmark" : "doc.on.doc") {
                            guard let command else { return }
                            NSPasteboard.general.clearContents()
                            copied = NSPasteboard.general.setString(command, forType: .string)
                            copyFailed = !copied
                        }.wardGlassButton(prominent: true).disabled(command == nil)
                        Text(preview).font(.system(size: 14, design: .monospaced)).textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }.padding(12).wardGlass(radius: 12)
                    if copyFailed { Text("Could not copy. Try again.").foregroundStyle(.orange) }
                    if command == nil, !relayGuideHostname.isEmpty {
                        Text("Enter a valid IP or hostname, port 1024–65535, and both TLS paths if using your own certificate.")
                            .foregroundStyle(.orange).fixedSize(horizontal: false, vertical: true)
                    }
                    Text("The script builds the relay, creates TLS and tokens, enables startup and checks the connection.")
                        .foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                    DisclosureGroup("Options", isExpanded: $relayOptionsOpen) {
                        VStack(alignment: .leading, spacing: 10) {
                            Toggle("Repository already cloned — run from its folder", isOn: $relayGuideExistingCheckout)
                            Text("Own TLS certificate (leave empty to generate one)")
                            TextField("Certificate path on server", text: $relayGuideCertificate).textFieldStyle(.roundedBorder)
                            TextField("Private key path on server", text: $relayGuidePrivateKey).textFieldStyle(.roundedBorder)
                            Text("Requires Linux, systemd, OpenSSL and curl or wget. Go is prepared automatically.").foregroundStyle(.secondary)
                        }.padding(.top, 10)
                    }
                    Text("2. Copy the WARD-RELAY-1 code into Connect a Server → Connect Relay.")
                        .fixedSize(horizontal: false, vertical: true)
                    Text("The code includes the public certificate and access settings. Keep it private; no files or separate tokens to transfer.")
                        .foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                }.frame(maxWidth: .infinity, alignment: .leading).padding(.bottom, 8)
                    .background(GeometryReader { proxy in
                        Color.clear.onAppear { if proxy.size.height > 10 { relayContentHeight = proxy.size.height } }
                            .onChange(of: proxy.size.height) { _, height in
                                if height > 10 && abs(relayContentHeight - height) > 1 { relayContentHeight = height }
                            }
                    })
            }
            HStack {
                Spacer()
                Button("Done") {
                    done(command == nil ? nil : ServerEnrollmentCommand.relayOrigin(hostname: relayGuideHostname, port: relayGuidePort))
                }.wardGlassButton(prominent: true).keyboardShortcut(.cancelAction)
            }.frame(height: 32)
        }.font(.system(size: 14)).padding(24)
            .frame(width: 700, height: min(max(420, relayContentHeight + 208), max(420, (NSScreen.main?.visibleFrame.height ?? 900) - 100)))
            .onChange(of: command) { _, _ in copied = false; copyFailed = false }
            .onAppear {
                if relayGuideHostname.isEmpty,
                   let address = URLComponents(string: initialAddress), let host = address.host {
                    relayGuideHostname = host
                    relayGuidePort = String(address.port ?? 8444)
                }
            }
    }
}

struct BeaconForm: View {
    @Environment(\.dismiss) private var dismiss
    @ObservedObject var model: WardModel
    @State var draft: Beacon
    @State private var token = ""
    @State private var error = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            VStack(alignment: .leading, spacing: 6) {
                Label("Add Beacon", systemImage: "antenna.radiowaves.left.and.right")
                    .font(.title.weight(.semibold))
                Text("Connect a signed database source and, optionally, an encrypted report relay.")
                    .foregroundStyle(.secondary)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(18)
            .wardBanner(tint: .pink)

            VStack(alignment: .leading, spacing: 10) {
                Text("Signed database").font(.headline)
                field("Name", text: $draft.name)
                field("HTTPS origin", text: $draft.feed)
                field("Trusted feed.pub path", text: $draft.feedKey)
                field("Custom CA path (optional)", text: $draft.caFile)
            }
            .padding(14)
            .wardGlass(radius: 14)

            VStack(alignment: .leading, spacing: 10) {
                Text("Report relay (optional)").font(.headline)
                field("Relay HTTPS origin", text: $draft.relay)
                if !draft.relay.isEmpty {
                    SecureField("Relay read token", text: $token)
                        .textFieldStyle(.roundedBorder)
                        .accessibilityLabel("Relay read token")
                }
            }
            .padding(14)
            .wardGlass(radius: 14)

            if !error.isEmpty { Label(error, systemImage: "exclamationmark.triangle").foregroundStyle(.red) }
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }.wardGlassButton().keyboardShortcut(.cancelAction)
                Button("Add Beacon") {
                    do {
                        try model.add(draft, token: token)
                        model.showNotice("Beacon added.")
                        dismiss()
                    } catch { self.error = error.localizedDescription }
                }
                .wardGlassButton(prominent: true)
                .keyboardShortcut(.defaultAction)
                .disabled(draft.name.isEmpty || draft.feed.isEmpty)
            }
        }
        .padding(24)
        .frame(width: 560)
    }

    private func field(_ title: String, text: Binding<String>) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(title).font(.caption.weight(.medium)).foregroundStyle(.secondary)
            TextField(title, text: text)
                .textFieldStyle(.roundedBorder)
                .accessibilityLabel(title)
        }
    }
}

struct ActivityStatus: View {
    let activity: String
    let visible: Bool
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    var body: some View {
        HStack(spacing: 10) {
            if visible && !reduceMotion {
                ProgressView().controlSize(.small).accessibilityHidden(true)
            }
            Text(activity).font(.callout.weight(.medium)).lineLimit(1)
            Spacer(minLength: 0)
        }
        .padding(.horizontal, 12)
        .frame(height: 36)
        .wardGlass(radius: 12)
        .opacity(visible ? 1 : 0)
        .accessibilityHidden(!visible)
    }
}

enum DevicePage: Hashable {
    case findings, review, ports, applications, packages, containers, coverage

    var title: String {
        switch self {
        case .findings: return "Findings"
        case .review: return "Needs review"
        case .ports: return "Port warnings"
        case .applications: return "Applications"
        case .packages: return "Packages"
        case .containers: return "Containers"
        case .coverage: return "Coverage"
        }
    }

    var symbol: String {
        switch self {
        case .findings: return "exclamationmark.shield.fill"
        case .review: return "questionmark.circle.fill"
        case .ports: return "network"
        case .applications: return "macwindow"
        case .packages: return "shippingbox.fill"
        case .containers: return "cube.box.fill"
        case .coverage: return "checklist"
        }
    }

    var tint: Color {
        switch self {
        case .findings: return Color(red: 0.78, green: 0.16, blue: 0.24)
        case .review: return .purple
        case .ports: return .orange
        case .applications: return .blue
        case .packages: return .cyan
        case .containers: return Color(red: 0.36, green: 0.48, blue: 0.95)
        case .coverage: return .teal
        }
    }
}

enum LocalRoute {
    static func tag(for path: [DevicePage]) -> String {
        switch path.first {
        case .findings: return "local:findings"
        case .review: return "local:review"
        case .ports: return "local:ports"
        case .applications: return "local:applications"
        case .packages: return "local:packages"
        case .containers: return "local:containers"
        case .coverage: return "local:coverage"
        case nil: return "local"
        }
    }

    static func path(for selection: String?) -> [DevicePage]? {
        switch selection {
        case "local": return []
        case "local:findings": return [.findings]
        case "local:review": return [.review]
        case "local:ports": return [.ports]
        case "local:applications": return [.applications]
        case "local:packages": return [.packages]
        case "local:containers": return [.containers]
        case "local:coverage": return [.coverage]
        default: return nil
        }
    }

    static func isLocal(_ selection: String?) -> Bool {
        selection == "local" || selection?.hasPrefix("local:") == true
    }

    static func direction(from old: String?, to new: String?) -> CGFloat {
        let order = ["local", "local:findings", "local:review", "local:ports", "local:coverage",
                     "local:applications", "local:packages", "local:containers", "imports", "database", "beacons"]
        guard let old, let new, let start = order.firstIndex(of: old), let end = order.firstIndex(of: new), start != end else { return 0 }
        return end > start ? 1 : -1
    }
}

private struct MacScanButton: View {
    let title: String
    @ObservedObject var model: WardModel
    @State private var scanHovered = false

    var body: some View {
        Button {
            Task { await model.localScan(update: false) }
        } label: {
            VStack(spacing: 2) {
                Image(systemName: "shield.lefthalf.filled")
                    .font(.system(size: 50, weight: .light))
                    .foregroundStyle(Color.indigo.gradient)
                    .frame(width: 108, height: 108)
                    .background {
                        Circle().fill(RadialGradient(colors: [.indigo.opacity(0.28), .clear],
                                                     center: .center, startRadius: 4, endRadius: 54))
                        .opacity(scanHovered ? 1 : 0.65)
                        Circle().inset(by: 8).strokeBorder(Color.indigo.opacity(0.25))
                    }
                    .accessibilityHidden(true)
                Text(title).font(.callout.weight(.semibold))
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(ScanButtonStyle(hovering: scanHovered && !model.busy)).wardPointer()
        .onHover { scanHovered = $0 }
        .onDisappear { scanHovered = false }
        .disabled(model.busy)
        .help("Scan this Mac")
    }
}

private struct BannerAction: View {
    let title: String
    let symbol: String
    let tint: Color
    let action: () -> Void
    @Environment(\.isEnabled) private var isEnabled
    @State private var hovering = false

    var body: some View {
        Button(action: action) {
            VStack(spacing: 6) {
                Image(systemName: symbol)
                    .font(.system(size: 32, weight: .medium))
                    .foregroundStyle(tint.gradient)
                    .frame(width: 68, height: 68)
                    .background(tint.opacity(0.16), in: RoundedRectangle(cornerRadius: 18))
                    .accessibilityHidden(true)
                Text(title)
                    .font(.callout.weight(.semibold))
                    .multilineTextAlignment(.center)
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(ScanButtonStyle(hovering: hovering && isEnabled))
        .wardPointer()
        .onHover { hovering = $0 }
    }
}

private struct ScanButtonStyle: ButtonStyle {
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    let hovering: Bool

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .brightness(configuration.isPressed ? -0.10 : hovering ? 0.10 : 0)
            .scaleEffect(reduceMotion ? 1 : configuration.isPressed ? 0.95 : hovering ? 1.05 : 1)
            .animation(reduceMotion ? nil : .easeOut(duration: 0.16), value: hovering)
            .animation(reduceMotion ? nil : .easeOut(duration: 0.12), value: configuration.isPressed)
    }
}

private struct ApplicationCheckScreen: View {
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    let completed: Int
    let total: Int

    var body: some View {
        VStack(spacing: 24) {
            ZStack {
                Circle().fill(Color.blue.opacity(0.12))
                TimelineView(.animation(paused: reduceMotion)) { timeline in
                    let turn = timeline.date.timeIntervalSinceReferenceDate.truncatingRemainder(dividingBy: 2)
                    Circle()
                        .trim(from: 0, to: 0.26)
                        .stroke(Color.cyan.gradient, style: StrokeStyle(lineWidth: 3, lineCap: .round))
                        .rotationEffect(.degrees(reduceMotion ? 0 : turn * 180))
                }
                Image(systemName: "macwindow")
                    .font(.system(size: 54, weight: .light))
                    .foregroundStyle(Color.blue.gradient)
            }
            .frame(width: 172, height: 172)
            .accessibilityHidden(true)

            VStack(alignment: .leading, spacing: 12) {
                Text("Checking for app updates").font(.title2.weight(.semibold))
                ProgressView(value: Double(completed), total: Double(total))
                    .tint(.cyan)
                    .accessibilityLabel("Applications checked")
                Text("\(completed.formatted()) of \(total.formatted()) applications checked")
                    .font(.callout.monospacedDigit())
                    .foregroundStyle(.secondary)
            }
            .padding(20)
            .frame(maxWidth: 520)
            .wardBanner(tint: .blue)
        }
        .padding(24)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

private struct MacScanView: View {
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    let progress: ScanProgress?
    let updating: Bool
    let startsScan: Bool
    let issue: WardModel.ScanIssue?
    let cancelling: Bool
    let cancel: () -> Void
    let close: () -> Void
    let update: () -> Void
    let showCoverage: () -> Void

    var body: some View {
        VStack(spacing: 18) {
            Group {
                if updating {
                    databaseAnimation
                } else {
                    WardShield(scanning: issue == nil)
                }
            }
            .frame(width: 240, height: 240)

            if let issue {
                VStack(alignment: .leading, spacing: 12) {
                    Label(issue.title, systemImage: "exclamationmark.triangle.fill")
                        .font(.title2.weight(.semibold))
                    Text(issue.detail)
                        .font(.body)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                    HStack(spacing: 10) {
                        Button("Update Database", systemImage: "arrow.clockwise", action: update)
                            .wardGlassButton(prominent: true)
                        if issue.showsCoverage {
                            Button("View Coverage", action: showCoverage).wardGlassButton()
                        }
                        Spacer()
                        Button("Close", action: close)
                            .wardGlassButton()
                            .keyboardShortcut(.cancelAction)
                    }
                    .controlSize(.large)
                }
                .padding(22)
                .frame(maxWidth: 560)
                .wardGlass(radius: 18)
            } else {
                VStack(alignment: .leading, spacing: 12) {
                    Label(updating ? "Database update" : "Security scan",
                          systemImage: updating ? "externaldrive" : "shield.lefthalf.filled")
                        .font(.caption.weight(.semibold))
                        .foregroundStyle(.secondary)
                    if updating {
                        DatabaseUpdateProgress(progress: progress, startsScan: startsScan)
                    } else {
                        scanProgressPanel
                    }
                }
                .font(.callout)
                .padding(20)
                .frame(maxWidth: 520, minHeight: 164, alignment: .topLeading)
                .wardBanner(tint: updating ? .cyan : .indigo)
                Button(cancelling ? "Cancelling…" : updating ? "Cancel Update" : "Cancel Scan",
                       systemImage: "xmark", role: .destructive, action: cancel)
                    .wardGlassButton(prominent: true)
                    .tint(.red)
                    .controlSize(.large)
                    .keyboardShortcut(.cancelAction)
                    .disabled(cancelling || (updating && progress?.stage == "updated"))
            }
        }
        .padding(.horizontal, 20)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private var databaseAnimation: some View {
        ZStack {
            Circle().fill(Color.cyan.opacity(0.10))
            Circle().strokeBorder(Color.cyan.opacity(0.22))
            TimelineView(.animation(paused: reduceMotion)) { timeline in
                let turn = timeline.date.timeIntervalSinceReferenceDate.truncatingRemainder(dividingBy: 2)
                Circle()
                    .trim(from: 0, to: 0.23)
                    .stroke(Color.cyan.gradient, style: StrokeStyle(lineWidth: 3, lineCap: .round))
                    .rotationEffect(.degrees(reduceMotion ? 0 : turn * 180))
            }
            Image(systemName: "externaldrive.fill")
                .font(.system(size: 56, weight: .light))
                .foregroundStyle(Color.cyan.gradient)
        }
        .frame(width: 172, height: 172)
        .accessibilityHidden(true)
    }

    private var scanProgressPanel: some View {
        let matching = progress?.stage == "matching"
        let total = matching ? (progress?.total ?? 0) : 0
        let done = min(max(0, progress?.done ?? 0), total)
        let fraction = total > 0 ? Double(done) / Double(total) : 0

        return VStack(alignment: .leading, spacing: 9) {
            HStack(spacing: 12) {
                Text(progress?.title ?? "Preparing local scan")
                    .font(.headline)
                    .lineLimit(1)
                    .truncationMode(.middle)
                Spacer(minLength: 0)
                if total > 0 {
                    Text(fraction.formatted(.percent.precision(.fractionLength(0))))
                        .font(.headline.monospacedDigit())
                }
            }
            if total > 0 {
                ProgressView(value: fraction)
                    .tint(.cyan)
                    .accessibilityLabel("Components checked")
                HStack {
                    Text("\(done.formatted()) / \(total.formatted()) components checked")
                    Spacer()
                    if let seconds = progress?.seconds {
                        Text("~\(seconds.formatted()) s left")
                    }
                }
                .foregroundStyle(.secondary)
                .monospacedDigit()
            } else {
                ProgressView()
                    .progressViewStyle(.linear)
                    .tint(.cyan)
                    .accessibilityLabel("Scan in progress")
            }
            if let progress, (matching || progress.stage == "report"),
               let matches = progress.matches, let review = progress.review {
                Divider()
                HStack(spacing: 16) {
                    Label("\(matches.formatted()) matches", systemImage: "exclamationmark.shield")
                    Label("\(review.formatted()) to review", systemImage: "questionmark.circle")
                }
                .font(.caption.weight(.medium))
                .foregroundStyle(.secondary)
                .monospacedDigit()
            }
        }
    }
}

private struct DatabaseUpdateProgress: View {
    let progress: ScanProgress?
    let startsScan: Bool

    var body: some View {
        let title: String = switch progress?.stage {
        case "planning": "Checking which database files need updating"
        case "download": "Downloading " + (progress?.component ?? "database files")
        case "install": "Verifying and applying the database"
        case "updated": "Database is up to date"
        default: "Checking the signed manifest"
        }
        return VStack(alignment: .leading, spacing: 9) {
            Text(title).font(.headline).lineLimit(1).truncationMode(.middle)
            if let progress, progress.total > 0 {
                ProgressView(value: Double(progress.done), total: Double(progress.total))
                    .tint(.cyan)
                    .accessibilityLabel("Database download")
                HStack {
                    Text("\(byteCount(progress.done)) / \(byteCount(progress.total))")
                    Spacer()
                    Text("\(byteCount(progress.total - progress.done)) left")
                }
                .monospacedDigit()
                .foregroundStyle(.secondary)
            } else if startsScan {
                Text("A new scan will start after the update.")
                    .foregroundStyle(.secondary)
            }
        }
    }

    private func byteCount(_ bytes: Int) -> String {
        ByteCountFormatter.string(fromByteCount: Int64(bytes), countStyle: .file)
    }
}

struct WardShield: View {
    let scanning: Bool
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    var body: some View {
        VStack(spacing: 22) {
            if let url = Bundle.main.url(forResource: "WardMatte", withExtension: "icns"),
               let icon = NSImage(contentsOf: url) {
                let shield = Image(nsImage: icon).resizable().scaledToFit()
                shield.overlay {
                    if scanning {
                    TimelineView(.animation(paused: reduceMotion)) { timeline in
                        GeometryReader { geometry in
                            let time = timeline.date.timeIntervalSinceReferenceDate
                            let position = reduceMotion ? 0.5 : (1 + sin(time * 2.4)) / 2
                            LinearGradient(colors: [.clear, .cyan.opacity(0.55), .white, .cyan.opacity(0.55), .clear],
                                           startPoint: .top, endPoint: .bottom)
                                .frame(height: 24)
                                .position(x: geometry.size.width / 2, y: geometry.size.height * position)
                        }
                    }.mask { shield }
                    }
                }
                .frame(maxWidth: 260, maxHeight: 260)
                .accessibilityHidden(true)
            }
        }.frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

private struct SidebarBackButton: View {
    let action: () -> Void
    @State private var hovering = false
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    var body: some View {
        Button(action: action) {
            HStack(spacing: 8) {
                Image(systemName: "chevron.left")
                    .font(.system(size: 12, weight: .semibold))
                    .offset(x: hovering ? -4 : 0)
                Text("Back")
                    .font(.system(size: 13.5, weight: .semibold))
                Spacer(minLength: 0)
            }
            .foregroundStyle(.primary)
            .padding(.horizontal, 10)
            .padding(.vertical, 8)
            .background(Color.white.opacity(hovering ? 0.08 : 0), in: RoundedRectangle(cornerRadius: 10, style: .continuous))
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain).wardPointer()
        .onHover { hovering = $0 }
        .animation(reduceMotion ? nil : .spring(response: 0.32, dampingFraction: 0.72), value: hovering)
        .padding(.bottom, 6)
    }
}

private struct SoftBannerButtonStyle: ButtonStyle {
    var hovering: Bool
    var tint: Color

    func makeBody(configuration: Configuration) -> some View {
        SoftBannerBody(hovering: hovering, pressed: configuration.isPressed, tint: tint, label: configuration.label)
    }

    private struct SoftBannerBody<Label: View>: View {
        let hovering: Bool
        let pressed: Bool
        let tint: Color
        let label: Label
        @Environment(\.accessibilityReduceMotion) private var reduceMotion

        private var lifted: Bool { hovering && !pressed }
        private var phase: Int { pressed ? 2 : (hovering ? 1 : 0) }
        private var glow: Double { pressed ? 0.55 : (lifted ? 1 : 0) }

        var body: some View {
            label
                .overlay {
                    RoundedRectangle(cornerRadius: 18, style: .continuous)
                        .stroke(tint.opacity(0.9 * glow), lineWidth: 1.6)
                        .blur(radius: 7)
                        .allowsHitTesting(false)
                }
                .overlay {
                    RoundedRectangle(cornerRadius: 18, style: .continuous)
                        .strokeBorder(Color.white.opacity(0.55 * glow))
                        .allowsHitTesting(false)
                }
                .brightness(pressed ? -0.03 : (lifted ? 0.06 : 0))
                .shadow(color: tint.opacity(0.85 * glow), radius: lifted ? 26 : (pressed ? 12 : 0))
                .shadow(color: Color.white.opacity(0.55 * glow), radius: lifted ? 8 : 0)
                .shadow(color: .black.opacity(lifted ? 0.22 : 0), radius: lifted ? 14 : 0, y: lifted ? 8 : 0)
                .scaleEffect(pressed ? 0.975 : (lifted ? 1.02 : 1))
                .offset(y: pressed ? 1 : (lifted ? -3 : 0))
                .animation(reduceMotion ? nil : .spring(response: 0.38, dampingFraction: 0.74), value: phase)
        }
    }
}

private struct WardOverviewCard: View {
    let title: String
    let detail: String
    let value: String
    let icon: String
    let tint: Color
    let enabled: Bool
    let action: () -> Void
    @State private var hovering = false

    var body: some View {
        Button(action: action) {
            VStack(alignment: .leading, spacing: 10) {
                HStack(alignment: .center) {
                    Image(systemName: icon)
                        .font(.system(size: 18, weight: .semibold))
                        .foregroundStyle(tint)
                        .frame(width: 40, height: 40)
                        .background(tint.opacity(0.16), in: RoundedRectangle(cornerRadius: 12, style: .continuous))
                        .accessibilityHidden(true)
                    Spacer(minLength: 8)
                    Text(value)
                        .font(.system(size: 22, weight: .semibold, design: .rounded))
                        .monospacedDigit()
                }
                Text(title).font(.headline)
                Text(detail)
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .padding(.trailing, 14)
                    .lineLimit(3)
                    .fixedSize(horizontal: false, vertical: true)
            }
            .padding(16)
            .frame(maxWidth: .infinity, minHeight: 136, alignment: .center)
            .overlay(alignment: .bottomTrailing) {
                Image(systemName: "chevron.right")
                    .font(.system(size: 12, weight: .semibold))
                    .foregroundStyle(Color.primary.opacity(hovering ? 0.72 : 0.32))
                    .padding(16)
                    .accessibilityHidden(true)
                    .allowsHitTesting(false)
            }
            .background(Color.primary.opacity(0.05), in: RoundedRectangle(cornerRadius: 18, style: .continuous))
            .overlay {
                RoundedRectangle(cornerRadius: 18, style: .continuous)
                    .strokeBorder(Color.primary.opacity(0.08))
            }
            .contentShape(RoundedRectangle(cornerRadius: 18, style: .continuous))
        }
        .buttonStyle(SoftBannerButtonStyle(hovering: hovering, tint: tint)).wardPointer()
        .disabled(!enabled)
        .focusEffectDisabled()
        .onHover { hovering = $0 }
        .zIndex(hovering ? 1 : 0)
    }
}

struct DeviceBrowser: View {
    @EnvironmentObject private var model: WardModel
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    let device: Device?
    var tracksLocalSidebar = false
    var onRename: ((Device) -> Void)? = nil
    @State private var showingReportActions = false
    @State private var ownPath: [DevicePage] = []
    @State private var findingFocus: String?

    private var report: Report? { device?.report }
    private var path: [DevicePage] { tracksLocalSidebar ? model.devicePath : ownPath }

    var body: some View {
        Group {
            if let page = path.last {
                pageChrome(page)
            } else {
                home
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
    }

    private var openFindings: [Report.Finding] {
        report?.findings.filter { $0.status == "affected" && !model.isVerified($0) } ?? []
    }

    private var home: some View {
        let affected = openFindings
        let advisories = report.map { max(0, $0.confirmed - model.resolvedMatches) }
        let items = Set(affected.map { "\($0.component)\t\($0.installed_version)\t\($0.origin ?? "")" }).count
        let dockerReview = report?.containerReviewCount ?? 0
        let unchecked = report.map { ($0.components ?? []).filter { ["NOT_CHECKED", "INCOMPLETE"].contains($0.result) }.count }
        let spotlight = Dictionary(grouping: affected) { "\($0.component)\t\($0.installed_version)" }
            .map { $0.value }
            .sorted {
                let a = $0[0], b = $1[0]
                let ar = ["CRITICAL", "HIGH", "MEDIUM", "LOW"].firstIndex(of: a.severity.uppercased()) ?? 9
                let br = ["CRITICAL", "HIGH", "MEDIUM", "LOW"].firstIndex(of: b.severity.uppercased()) ?? 9
                return (ar, a.component) < (br, b.component)
            }
            .prefix(6)
        let findingsDetail = report == nil
            ? "Scan this Mac to see which installed versions fall in an affected range."
            : "\((advisories ?? 0).formatted()) advisories across \(items.formatted()) installed items."
        let reviewDetail = dockerReview > 0
            ? "Host matches shown · \(dockerReview.formatted()) in Docker."
            : "Matches that need manual review."
        let isLocal = tracksLocalSidebar || device?.id == "local"
        return ScrollView {
            VStack(alignment: .leading, spacing: 26) {
                HStack(spacing: 20) {
                    VStack(alignment: .leading, spacing: 7) {
                        Text(isLocal ? "This Mac" : "Scan report")
                            .font(.callout.weight(.semibold))
                            .foregroundStyle(.secondary)
                        Text(isLocal ? "Scan overview" : (device?.name ?? "Scan overview"))
                            .font(.largeTitle.weight(.semibold))
                        Text(report == nil ? "Scan this Mac to see results here." :
                            "Review security findings, scan coverage, and software inventory.")
                            .foregroundStyle(.secondary)
                        if !isLocal, let report {
                            let details = [report.hostName, report.systemSummary].compactMap { $0 }
                            if !details.isEmpty {
                                Text(details.joined(separator: " · "))
                                    .font(.callout.weight(.medium))
                                    .foregroundStyle(.secondary)
                                    .textSelection(.enabled)
                            }
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    if isLocal {
                        MacScanButton(title: "Rescan", model: model)
                    } else if let device, device.id.hasPrefix("import:") {
                        Button {
                            showingReportActions.toggle()
                        } label: {
                            Image(systemName: "ellipsis.circle")
                                .resizable()
                                .scaledToFit()
                                .frame(width: 38, height: 38)
                                .foregroundStyle(Color.indigo.gradient)
                                .frame(width: 60, height: 60)
                                .background(Color.indigo.opacity(0.18), in: RoundedRectangle(cornerRadius: 16))
                                .contentShape(Rectangle())
                        }
                        .buttonStyle(.plain).wardPointer()
                        .accessibilityLabel("Report actions")
                        .disabled(model.busy)
                        .help("Report actions")
                        .popover(isPresented: $showingReportActions, arrowEdge: .trailing) {
                            VStack(alignment: .leading, spacing: 10) {
                                if device.id.hasPrefix("import:"), let onRename {
                                    Button("Rename Report…", systemImage: "pencil") {
                                        showingReportActions = false
                                        onRename(device)
                                    }
                                    .wardGlassButton()
                                }
                                Button("Remove Report from List", systemImage: "trash", role: .destructive) {
                                    showingReportActions = false
                                    model.removeReport(device)
                                }
                                .wardGlassButton()
                            }
                            .padding(14)
                        }
                    }
                }
                .padding(24)
                .wardBanner(tint: .indigo)

                VStack(alignment: .leading, spacing: 12) {
                    Text("Security checks").font(.title2.weight(.semibold))
                    LazyVGrid(columns: [GridItem(.adaptive(minimum: 210), spacing: 14)], spacing: 14) {
                        overviewCard("Findings", findingsDetail, advisories, "exclamationmark.shield.fill",
                                     Color(red: 0.86, green: 0.32, blue: 0.42), .findings)
                        overviewCard("Needs review", reviewDetail, report?.hostReviewCount, "questionmark.circle.fill",
                                     Color(red: 0.62, green: 0.46, blue: 0.92), .review)
                        overviewCard("Port warnings", "Network listeners and firewall warnings.",
                                     report?.portProblems.count, "network", Color(red: 0.93, green: 0.58, blue: 0.28), .ports)
                        overviewCard("Coverage", "Components with incomplete or skipped checks.",
                                     unchecked, "checklist", Color(red: 0.28, green: 0.72, blue: 0.66), .coverage)
                    }
                }

                if !spotlight.isEmpty {
                    VStack(alignment: .leading, spacing: 8) {
                        HStack {
                            Label("Highest severity", systemImage: "exclamationmark.shield")
                                .font(.title3.weight(.semibold))
                            Spacer()
                            Button("All findings") { navigate(.findings, replace: true, focus: nil) }
                                .wardGlassButton()
                        }
                        ForEach(Array(spotlight.enumerated()), id: \.offset) { _, group in
                            let first = group[0]
                            Button { navigate(.findings, replace: true, focus: first.component) } label: {
                                HStack(spacing: 10) {
                                    Text(first.severity.uppercased()).font(.caption2.bold())
                                        .foregroundStyle(severityColor(first.severity))
                                        .padding(.horizontal, 6).padding(.vertical, 3)
                                        .wardGlassCapsule(tint: severityColor(first.severity), opacity: 0.18)
                                    Text(first.component).font(.callout.weight(.semibold)).lineLimit(1)
                                    Text(first.installed_version).font(.caption.monospaced()).foregroundStyle(.secondary)
                                    Spacer()
                                    Text(group.count == 1 ? "1 advisory" : "\(group.count.formatted()) advisories")
                                        .font(.caption).foregroundStyle(.secondary)
                                    Image(systemName: "chevron.right").font(.caption2).foregroundStyle(.tertiary)
                                }
                                .padding(.horizontal, 10).padding(.vertical, 8)
                                .background(.quaternary.opacity(0.65), in: RoundedRectangle(cornerRadius: 10))
                            }.buttonStyle(.plain).wardPointer().focusEffectDisabled()
                        }
                    }
                    .padding(16)
                    .wardGlass(radius: 18)
                }

                VStack(alignment: .leading, spacing: 12) {
                    Text("Software inventory").font(.title2.weight(.semibold))
                    VStack(spacing: 0) {
                        inventoryLink(.applications, count: report?.userApplications.count)
                        Divider()
                        inventoryLink(.packages, count: report?.inventory.packages.count)
                        Divider()
                        inventoryLink(.containers, count: report.map { $0.inventory.containers?.count ?? 0 })
                    }
                    .wardGlass(radius: 18)
                }


            }
            .frame(maxWidth: 1080)
            .padding(.horizontal, 28)
            .padding(.top, 46)
            .padding(.bottom, 32)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .ignoresSafeArea(edges: .top)
    }

    private func inventoryLink(_ page: DevicePage, count: Int?) -> some View {
        Button {
            navigate(page, replace: true, focus: nil)
        } label: {
            HStack(spacing: 12) {
                Image(systemName: page.symbol)
                    .foregroundStyle(page.tint)
                    .frame(width: 32, height: 32)
                    .background(page.tint.opacity(0.14), in: RoundedRectangle(cornerRadius: 9))
                    .accessibilityHidden(true)
                Text(page.title).font(.callout.weight(.semibold))
                Spacer()
                Text(count?.formatted() ?? "—").monospacedDigit()
                Image(systemName: "chevron.right").font(.caption).foregroundStyle(.secondary)
                    .accessibilityHidden(true)
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 8)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain).wardPointer()
        .disabled(report == nil)
    }

    private func overviewCard(_ title: String, _ detail: String, _ count: Int?, _ icon: String, _ tint: Color, _ page: DevicePage) -> some View {
        WardOverviewCard(title: title, detail: detail, value: count?.formatted() ?? "—",
                         icon: icon, tint: tint, enabled: report != nil) {
            navigate(page, replace: true, focus: nil)
        }
    }

    private func pageChrome(_ page: DevicePage) -> some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 28) {
                Button {
                    findingFocus = nil
                    setPath(Array(path.dropLast()))
                } label: {
                    Label(path.dropLast().last?.title ?? "Overview", systemImage: "chevron.left")
                }
                .wardGlassButton()
                .help("Back one level")
                if let device {
                    ReportView(device: device, page: page, subtitle: subtitle(page), focus: findingFocus, onOpen: { next, name in
                        navigate(next, replace: false, focus: name)
                    }, onClearFocus: { findingFocus = nil })
                    .id(page)
                } else {
                    DeviceSectionBanner(page: page, subtitle: subtitle(page))
                }
            }
            .padding(.horizontal, 28)
            .padding(.top, 46)
            .padding(.bottom, 32)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .ignoresSafeArea(edges: .top)
    }

    private func subtitle(_ page: DevicePage) -> String {
        guard let report else { return "Scan this Mac to fill this page." }
        switch page {
        case .findings:
            let shown = max(0, report.confirmed - model.resolvedMatches)
            let affected = report.findings.filter { $0.status == "affected" && !model.isVerified($0) }
            let items = Set(affected.map { "\($0.component)\t\($0.installed_version)" }).count
            return "\(shown.formatted()) advisories across \(items.formatted()) items. A match means the installed version falls in an affected range."
        case .review:
            let listed = report.findings.filter { $0.status == "review" }.count
            return "\(report.hostReviewCount.formatted()) on this Mac · \(report.containerReviewCount.formatted()) in Docker. The full total is \(report.requires_review.formatted()). \(listed.formatted()) records are saved in this report."
        case .ports:
            let count = report.portProblems.count
            return count == 0 ? "No local exposure warnings in the checks that ran." : "\(count.formatted()) listeners or firewall rules worth a closer look."
        case .applications:
            return "Ordinary Mac apps from the last scan, plus apps this account has opened outside the usual folders. Versions come from the App Store or the update feed written in the app, and a check is kept for an hour."
        case .packages:
            return "Browse installed versions by source and filter them by scan result."
        case .containers:
            return "Images in use and the containers started from them. The Docker review total stays on Needs review."
        case .coverage:
            let unchecked = (report.components ?? []).filter { ["NOT_CHECKED", "INCOMPLETE"].contains($0.result) }.count
            return "\(unchecked.formatted()) components were collected and then not compared to the database. A gap here is not a clean result."
        }
    }

    private func severityColor(_ severity: String) -> Color {
        switch severity.uppercased() {
        case "CRITICAL": return .pink
        case "HIGH": return .red
        case "MEDIUM": return .orange
        case "LOW": return .blue
        default: return .secondary
        }
    }

    private func navigate(_ page: DevicePage, replace: Bool, focus: String?) {
        findingFocus = focus
        var next = path
        if replace || next.isEmpty { next = [page] } else { next.append(page) }
        setPath(next)
    }

    private func setPath(_ next: [DevicePage]) {
        if tracksLocalSidebar {
            let tag = LocalRoute.tag(for: next)
            if model.selection != tag {
                withAnimation(reduceMotion ? nil : .spring(response: 0.52, dampingFraction: 0.84)) {
                    model.pageTravel = LocalRoute.direction(from: model.selection, to: tag)
                    model.devicePath = next
                    model.selection = tag
                }
            } else if model.devicePath != next {
                model.devicePath = next
            }
        } else {
            ownPath = next
        }
    }
}

private enum AppFilter: String, CaseIterable, Identifiable {
    case updates = "Available updates"
    case flagged = "Needs review"
    case user = "Your apps"
    case apple = "Apple"
    var id: String { rawValue }
}

private enum AppUpdateChannel {
    case installerMetadata([URL])
    case productXML(URL)
    case jetBrains(String, String)
    case appStore(String)
    case sparkle(URL)
    case electron(URL)
    case vscode(URL, String, String, String)
    case plain(URL)
    case dockerDesktop(URL)
    case sparkleUnlisted
    case system
    case none
    case missing

    var label: String {
        switch self {
        case .jetBrains: return "JetBrains stable releases"
        case .appStore: return "Mac App Store"
        case .sparkle: return "Sparkle"
        case .electron, .vscode, .plain, .productXML, .installerMetadata: return "App updater"
        case .dockerDesktop: return "Docker Desktop updater"
        case .sparkleUnlisted: return "Sparkle feed is not in the app"
        case .system: return "Updates with macOS"
        case .missing: return "Application is not on this Mac"
        case .none: return "No update channel in this app"
        }
    }
}

private struct AppUpdateRecord: Codable, Equatable, Sendable {
    var text: String
    var newer: Bool
    var canInstall: Bool
    var reported: String
    var installed: String
}

private enum AppUpdateReconciliation {
    static func installedVersion(at bundle: URL) -> String? {
        guard let data = try? Data(contentsOf: bundle.appendingPathComponent("Contents/Info.plist")),
              let info = (try? PropertyListSerialization.propertyList(from: data, format: nil)) as? [String: Any],
              let version = (info["CFBundleShortVersionString"] as? String) ?? (info["CFBundleVersion"] as? String) else { return nil }
        let value = version.trimmingCharacters(in: .whitespacesAndNewlines)
        return value.isEmpty ? nil : value
    }
    static func reconcile(_ record: AppUpdateRecord, installed: String?) -> AppUpdateRecord {
        guard let installed, !installed.isEmpty else { return record }
        var updated = record
        updated.installed = installed
        guard !record.reported.isEmpty, let order = versionOrder(installed, record.reported) else {
            if installed != record.installed {
                updated.canInstall = false
                updated.text = "Installed version changed. Check updates."
            }
            return updated
        }
        updated.newer = order == .orderedAscending
        updated.canInstall = record.canInstall && updated.newer
        if !updated.newer {
            updated.reported = installed
            updated.text = ""
        }
        return updated
    }
}

private func currentlyNeedsAppUpdate(_ id: String, record: AppUpdateRecord) -> Bool {
    guard record.newer, let url = NSWorkspace.shared.urlForApplication(withBundleIdentifier: id),
          let version = AppUpdateReconciliation.installedVersion(at: url) else { return false }
    if let order = versionOrder(version, record.reported) { return order == .orderedAscending }
    return version == record.installed
}

private struct SystemSoftwareUpdate: Codable, Identifiable, Equatable {
    let label: String
    let title: String
    let version: String
    var action: String? = nil
    var pendingRestart: Bool? = nil
    var requiresRestart: Bool { action == "restart" || action == "shutdown" }
    var id: String { "system-software:" + label }
    static func parse(_ output: String) throws -> [Self] {
        var label: String?
        var updates: [Self] = []
        for raw in output.split(separator: "\n") {
            let line = raw.trimmingCharacters(in: .whitespaces)
            if line.hasPrefix("* Label:") { label = String(line.dropFirst(8)).trimmingCharacters(in: .whitespaces) }
            else if let current = label, line.hasPrefix("Title: "),
                    let split = line.range(of: ", Version: ") {
                let title = String(line[line.index(line.startIndex, offsetBy: 7)..<split.lowerBound])
                let version = String(line[split.upperBound...].prefix { $0 != "," }).trimmingCharacters(in: .whitespaces)
                guard !title.isEmpty, !version.isEmpty else { throw WardError("Incomplete system update response.") }
                let action = line.range(of: ", Action: ").map { String(line[$0.upperBound...].prefix { $0 != "," }).trimmingCharacters(in: .whitespaces).lowercased() }
                updates.append(Self(label: current, title: title, version: version, action: action))
                label = nil
            }
        }
        guard label == nil, !updates.isEmpty || output.contains("No new software available") else {
            throw WardError("System update availability could not be determined.")
        }
        return updates
    }
    static func check(cachedOnly: Bool = false) throws -> [Self] {
        let file = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        FileManager.default.createFile(atPath: file.path, contents: nil, attributes: [.posixPermissions: 0o600])
        defer { try? FileManager.default.removeItem(at: file) }
        let handle = try FileHandle(forWritingTo: file)
        defer { try? handle.close() }
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/sbin/softwareupdate")
        process.arguments = cachedOnly ? ["--list", "--no-scan"] : ["--list"]
        process.environment = ProcessInfo.processInfo.environment.merging(["LC_ALL": "C", "LANG": "en_US.UTF-8"]) { _, new in new }
        process.standardOutput = handle; process.standardError = handle
        process.standardInput = FileHandle.nullDevice
        try process.run()
        let deadline = Date().addingTimeInterval(120)
        while process.isRunning {
            if Date() >= deadline { process.terminate(); throw WardError("System update check timed out. Try again.") }
            Thread.sleep(forTimeInterval: 0.1)
        }
        guard process.terminationStatus == 0 else { throw WardError("System update check failed. Try again.") }
        guard (try file.resourceValues(forKeys: [.fileSizeKey]).fileSize ?? 0) <= 1 << 20 else { throw WardError("System update response is too large.") }
        return try parse(String(decoding: Data(contentsOf: file), as: UTF8.self))
    }
    static func mergingRestartPending(_ updates: [Self]) -> [Self] {
        let defaults = UserDefaults.standard
        let boot = Date().timeIntervalSince1970 - ProcessInfo.processInfo.systemUptime
        guard abs(defaults.double(forKey: "ward.system-update-restart-boot") - boot) < 5,
              let data = defaults.data(forKey: "ward.system-update-restart-items"),
              let pending = try? JSONDecoder().decode([Self].self, from: data) else { return updates.filter { $0.pendingRestart != true } }
        let ids = Set(pending.map(\.id))
        return updates.filter { $0.pendingRestart != true && !ids.contains($0.id) } + pending
    }
    static func rememberRestart(_ update: Self) {
        var pending = mergingRestartPending([])
        pending.removeAll { $0.id == update.id }
        var item = update; item.pendingRestart = true; pending.append(item)
        let defaults = UserDefaults.standard
        defaults.set(Date().timeIntervalSince1970 - ProcessInfo.processInfo.systemUptime, forKey: "ward.system-update-restart-boot")
        if let data = try? JSONEncoder().encode(pending) { defaults.set(data, forKey: "ward.system-update-restart-items") }
    }
    static func load() -> [Self] {
        let data = UserDefaults.standard.data(forKey: "ward.system-software-updates.v1") ?? Data()
        return mergingRestartPending((try? JSONDecoder().decode([Self].self, from: data)) ?? [])
    }
}

private struct SystemInstallProgress: Equatable {
    let stage: String
    let percent: Double?
    var fraction: Double {
        let value = max(0, min(100, percent ?? 0)) / 100
        switch stage {
        case "Downloading update…": return 0.05 + 0.60 * value
        case "Installing update…": return 0.70 + 0.28 * value
        case "Verifying update…": return 0.68
        default: return 0.02
        }
    }
    static func latest(_ output: String) -> Self? {
        var result: Self?
        for line in output.components(separatedBy: .newlines).flatMap({ $0.components(separatedBy: "\r") }) {
            let text = line.trimmingCharacters(in: .whitespaces)
            let stage: String
            if text.hasPrefix("Downloading") || text.hasPrefix("Downloaded") { stage = "Downloading update…" }
            else if text.hasPrefix("Installing") || text.hasPrefix("Preparing") { stage = "Installing update…" }
            else if text.hasPrefix("Verifying") { stage = "Verifying update…" }
            else { continue }
            let percent: Double?
            if let range = text.range(of: #"[0-9]+(?:\.[0-9]+)?\s*%"#, options: .regularExpression) {
                let value = Double(text[range].replacingOccurrences(of: "%", with: "").trimmingCharacters(in: .whitespaces))
                percent = value.flatMap { $0.isFinite ? min(100, max(0, $0)) : nil }
            } else { percent = text.hasPrefix("Downloaded") ? 100 : nil }
            result = Self(stage: stage, percent: percent)
        }
        return result
    }
}

private enum SystemUpdateInstaller {
    enum Outcome: Equatable { case installed, restartRequired }
    // Only Apple's fixed updater is privileged; no user-provided executable,
    // script, download URL or writable log path is executed as administrator.
    static let launchScript = #"""
        set -eu
        label=$1
        export LC_ALL=C LANG=en_US.UTF-8
        work=$(/usr/bin/mktemp -d '/Library/Application Support/.ward-system-update.XXXXXXXX')
        /bin/chmod 755 "$work"
        : > "$work/output"
        /bin/chmod 644 "$work/output"
        (
            set +e
            /usr/sbin/softwareupdate --install "$label" --verbose </dev/null > "$work/output" 2>&1
            result=$?
            /usr/bin/printf '%s\n' "$result" > "$work/status.pending"
            /bin/chmod 644 "$work/status.pending"
            /bin/mv "$work/status.pending" "$work/status"
            (/bin/sleep 600; /bin/rm -rf -- "$work") </dev/null >/dev/null 2>&1 &
        ) </dev/null >/dev/null 2>&1 &
        /usr/bin/printf '%s' "$work"
        """#
    static let authorizationScript = """
        on run argv
            set cmd to "/bin/sh -c " & quoted form of (item 1 of argv) & " ward-system-update " & quoted form of (item 2 of argv)
            do shell script cmd with administrator privileges
        end run
        """
    static func validate(_ label: String) throws {
        guard !label.isEmpty, label.utf8.count <= 512, !label.hasPrefix("-"),
              !label.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }) else {
            throw WardError("Invalid system update label. Check updates again.")
        }
    }
    static func failure(_ output: String) -> WardError {
        let lower = output.lowercased()
        if lower.contains("authenticate") || lower.contains("volume owner") || lower.contains("--stdinpass") {
            return WardError("macOS requires owner authorization for this update. Complete it in Software Update.")
        }
        let detail = output.components(separatedBy: .newlines).map { $0.trimmingCharacters(in: .whitespaces) }.last { !$0.isEmpty } ?? "Try again."
        return WardError("System update failed. " + String(detail.prefix(200)))
    }
    static func verify(_ update: SystemSoftwareUpdate, exitCode: Int, output: String,
                       remaining: [SystemSoftwareUpdate]) throws -> Outcome {
        guard exitCode == 0 else { throw failure(output) }
        let lower = output.lowercased()
        guard lower.contains("done with ") || lower.contains("successfully installed") || lower.components(separatedBy: .newlines).contains(where: { $0.hasPrefix("installed ") }) else {
            throw WardError("macOS did not confirm installation. Check updates again.")
        }
        let restart = update.requiresRestart || lower.contains("restart is required") || lower.contains("requires that you restart") || lower.contains("must restart") || lower.contains("restart your computer") || lower.contains("restart your mac")
        if remaining.contains(where: { $0.label == update.label }) {
            guard restart && (lower.contains("done with") || lower.contains("successfully installed")) else {
                throw WardError("macOS still offers this update. Installation was not confirmed.")
            }
        }
        return restart ? .restartRequired : .installed
    }
    static func install(_ update: SystemSoftwareUpdate,
                        progress: @escaping @MainActor @Sendable (SystemInstallProgress) -> Void) async throws -> (Outcome, [SystemSoftwareUpdate]) {
        try validate(update.label)
        await progress(SystemInstallProgress(stage: "Checking update availability…", percent: nil))
        let offered = try await Task.detached { try SystemSoftwareUpdate.check() }.value
        guard offered.contains(where: { $0.label == update.label && $0.version == update.version }) else {
            throw WardError("This update is no longer offered. Check updates again.")
        }
        await progress(SystemInstallProgress(stage: "Waiting for macOS approval…", percent: nil))
        let work = try await Task.detached {
            try toolResult("/usr/bin/osascript", ["-e", authorizationScript, launchScript, update.label]).stdout.trimmingCharacters(in: .whitespacesAndNewlines)
        }.value
        guard work.range(of: #"^/Library/Application Support/\.ward-system-update\.[A-Za-z0-9]+$"#, options: .regularExpression) != nil else {
            throw WardError("System update could not start.")
        }
        let root = URL(fileURLWithPath: work)
        let deadline = ContinuousClock.now + .seconds(7200)
        var previous: SystemInstallProgress?
        var output = ""
        while true {
            let snapshot = try await Task.detached { () -> (String, Int?) in
                let file = root.appendingPathComponent("output")
                let handle = try FileHandle(forReadingFrom: file)
                defer { try? handle.close() }
                // Read a bounded tail, even if the system updater is verbose.
                let length = try handle.seekToEnd()
                try handle.seek(toOffset: length > 262144 ? length - 262144 : 0)
                let data = try handle.read(upToCount: 262144) ?? Data()
                let status = try? String(contentsOf: root.appendingPathComponent("status"), encoding: .utf8)
                return (String(decoding: data, as: UTF8.self), status.flatMap { Int($0.trimmingCharacters(in: .whitespacesAndNewlines)) })
            }.value
            output = snapshot.0
            if let value = SystemInstallProgress.latest(output), value != previous {
                await progress(value); previous = value
            }
            if let status = snapshot.1 {
                guard status == 0 else { throw failure(output) }
                await progress(SystemInstallProgress(stage: "Verifying update…", percent: nil))
                let remaining = try await Task.detached { try SystemSoftwareUpdate.check() }.value
                return (try verify(update, exitCode: status, output: output, remaining: remaining), remaining)
            }
            guard ContinuousClock.now < deadline else { throw WardError("macOS is still updating. Check updates before retrying; installation has not been cancelled.") }
            try await Task.sleep(for: .milliseconds(300))
        }
    }
}

private enum AppUpdateAlerts {
    static func pending(_ results: [String: AppUpdateRecord], notified: [String: String]) -> [String: AppUpdateRecord] {
        results.filter { $0.value.newer && !$0.value.reported.isEmpty && notified[$0.key] != $0.value.reported }
    }
}

private struct AppUpdateCacheFile: Codable {
    var format: Int
    var checkedAt: TimeInterval
    var results: [String: AppUpdateRecord]
}

private enum AppUpdateStore {
    static let ttl: TimeInterval = 3600
    static let format = 3
    static let maxBytes = 1_200 * 1024 * 1024
    static let maxVendorArchive = 2_000_000_000
    static let maxExpandedArchive: Int64 = 6_000_000_000
    static let maxDeveloperZip = 600 * 1024 * 1024
    static var file: URL {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent(".shixpeer.ward/macos/application-updates.json")
    }

    static func load() -> (date: Date, results: [String: AppUpdateRecord])? {
        guard let data = try? Data(contentsOf: file),
              data.count <= 1_000_000,
              let decoded = try? JSONDecoder().decode(AppUpdateCacheFile.self, from: data),
              decoded.format == format,
              decoded.results.count <= 500,
              decoded.checkedAt > 0 else { return nil }
        return (Date(timeIntervalSince1970: decoded.checkedAt), decoded.results)
    }

    static func save(_ results: [String: AppUpdateRecord], at date: Date = Date()) {
        var kept: [String: AppUpdateRecord] = [:]
        for (key, value) in results where kept.count < 500 {
            kept[key] = value
        }
        guard let data = try? JSONEncoder().encode(AppUpdateCacheFile(format: format, checkedAt: date.timeIntervalSince1970, results: kept)) else { return }
        let directory = file.deletingLastPathComponent()
        try? FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let temp = directory.appendingPathComponent(".application-updates-\(UUID().uuidString).json")
        do {
            try data.write(to: temp, options: .atomic)
            if FileManager.default.fileExists(atPath: file.path) {
                _ = try FileManager.default.replaceItemAt(file, withItemAt: temp)
            } else {
                try FileManager.default.moveItem(at: temp, to: file)
            }
        } catch {
            try? FileManager.default.removeItem(at: temp)
        }
    }
}

private struct SparkleZip {
    var version: String
    var url: URL
    var signature: Data
    var length: Int?
}

private func appChannel(_ app: Report.Inventory.Application) -> AppUpdateChannel {
    guard !app.identifier.isEmpty,
          let bundle = NSWorkspace.shared.urlForApplication(withBundleIdentifier: app.identifier) else {
        return app.identifier.isEmpty ? .none : .missing
    }
    let info = bundle.appendingPathComponent("Contents/Info.plist")
    let modified = (try? info.resourceValues(forKeys: [.contentModificationDateKey]).contentModificationDate)?.timeIntervalSince1970 ?? 0
    return ChannelMemo.shared.channel(for: bundle.path + "\t" + app.identifier + "\t" + String(modified)) {
        discoveredChannel(app, bundle: bundle)
    }
}

private func discoveredChannel(_ app: Report.Inventory.Application, bundle: URL) -> AppUpdateChannel {
    let plist = NSDictionary(contentsOf: bundle.appendingPathComponent("Contents/Info.plist"))
    let receipt = bundle.appendingPathComponent("Contents/_MASReceipt/receipt").path
    if FileManager.default.fileExists(atPath: receipt), appStoreIdentifier(app.identifier) {
        return .appStore(app.identifier)
    }
    if app.isApple { return .system }
    if app.identifier == "com.docker.docker" {
        let executable = bundle.appendingPathComponent("Contents/Resources/cli-plugins/docker-desktop")
        return FileManager.default.isExecutableFile(atPath: executable.path) ? .dockerDesktop(executable) : .none
    }
    if let channel = jetBrainsChannel(bundle, identifier: app.identifier) { return channel }
    if let feed = declaredSparkleFeed(bundle, plist: plist) {
        return .sparkle(feed)
    }
    if let url = electronFeed(bundle) {
        return .electron(url)
    }
    if let vscode = vscodeChannel(bundle) {
        return .vscode(vscode.0, vscode.1, vscode.2, vscode.3)
    }
    if let feed = eclipseProductFeed(bundle) { return .productXML(feed) }
    if let plain = plainVersionFeed(bundle) {
        return .plain(plain)
    }
    if let executable = mainExecutable(bundle) {
        let urls = NativeInstallerUpdates.candidates(executable: executable, arm: currentCPU() == "arm64")
        if !urls.isEmpty { return .installerMetadata(urls) }
    }
    if plist?["SUPublicEDKey"] != nil || plist?["SUPublicDSAKeyFile"] != nil {
        return .sparkleUnlisted
    }
    return .none
}

private func jetBrainsChannel(_ bundle: URL, identifier: String) -> AppUpdateChannel? {
    guard identifier.hasPrefix("com.jetbrains."),
          identifier.range(of: "^[A-Za-z0-9.]+$", options: .regularExpression) != nil else { return nil }
    var code: SecStaticCode?
    var requirement: SecRequirement?
    let expression = "anchor apple generic and identifier \"\(identifier)\" and certificate leaf[subject.OU] = \"2ZEFAR8TH3\""
    guard SecStaticCodeCreateWithPath(bundle as CFURL, [], &code) == errSecSuccess,
          SecRequirementCreateWithString(expression as CFString, [], &requirement) == errSecSuccess,
          let code, let requirement, SecStaticCodeCheckValidity(code, [], requirement) == errSecSuccess else { return nil }

    struct Product: Decodable { let productCode, version: String }
    let url = bundle.appendingPathComponent("Contents/Resources/product-info.json")
    guard let size = try? url.resourceValues(forKeys: [.fileSizeKey]).fileSize,
          size <= 2_000_000,
          let data = try? Data(contentsOf: url), data.count <= 2_000_000,
          let product = try? JSONDecoder().decode(Product.self, from: data),
          product.productCode.range(of: "^[A-Z0-9]{2,12}$", options: .regularExpression) != nil,
          versionOrder(product.version, product.version) != nil else { return nil }
    return .jetBrains(product.productCode, product.version)
}

private func declaredSparkleFeed(_ bundle: URL, plist: NSDictionary?) -> URL? {
    if let feed = plist?["SUFeedURL"] as? String, let url = httpsUpdateURL(feed) {
        return url
    }
    if let feed = packagedSparkleFeed(bundle, plist: plist) { return feed }
    return embeddedSparkleFeed(bundle)
}

private func boundedUpdateData(_ file: URL) -> Data? {
    guard let values = try? file.resourceValues(forKeys: [.fileSizeKey, .isRegularFileKey]),
          values.isRegularFile == true, let size = values.fileSize, size > 0, size <= 512_000,
          let data = try? Data(contentsOf: file), data.count <= 512_000 else { return nil }
    return data
}

// Only explicit updater configuration is authoritative. Package repositories
// and homepages can describe dependencies or templates rather than the app.
private func electronProviderFeed(_ configuration: [String: String]) -> URL? {
    guard let provider = configuration["provider"] else { return nil }
    let channel = configuration["channel"] ?? "latest"
    guard channel.range(of: "^[A-Za-z0-9_-]{1,40}$", options: .regularExpression) != nil else { return nil }
    if provider == "generic", let raw = configuration["url"], let base = httpsUpdateURL(raw) {
        if ["yml", "yaml"].contains(base.pathExtension.lowercased()) { return base }
        return base.appendingPathComponent(channel + "-mac.yml")
    }
    if provider == "github", configuration["private"] != "true",
       let owner = configuration["owner"], let repo = configuration["repo"],
       [owner, repo].allSatisfy({ $0.range(of: "^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$", options: .regularExpression) != nil && $0 != "." && $0 != ".." }),
       channel == "latest" {
        return URL(string: "https://github.com/" + owner + "/" + repo + "/releases/latest/download/latest-mac.yml")
    }
    return nil
}

private func electronConfigurationFeed(_ data: Data) -> URL? {
    if let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
        // Installed electron-builder configuration or explicit publish metadata.
        let publish = (object["build"] as? [String: Any])?["publish"] ?? object["publish"] ?? object
        let entries = (publish as? [[String: Any]]) ?? (publish as? [String: Any]).map { [$0] } ?? []
        for entry in entries {
            let strings = entry.compactMapValues { value -> String? in
                if let text = value as? String { return text }
                if let boolean = value as? Bool { return boolean ? "true" : "false" }
                return nil
            }
            if let feed = electronProviderFeed(strings) { return feed }
        }
        return nil
    }
    guard let text = String(data: data, encoding: .utf8) else { return nil }
    var configuration: [String: String] = [:]
    for raw in text.split(separator: "\n") {
        let line = raw.trimmingCharacters(in: .whitespaces)
        guard !line.hasPrefix("#"), let colon = line.firstIndex(of: ":") else { continue }
        let key = String(line[..<colon])
        guard ["provider", "url", "owner", "repo", "channel", "private"].contains(key),
              configuration[key] == nil else { continue }
        var value = String(line[line.index(after: colon)...]).trimmingCharacters(in: .whitespaces)
        if value.count >= 2 && ((value.hasPrefix("\"") && value.hasSuffix("\"")) ||
                               (value.hasPrefix("'") && value.hasSuffix("'"))) {
            value.removeFirst()
            value.removeLast()
        }
        configuration[key] = value
    }
    return electronProviderFeed(configuration)
}

// Electron ASAR keeps package.json behind a bounded JSON index.
// Read only that metadata member, without extracting or executing app code.
private func asarPackageData(_ archive: URL) -> Data? {
    guard let values = try? archive.resourceValues(forKeys: [.fileSizeKey, .isRegularFileKey]),
          values.isRegularFile == true, let fileSize = values.fileSize, fileSize >= 16,
          let handle = try? FileHandle(forReadingFrom: archive) else { return nil }
    defer { try? handle.close() }
    func read(_ count: Int) -> Data? {
        guard let data = try? handle.read(upToCount: count), data.count == count else { return nil }
        return data
    }
    guard let prefix = read(16) else { return nil }
    func word(_ offset: Int) -> UInt64 {
        (0..<4).reduce(UInt64(0)) { $0 | (UInt64(prefix[offset + $1]) << (8 * $1)) }
    }
    let headerBytes = word(4)
    let jsonBytes = word(12)
    guard word(0) == 4, headerBytes >= 8, headerBytes <= 8 * 1024 * 1024,
          word(8) + 4 == headerBytes, jsonBytes > 0, jsonBytes <= headerBytes - 8,
          8 + headerBytes <= UInt64(fileSize),
          let raw = read(Int(jsonBytes)),
          let header = try? JSONSerialization.jsonObject(with: raw) as? [String: Any],
          let files = header["files"] as? [String: Any],
          let member = files["package.json"] as? [String: Any],
          member["link"] == nil, member["unpacked"] == nil,
          let length = member["size"] as? NSNumber,
          CFGetTypeID(length) != CFBooleanGetTypeID(),
          let offsetText = member["offset"] as? String,
          offsetText.range(of: "^[0-9]{1,18}$", options: .regularExpression) != nil,
          let offset = UInt64(offsetText) else { return nil }
    let size = length.doubleValue
    guard size > 0, size <= 512_000, size.rounded() == size else { return nil }
    let base = 8 + headerBytes
    guard offset <= UInt64(fileSize) - base,
          UInt64(size) <= UInt64(fileSize) - base - offset else { return nil }
    do { try handle.seek(toOffset: base + offset) } catch { return nil }
    return read(Int(size))
}

private func packagedSparkleFeed(_ bundle: URL, plist: NSDictionary?) -> URL? {
    let data = asarPackageData(bundle.appendingPathComponent("Contents/Resources/app.asar"))
        ?? boundedUpdateData(bundle.appendingPathComponent("Contents/Resources/app/package.json"))
    guard let data, let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
          let publicKey = plist?["SUPublicEDKey"] as? String else { return nil }
    var feeds = Set<URL>()
    for (key, value) in object {
        let normalized = key.lowercased()
        let suffix = "sparklefeedurl"
        guard normalized.hasSuffix(suffix), let raw = value as? String,
              let url = httpsUpdateURL(raw) else { continue }
        let prefix = String(normalized.dropLast(suffix.count))
        let keys = object.filter { $0.key.lowercased() == prefix + "sparklepublickey" }
        guard keys.count == 1, keys.first?.value as? String == publicKey else { continue }
        feeds.insert(url)
    }
    return feeds.count == 1 ? feeds.first : nil
}

private func electronFeed(_ bundle: URL) -> URL? {
    for path in ["Contents/Resources/app-update.yml", "Contents/Resources/app-update.yaml",
                 "Contents/Resources/app-update.json", "Contents/Resources/app/package.json"] {
        if let data = boundedUpdateData(bundle.appendingPathComponent(path)),
           let feed = electronConfigurationFeed(data) { return feed }
    }
    if let data = asarPackageData(bundle.appendingPathComponent("Contents/Resources/app.asar")) {
        return electronConfigurationFeed(data)
    }
    return nil
}

private func liveVersion(_ app: Report.Inventory.Application) -> String {
    guard !app.identifier.isEmpty,
          let bundle = NSWorkspace.shared.urlForApplication(withBundleIdentifier: app.identifier),
          let plist = NSDictionary(contentsOf: bundle.appendingPathComponent("Contents/Info.plist")),
          let short = plist["CFBundleShortVersionString"] as? String else { return app.version }
    let trimmed = short.trimmingCharacters(in: .whitespacesAndNewlines)
    return trimmed.isEmpty ? app.version : trimmed
}

private func updateJobs(for applications: [Report.Inventory.Application]) -> [AppUpdateJob] {
    applications.compactMap { app -> AppUpdateJob? in
        guard !app.identifier.isEmpty else { return nil }
        let installed = liveVersion(app)
        guard !installed.isEmpty else { return nil }
        switch appChannel(app) {
        case .jetBrains(let code, let version):
            return AppUpdateJob(id: app.identifier, installed: version, target: .jetBrains(code))
        case .appStore(let id):
            return AppUpdateJob(id: app.identifier, installed: installed, target: .appStore(id))
        case .sparkle(let url):
            let bundle = NSWorkspace.shared.urlForApplication(withBundleIdentifier: app.identifier)
            let hasKey = bundle.map(sparkleHasSigningKey) ?? false
            return AppUpdateJob(id: app.identifier, installed: installed, target: .sparkle(url, hasKey))
        case .electron(let url):
            return AppUpdateJob(id: app.identifier, installed: installed, target: .electron(url))
        case .vscode(let base, let platform, let name, let quality):
            return AppUpdateJob(id: app.identifier, installed: installed, target: .vscode(base, platform, name, quality))
        case .installerMetadata(let urls):
            return AppUpdateJob(id: app.identifier, installed: installed, target: .installerMetadata(urls))
        case .productXML(let url):
            return AppUpdateJob(id: app.identifier, installed: installed, target: .productXML(url))
        case .plain(let url):
            return AppUpdateJob(id: app.identifier, installed: installed, target: .plain(url))
        case .dockerDesktop(let executable):
            return AppUpdateJob(id: app.identifier, installed: installed, target: .dockerDesktop(executable))
        case .sparkleUnlisted, .system, .none, .missing:
            return nil
        }
    }
}

private struct VendorPackage {
    let version: String
    let url: URL?
    let size: Int?
    var checksumURL: URL? = nil
    var sha512: String? = nil
}

private func verifyArchiveChecksum(_ file: URL, sha256: String? = nil, sha512: String? = nil) throws {
    guard sha256 != nil || sha512 != nil else { return }
    if let sha256, sha256.range(of: "^[A-Fa-f0-9]{64}$", options: .regularExpression) == nil { throw WardError("Invalid SHA-256 metadata.") }
    if let sha512, Data(base64Encoded: sha512)?.count != 64 { throw WardError("Invalid SHA-512 metadata.") }
    let handle = try FileHandle(forReadingFrom: file)
    defer { try? handle.close() }
    var hash256 = SHA256(); var hash512 = SHA512()
    while let block = try handle.read(upToCount: 1 << 20), !block.isEmpty {
        if sha256 != nil { hash256.update(data: block) }
        if sha512 != nil { hash512.update(data: block) }
    }
    if let sha256, hash256.finalize().map({ String(format: "%02x", $0) }).joined() != sha256.lowercased() { throw WardError("Archive SHA-256 mismatch. Installation stopped.") }
    if let sha512, Data(hash512.finalize()).base64EncodedString() != sha512 { throw WardError("Archive SHA-512 mismatch. Installation stopped.") }
}

private func installableVendorURL(_ raw: String) -> URL? {
    guard let url = httpsUpdateURL(raw), archiveSuffix(url.path.lowercased()) != nil else { return nil }
    return url
}

private func jetBrainsPackage(_ code: String) async throws -> VendorPackage {
    guard code.range(of: "^[A-Z0-9]{2,12}$", options: .regularExpression) != nil else { throw URLError(.badURL) }
    var parts = URLComponents(string: "https://data.services.jetbrains.com/products/releases")!
    parts.queryItems = [URLQueryItem(name: "code", value: code), URLQueryItem(name: "type", value: "release"),
                        URLQueryItem(name: "latest", value: "true")]
    struct Download: Decodable { let link: String; let size: Int; let checksumLink: String? }
    struct Release: Decodable { let version, type: String; let downloads: [String: Download] }
    let releases = try JSONDecoder().decode([String: [Release]].self, from: await fetchHTTPS(parts.url!))
    let stable = (releases[code] ?? []).filter { $0.type == "release" }
    guard let version = newestComparable(stable.map(\.version)), let release = stable.first(where: { $0.version == version }) else {
        throw URLError(.badServerResponse)
    }
    let architecture = currentCPU() == "arm64" ? "macM1" : "mac"
    guard let archive = release.downloads[architecture], archive.size > 0,
          archive.size <= AppUpdateStore.maxVendorArchive, let url = installableVendorURL(archive.link) else {
        return VendorPackage(version: version, url: nil, size: nil)
    }
    let checksumURL = archive.checksumLink.flatMap(httpsUpdateURL)
    if archive.checksumLink != nil && checksumURL == nil { throw URLError(.badServerResponse) }
    return VendorPackage(version: version, url: url, size: archive.size, checksumURL: checksumURL)
}

private func electronPackage(_ base: URL) async throws -> VendorPackage {
    let feed = ["yml", "yaml"].contains(base.pathExtension.lowercased()) ? base : base.appendingPathComponent("latest-mac.yml")
    return try electronPackageMetadata(try await fetchHTTPS(feed), feed: feed)
}

private func electronPackageMetadata(_ data: Data, feed: URL) throws -> VendorPackage {
    let text = String(decoding: data, as: UTF8.self)
    var fields: [String: String] = [:]
    for raw in text.split(separator: "\n") where !raw.hasPrefix(" ") && !raw.hasPrefix("\t") {
        guard let colon = raw.firstIndex(of: ":") else { continue }
        let key = String(raw[..<colon])
        guard ["version", "path", "sha512"].contains(key), fields[key] == nil else { continue }
        var value = raw[raw.index(after: colon)...].trimmingCharacters(in: .whitespaces)
        if value.count >= 2 && ((value.hasPrefix("\"") && value.hasSuffix("\"")) ||
                               (value.hasPrefix("'") && value.hasSuffix("'"))) {
            value.removeFirst(); value.removeLast()
        }
        fields[key] = value
    }
    guard let version = fields["version"], versionOrder(version, version) != nil else { throw URLError(.badServerResponse) }
    let url = fields["path"].flatMap { resolveFeedURL($0, relativeTo: feed) }.flatMap { installableVendorURL($0.absoluteString) }
    if let checksum = fields["sha512"], Data(base64Encoded: checksum)?.count != 64 { throw URLError(.badServerResponse) }
    return VendorPackage(version: version, url: url, size: nil, sha512: fields["sha512"])
}

private func verifyDeveloperUpdate(_ app: URL, bundleID: String, team: String) throws {
    guard team.range(of: "^[A-Z0-9]{10}$", options: .regularExpression) != nil,
          bundleID.range(of: "^[A-Za-z0-9][A-Za-z0-9.-]*$", options: .regularExpression) != nil else {
        throw WardError("The developer signature cannot be verified.")
    }
    let requirement = "anchor apple generic and identifier \"\(bundleID)\" and certificate leaf[subject.OU] = \"\(team)\""
    try runTool("/usr/bin/codesign", ["--verify", "--strict", "--deep", "-R=" + requirement, app.path])
}

private struct AppUpdateJob: Sendable {
    enum Target: Sendable {
        case installerMetadata([URL])
        case productXML(URL)
        case jetBrains(String)
        case appStore(String)
        case sparkle(URL, Bool)
        case electron(URL)
        case vscode(URL, String, String, String)
        case plain(URL)
        case dockerDesktop(URL)
    }
    let id: String
    let installed: String
    let target: Target

    func lookup() async -> AppUpdateRecord {
        do {
            switch target {
            case .installerMetadata(let urls):
                let version = try await NativeInstallerUpdates.version(urls, id: id)
                return Self.record(channel: "its installer metadata", installed: installed, reported: version, canInstall: false)
            case .jetBrains(let code):
                let package = try await jetBrainsPackage(code)
                return Self.record(channel: "JetBrains", installed: installed, reported: package.version,
                                   canInstall: package.url != nil)
            case .appStore(let bundleID):
                let reported = try await Self.appStoreVersion(bundleID)
                return Self.record(channel: "the App Store", installed: installed, reported: reported, canInstall: false)
            case .sparkle(let url, let hasKey):
                let xml = String(decoding: try await fetchHTTPS(url), as: UTF8.self)
                guard let reported = newestComparable(sparkleVersions(xml)) else { throw URLError(.badServerResponse) }
                let base = Self.record(channel: "Sparkle", installed: installed, reported: reported, canInstall: false)
                let installable = base.newer && hasKey && sparkleInstallableArchive(xml, version: reported, feed: url) != nil
                return AppUpdateRecord(text: base.text, newer: base.newer, canInstall: installable, reported: reported, installed: installed)
            case .electron(let url):
                let package = try await electronPackage(url)
                return Self.record(channel: "its updater", installed: installed, reported: package.version,
                                   canInstall: package.url != nil)
            case .vscode(let base, let platform, let name, let quality):
                return try await Self.vscodeRecord(base: base, platform: platform, name: name, quality: quality, installed: installed)
            case .dockerDesktop(let executable):
                let reported = try await Self.dockerDesktopVersion(executable)
                return Self.record(channel: "Docker Desktop", installed: installed, reported: reported, canInstall: false)
            case .productXML(let url):
                let data = try await fetchHTTPS(url)
                guard let reported = productXMLVersion(data) else { throw URLError(.badServerResponse) }
                return Self.record(channel: "its product update feed", installed: installed, reported: reported, canInstall: false)
            case .plain(let url):
                let reported = try await Self.plainVersion(url)
                return Self.record(channel: "its updater", installed: installed, reported: reported, canInstall: false)
            }
        } catch {
            let text: String
            switch target {
            case .jetBrains: text = "JetBrains release check failed"
            case .appStore: text = "App Store check failed"
            case .dockerDesktop: text = "Docker Desktop update check failed"
            case .sparkle: text = "Sparkle feed could not be read"
            case .electron, .vscode, .plain, .productXML, .installerMetadata: text = "Updater feed could not be read"
            }
            return AppUpdateRecord(text: text, newer: false, canInstall: false, reported: "", installed: installed)
        }
    }

    private static func dockerDesktopVersion(_ executable: URL) async throws -> String {
        let arch = currentCPU() == "arm64" ? "arm64" : "amd64"
        let url = URL(string: "https://desktop.docker.com/mac/main/" + arch + "/appcast.json")!
        struct Feed: Decodable {
            struct Item: Decodable { let AppVersion: String; let Visibility: String? }
            let Items: [Item]
        }
        let feed = try JSONDecoder().decode(Feed.self, from: await fetchHTTPS(url))
        guard let version = newestComparable(feed.Items.filter { ($0.Visibility.flatMap(Double.init) ?? 0) > 0 }.map(\.AppVersion)) else {
            throw WardError("No published stable Docker Desktop version.")
        }
        return version
    }

    private static func record(channel: String, installed: String, reported: String, canInstall: Bool) -> AppUpdateRecord {
        let text: String
        let newer: Bool
        if let order = versionOrder(installed, reported) {
            switch order {
            case .orderedAscending:
                text = "Newer \(reported) on \(channel)"
                newer = true
            case .orderedSame:
                text = "Already the newest on \(channel)"
                newer = false
            default:
                text = "Installed is newer than \(channel) (\(reported))"
                newer = false
            }
        } else {
            text = "\(channel) reports \(reported)"
            newer = false
        }
        return AppUpdateRecord(text: text, newer: newer, canInstall: canInstall && newer, reported: reported, installed: installed)
    }

    private static func appStoreVersion(_ bundleID: String) async throws -> String {
        guard appStoreIdentifier(bundleID),
              var parts = URLComponents(string: "https://itunes.apple.com/lookup") else { throw URLError(.badURL) }
        parts.queryItems = [URLQueryItem(name: "bundleId", value: bundleID)]
        guard let url = parts.url else { throw URLError(.badURL) }
        let data = try await fetchHTTPS(url)
        struct Lookup: Decodable {
            struct Item: Decodable { let version, bundleId: String? }
            let results: [Item]
        }
        let lookup = try JSONDecoder().decode(Lookup.self, from: data)
        guard let item = lookup.results.first, item.bundleId == bundleID, let version = item.version, !version.isEmpty else {
            throw URLError(.badServerResponse)
        }
        return version
    }

    private static func vscodeRecord(base: URL, platform: String, name: String, quality: String, installed: String) async throws -> AppUpdateRecord {
        guard let url = vscodeCheckURL(base: base, platform: platform, name: name, quality: quality, installed: installed) else {
            throw URLError(.badURL)
        }
        let (data, status) = try await fetchHTTPSStatus(url)
        if status == 204 {
            return record(channel: "its updater", installed: installed, reported: installed, canInstall: false)
        }
        struct Payload: Decodable { let url, name: String; let sha256hash: String? }
        let payload = try JSONDecoder().decode(Payload.self, from: data)
        let archive = httpsUpdateURL(payload.url)
        let zip = archive?.path.lowercased().hasSuffix(".zip") == true
        let baseRecord = record(channel: "its updater", installed: installed, reported: payload.name, canInstall: false)
        let installable = baseRecord.newer && zip
        return AppUpdateRecord(text: baseRecord.text, newer: baseRecord.newer, canInstall: installable, reported: payload.name, installed: installed)
    }

    private static func plainVersion(_ url: URL) async throws -> String {
        let text = String(decoding: try await fetchHTTPS(url), as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
        let token = text.split(whereSeparator: \.isWhitespace).first.map(String.init) ?? ""
        guard versionOrder(token, token) != nil else { throw URLError(.badServerResponse) }
        return token
    }
}

private func appStoreIdentifier(_ identifier: String) -> Bool {
    identifier.range(of: "^[A-Za-z0-9][A-Za-z0-9.-]{0,200}$", options: .regularExpression) != nil
}

// Apps the account has opened that live outside the folders the scan walks.
// A preferences file is the evidence of a launch. Library, build trees and nested copies stay out.
private func outsideApplications(known: Set<String>, includeStandardLocations: Bool = false) -> [Report.Inventory.Application] {
    let home = FileManager.default.homeDirectoryForCurrentUser.path
    guard let lines = spotlightApplications() else { return [] }
    var found: [Report.Inventory.Application] = []
    var seen = Set<String>()
    for raw in lines {
        guard let bundle = applicationBundleURL(raw) else { continue }
        let path = bundle.path
        let standard = path.hasPrefix("/Applications/") || path.hasPrefix(home + "/Applications/")
        if seen.contains(path) || (skippedOutsidePath(path, home: home) && !(includeStandardLocations && standard)) { continue }
        seen.insert(path)
        guard let plist = NSDictionary(contentsOf: bundle.appendingPathComponent("Contents/Info.plist")),
              let identifier = plist["CFBundleIdentifier"] as? String,
              appStoreIdentifier(identifier),
              identifier != "com.shixpeer.ward",
              !known.contains(identifier) else { continue }
        let prefs = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Preferences")
            .appendingPathComponent(identifier + ".plist")
        var directory: ObjCBool = false
        guard (includeStandardLocations && standard) || (FileManager.default.fileExists(atPath: prefs.path, isDirectory: &directory) && !directory.boolValue) else { continue }
        var name = ((plist["CFBundleName"] as? String) ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        if name.isEmpty {
            name = ((plist["CFBundleDisplayName"] as? String) ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        }
        if name.isEmpty { name = bundle.deletingPathExtension().lastPathComponent }
        var version = ((plist["CFBundleShortVersionString"] as? String) ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        var kind = "release"
        if version.isEmpty {
            version = ((plist["CFBundleVersion"] as? String) ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
            kind = "build"
        }
        guard name.count <= 512, version.count <= 512 else { continue }
        found.append(Report.Inventory.Application(name: name, version: version, identifier: identifier, versionKind: kind))
        if found.count >= 200 { break }
    }
    return found
}

private func spotlightApplications() -> [String]? {
    let task = Process()
    task.executableURL = URL(fileURLWithPath: "/usr/bin/mdfind")
    task.arguments = ["kMDItemContentTypeTree == 'com.apple.application-bundle'"]
    let pipe = Pipe()
    task.standardOutput = pipe
    task.standardError = FileHandle.nullDevice
    do { try task.run() } catch { return nil }
    let data = pipe.fileHandleForReading.readData(ofLength: 2_000_001)
    if data.count > 2_000_000 {
        task.terminate()
        _ = pipe.fileHandleForReading.readDataToEndOfFile()
        return nil
    }
    task.waitUntilExit()
    guard task.terminationStatus == 0 else { return nil }
    guard let text = String(data: data, encoding: .utf8) else { return nil }
    return text.split(whereSeparator: \.isNewline).map(String.init)
}

private func applicationBundleURL(_ raw: String) -> URL? {
    let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
    guard trimmed.hasPrefix("/"), let range = trimmed.range(of: ".app") else { return nil }
    let end = trimmed.index(range.lowerBound, offsetBy: 4)
    if end != trimmed.endIndex, trimmed[end] != "/" { return nil }
    let path = String(trimmed[..<end])
    guard !path.contains(".."), !path.contains(".app/") else { return nil }
    return URL(fileURLWithPath: path).standardizedFileURL
}

private func skippedOutsidePath(_ path: String, home: String) -> Bool {
    if path.hasPrefix("/Applications/") || path.hasPrefix("/System/") || path.hasPrefix(home + "/Applications/") {
        return true
    }
    if path.contains(".framework/") { return true }
    for part in path.split(separator: "/") {
        if part == "Library" || part == "node_modules" || part == "DerivedData" || part == "dist" {
            return true
        }
    }
    return false
}

private func httpsUpdateURL(_ string: String) -> URL? {
    guard let url = URL(string: string),
          url.scheme?.lowercased() == "https",
          let host = url.host, !host.isEmpty, host.contains("."),
          url.user == nil, url.password == nil else { return nil }
    return url
}

private func fetchHTTPS(_ url: URL) async throws -> Data {
    let (data, response) = try await MetadataBackend.shared.fetch(url)
    guard response.statusCode == 200 else { throw URLError(.badServerResponse) }
    return data
}

private func fetchHTTPSStatus(_ url: URL) async throws -> (data: Data, status: Int) {
    let (data, response) = try await MetadataBackend.shared.fetch(url)
    guard response.statusCode == 200 || response.statusCode == 204 else { throw URLError(.badServerResponse) }
    return (data, response.statusCode)
}

private func vscodeCheckURL(base: URL, platform: String, name: String, quality: String, installed: String) -> URL? {
    func token(_ value: String, _ pattern: String) -> Bool {
        value.range(of: pattern, options: .regularExpression) != nil
    }
    guard token(platform, "^[A-Za-z0-9-]{1,40}$"),
          token(name, "^[a-z0-9-]{1,40}$"),
          token(quality, "^[a-z]{1,20}$"),
          token(installed, "^[0-9]+(\\.[0-9]+){0,6}$") else { return nil }
    var root = base.absoluteString
    if root.hasSuffix("/") { root.removeLast() }
    return httpsUpdateURL(root + "/api/update/\(platform)/\(name)/\(installed)/shixpeer-ward/\(quality)")
}

private func decodeBase64(_ raw: String) -> Data? {
    let text = raw.trimmingCharacters(in: .whitespacesAndNewlines).replacingOccurrences(of: "\n", with: "")
    if let data = Data(base64Encoded: text) { return data }
    let remainder = text.count % 4
    guard remainder != 0 else { return nil }
    return Data(base64Encoded: text + String(repeating: "=", count: 4 - remainder))
}

private func xmlUnescape(_ value: String) -> String {
    value.replacingOccurrences(of: "&amp;", with: "&")
        .replacingOccurrences(of: "&quot;", with: "\"")
        .replacingOccurrences(of: "&apos;", with: "'")
        .replacingOccurrences(of: "&lt;", with: "<")
        .replacingOccurrences(of: "&gt;", with: ">")
}

private func sparkleHasSigningKey(_ bundle: URL) -> Bool {
    let plist = NSDictionary(contentsOf: bundle.appendingPathComponent("Contents/Info.plist"))
    guard let raw = plist?["SUPublicEDKey"] as? String, let data = decodeBase64(raw) else { return false }
    return data.count == 32
}

private func sparkleInstallableArchive(_ xml: String, version: String, feed: URL) -> SparkleZip? {
    for item in sparkleItemBodies(xml) {
        guard sparkleItemVersion(item) == version else { continue }
        guard let expression = try? NSRegularExpression(pattern: #"<enclosure\b[^>]*>"#) else { return nil }
        let range = NSRange(item.startIndex..., in: item)
        guard let match = expression.firstMatch(in: item, range: range),
              let slice = Range(match.range, in: item) else { continue }
        let tag = String(item[slice])
        guard let rawURL = xmlAttribute(tag, "url"), let url = resolveFeedURL(xmlUnescape(rawURL), relativeTo: feed) else { continue }
        let name = url.lastPathComponent.lowercased()
        guard archiveSuffix(name) != nil, !name.contains(".delta") else { continue }
        guard let sigText = xmlAttribute(tag, "sparkle:edSignature"),
              let signature = decodeBase64(xmlUnescape(sigText)), signature.count == 64 else { continue }
        let length = xmlAttribute(tag, "length").flatMap(Int.init)
        if let length, length <= 0 || length > AppUpdateStore.maxBytes { continue }
        return SparkleZip(version: version, url: url, signature: signature, length: length)
    }
    return nil
}

private func sparkleItemBodies(_ xml: String) -> [String] {
    guard let expression = try? NSRegularExpression(pattern: #"<item\b[^>]*>[\s\S]*?</item>"#) else { return [] }
    let range = NSRange(xml.startIndex..., in: xml)
    return expression.matches(in: xml, range: range).prefix(40).compactMap { match in
        Range(match.range, in: xml).map { String(xml[$0]) }
    }
}

private func sparkleItemVersion(_ item: String) -> String? {
    if let short = xmlElement(item, "sparkle:shortVersionString"), !short.isEmpty { return short }
    if let short = xmlAttribute(item, "sparkle:shortVersionString") { return short }
    if let version = xmlElement(item, "sparkle:version"), !version.isEmpty { return version }
    return xmlAttribute(item, "sparkle:version")
}

private func xmlElement(_ xml: String, _ name: String) -> String? {
    let pattern = "<" + NSRegularExpression.escapedPattern(for: name) + #"(?:\s[^>]*)?>([^<]+)</"# + NSRegularExpression.escapedPattern(for: name) + ">"
    guard let expression = try? NSRegularExpression(pattern: pattern) else { return nil }
    let range = NSRange(xml.startIndex..., in: xml)
    guard let match = expression.firstMatch(in: xml, range: range),
          match.numberOfRanges > 1,
          let slice = Range(match.range(at: 1), in: xml) else { return nil }
    let value = xml[slice].trimmingCharacters(in: .whitespacesAndNewlines)
    return value.isEmpty ? nil : String(value)
}

private func resolveFeedURL(_ raw: String, relativeTo feed: URL) -> URL? {
    if raw.lowercased().hasPrefix("http://") { return nil }
    if let absolute = httpsUpdateURL(raw) { return absolute }
    guard !raw.contains("://"), let resolved = URL(string: raw, relativeTo: feed)?.absoluteURL else { return nil }
    return httpsUpdateURL(resolved.absoluteString)
}

private func archiveSuffix(_ name: String) -> String? {
    for suffix in [".tar.xz", ".tar.gz", ".tar.bz2", ".zip", ".dmg", ".txz", ".tgz"] where name.hasSuffix(suffix) {
        return suffix
    }
    return nil
}

private func embeddedSparkleFeed(_ bundle: URL) -> URL? {
    let arch = currentCPU()
    var found: [URL] = []
    var budget = 40_000_000
    for file in sparkleCandidateFiles(bundle) {
        guard budget > 0 else { break }
        guard let values = try? file.resourceValues(forKeys: [.fileSizeKey, .isRegularFileKey]),
              values.isRegularFile == true,
              let size = values.fileSize, size > 0, size <= 20_000_000, size <= budget,
              let data = try? Data(contentsOf: file, options: [.mappedIfSafe]) else { continue }
        budget -= data.count
        found.append(contentsOf: sparkleFeedURLs(in: data))
    }
    return found.max { scoreSparkleFeed($0, arch: arch) < scoreSparkleFeed($1, arch: arch) }
}

private func mainExecutable(_ bundle: URL) -> URL? {
    let plist = NSDictionary(contentsOf: bundle.appendingPathComponent("Contents/Info.plist"))
    let macos = bundle.appendingPathComponent("Contents/MacOS")
    if let exe = plist?["CFBundleExecutable"] as? String {
        let trimmed = exe.trimmingCharacters(in: .whitespacesAndNewlines)
        if !trimmed.isEmpty {
            let url = macos.appendingPathComponent(trimmed)
            if FileManager.default.fileExists(atPath: url.path) { return url }
        }
    }
    guard let items = try? FileManager.default.contentsOfDirectory(at: macos, includingPropertiesForKeys: [.isRegularFileKey]) else { return nil }
    let files = items.filter { (try? $0.resourceValues(forKeys: [.isRegularFileKey]).isRegularFile) == true }
    return files.count == 1 ? files[0] : nil
}

private func sparkleCandidateFiles(_ bundle: URL) -> [URL] {
    var files: [URL] = []
    if let exe = mainExecutable(bundle) { files.append(exe) }
    let macos = bundle.appendingPathComponent("Contents/MacOS")
    if let items = try? FileManager.default.contentsOfDirectory(at: macos, includingPropertiesForKeys: nil) {
        for url in items {
            let name = url.lastPathComponent.lowercased()
            if name.contains("sparkle") || name.contains("update") { files.append(url) }
        }
    }
    let plugins = macos.appendingPathComponent("plugins")
    if let items = try? FileManager.default.contentsOfDirectory(at: plugins, includingPropertiesForKeys: nil) {
        for url in items {
            let name = url.lastPathComponent.lowercased()
            if name.contains("macos") || name.contains("sparkle") || name.contains("update") { files.append(url) }
        }
    }
    return files
}

private func sparkleFeedURLs(in data: Data) -> [URL] {
    guard let text = String(data: data, encoding: .isoLatin1),
          let expression = try? NSRegularExpression(pattern: #"https://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{8,200}"#) else { return [] }
    let range = NSRange(text.startIndex..., in: text)
    var urls: [URL] = []
    for match in expression.matches(in: text, range: range).prefix(400) {
        guard let slice = Range(match.range, in: text), let url = httpsUpdateURL(String(text[slice])) else { continue }
        let path = url.path.lowercased()
        let host = url.host?.lowercased() ?? ""
        guard host != "sparkle-project.org",
              (path.contains("appcast") && path.hasSuffix(".xml")) || (path.contains("/sparkle/") && path.hasSuffix(".xml")) else { continue }
        urls.append(url)
    }
    return urls
}

private func scoreSparkleFeed(_ url: URL, arch: String) -> Int {
    let path = url.path.lowercased()
    var score = 0
    if path.contains("appcast") { score += 5 }
    if path.contains("/stable/") { score += 8 }
    if path.contains("unstable") || path.contains("release-candidate") || path.contains(".dev") { score -= 20 }
    if path.contains(arch) { score += 12 }
    let other = arch == "arm64" ? "intel64" : "arm64"
    if path.contains(other) || (arch == "arm64" && (path.contains("x86_64") || path.contains("intel64"))) { score -= 30 }
    if arch != "arm64" && path.contains("arm64") { score -= 30 }
    return score
}

private func currentCPU() -> String {
    #if arch(arm64)
    return "arm64"
    #else
    return "intel64"
    #endif
}

// Reads the active Eclipse product declaration, never plugin update repositories.
private func eclipseProductFeed(_ bundle: URL) -> URL? {
    let root = bundle.appendingPathComponent("Contents/Eclipse")
    guard let data = boundedUpdateData(root.appendingPathComponent("configuration/config.ini")),
          let text = String(data: data, encoding: .utf8) else { return nil }
    let products = text.split(separator: "\n").compactMap { line -> String? in
        let parts = line.split(separator: "=", maxSplits: 1)
        guard parts.count == 2, parts[0].trimmingCharacters(in: .whitespaces) == "eclipse.product" else { return nil }
        return parts[1].trimmingCharacters(in: .whitespacesAndNewlines)
    }
    guard products.count == 1, let product = products.first,
          product.range(of: "^[A-Za-z0-9_.-]{1,240}$", options: .regularExpression) != nil,
          let dot = product.lastIndex(of: ".") else { return nil }
    let plugin = String(product[..<dot])
    let extensionID = String(product[product.index(after: dot)...])
    let directory = root.appendingPathComponent("plugins")
    guard let entries = try? FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil) else { return nil }
    let candidates = entries.filter { $0.lastPathComponent.hasPrefix(plugin + "_") && $0.pathExtension == "jar" }
    guard candidates.count == 1, let archive = candidates.first,
          let xml = zipMetadata(archive, member: "plugin.xml") else { return nil }
    let delegate = ProductMetadataParser(extensionID: extensionID)
    let parser = XMLParser(data: xml)
    parser.shouldResolveExternalEntities = false
    parser.delegate = delegate
    guard parser.parse(), delegate.feeds.count == 1 else { return nil }
    return delegate.feeds.first.flatMap(httpsUpdateURL)
}

private func zipMetadata(_ archive: URL, member: String) -> Data? {
    let process = Process()
    let pipe = Pipe()
    process.executableURL = URL(fileURLWithPath: "/usr/bin/unzip")
    process.arguments = ["-p", archive.path, member]
    process.standardInput = FileHandle.nullDevice
    process.standardOutput = pipe
    process.standardError = FileHandle.nullDevice
    do { try process.run() } catch { return nil }
    pipe.fileHandleForWriting.closeFile()
    let timeout = DispatchWorkItem { if process.isRunning { process.terminate() } }
    DispatchQueue.global().asyncAfter(deadline: .now() + 5, execute: timeout)
    defer { timeout.cancel() }
    let data = pipe.fileHandleForReading.readData(ofLength: 512_001)
    if data.count > 512_000 {
        if process.isRunning { process.terminate() }
        pipe.fileHandleForReading.closeFile()
        process.waitUntilExit()
        return nil
    }
    process.waitUntilExit()
    return process.terminationStatus == 0 ? data : nil
}

private final class ProductMetadataParser: NSObject, XMLParserDelegate {
    let extensionID: String
    var feeds: [String] = []
    private var active = false
    init(extensionID: String) { self.extensionID = extensionID }
    func parser(_ parser: XMLParser, didStartElement elementName: String, namespaceURI: String?,
                qualifiedName qName: String?, attributes: [String: String]) {
        if elementName == "extension" {
            active = attributes["point"] == "org.eclipse.core.runtime.products" && attributes["id"] == extensionID
        }
        if active && elementName == "property" && attributes["name"] == "versionUpdateURL",
           let value = attributes["value"] { feeds.append(value) }
    }
    func parser(_ parser: XMLParser, didEndElement elementName: String, namespaceURI: String?, qualifiedName qName: String?) {
        if elementName == "extension" { active = false }
    }
}

private func productXMLVersion(_ data: Data) -> String? {
    let delegate = ProductVersionParser()
    let parser = XMLParser(data: data)
    parser.shouldResolveExternalEntities = false
    parser.delegate = delegate
    guard parser.parse(), delegate.versions.count == 1, let value = delegate.versions.first,
          versionOrder(value, value) != nil else { return nil }
    return value
}

private final class ProductVersionParser: NSObject, XMLParserDelegate {
    var versions: [String] = []
    private var elements: [String] = []
    private var number = ""
    func parser(_ parser: XMLParser, didStartElement elementName: String, namespaceURI: String?,
                qualifiedName qName: String?, attributes: [String: String]) {
        elements.append(elementName)
        if elements == ["version", "number"] { number = "" }
    }
    func parser(_ parser: XMLParser, foundCharacters string: String) {
        if elements == ["version", "number"] { number += string }
    }
    func parser(_ parser: XMLParser, didEndElement elementName: String, namespaceURI: String?, qualifiedName qName: String?) {
        if elements == ["version", "number"] { versions.append(number.trimmingCharacters(in: .whitespacesAndNewlines)) }
        if !elements.isEmpty { elements.removeLast() }
    }
}

private func plainVersionFeed(_ bundle: URL) -> URL? {
    guard let file = mainExecutable(bundle) else { return nil }
    guard let values = try? file.resourceValues(forKeys: [.fileSizeKey, .isRegularFileKey]),
          values.isRegularFile == true,
          let size = values.fileSize, size > 0, size <= 30_000_000,
          let data = try? Data(contentsOf: file, options: [.mappedIfSafe]),
          let text = String(data: data, encoding: .isoLatin1),
          let expression = try? NSRegularExpression(pattern: #"https://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{8,200}"#) else { return nil }
    let range = NSRange(text.startIndex..., in: text)
    for match in expression.matches(in: text, range: range).prefix(400) {
        guard let slice = Range(match.range, in: text), let url = httpsUpdateURL(String(text[slice])) else { continue }
        if url.lastPathComponent == "currentrelease" { return url }
    }
    return nil
}

private func vscodeChannel(_ bundle: URL) -> (URL, String, String, String)? {
    let file = bundle.appendingPathComponent("Contents/Resources/app/product.json")
    guard let data = try? Data(contentsOf: file), data.count <= 2_000_000,
          let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
          let update = json["updateUrl"] as? String, let base = httpsUpdateURL(update),
          let name = (json["nameShort"] as? String)?.lowercased().replacingOccurrences(of: " ", with: "-"),
          let quality = json["quality"] as? String, quality == "stable" || quality == "insider" else { return nil }
    let platform: String
    if let universal = json["darwinUniversalAssetId"] as? String, universal.hasPrefix("darwin") {
        platform = universal
    } else {
        platform = currentCPU() == "arm64" ? "darwin-arm64" : "darwin"
    }
    return (base, platform, name, quality)
}

private final class ChannelMemo: @unchecked Sendable {
    static let shared = ChannelMemo()
    private let lock = NSLock()
    private var values: [String: AppUpdateChannel] = [:]
    func channel(for key: String, make: () -> AppUpdateChannel) -> AppUpdateChannel {
        lock.lock()
        if let cached = values[key] {
            lock.unlock()
            return cached
        }
        lock.unlock()
        let made = make()
        lock.lock()
        values[key] = made
        lock.unlock()
        return made
    }
}

private func xmlAttribute(_ tag: String, _ name: String) -> String? {
    let pattern = NSRegularExpression.escapedPattern(for: name) + #"\s*=\s*"([^"]*)""#
    guard let expression = try? NSRegularExpression(pattern: pattern) else { return nil }
    let range = NSRange(tag.startIndex..., in: tag)
    guard let match = expression.firstMatch(in: tag, range: range),
          match.numberOfRanges > 1,
          let slice = Range(match.range(at: 1), in: tag) else { return nil }
    let value = tag[slice].trimmingCharacters(in: .whitespacesAndNewlines)
    return value.isEmpty ? nil : String(value)
}

private final class ArchiveDownloadProgress: NSObject, URLSessionDownloadDelegate, @unchecked Sendable {
    let maximum: Int64
    let progress: (@MainActor @Sendable (Int64, Int64) -> Void)?
    private var lastUpdate = Date.distantPast
    var completion: CheckedContinuation<(URL, URLResponse), Error>?
    private var downloaded: URL?
    private var downloadError: Error?

    init(maximum: Int, progress: (@MainActor @Sendable (Int64, Int64) -> Void)?) {
        self.maximum = Int64(maximum)
        self.progress = progress
    }

    func urlSession(_ session: URLSession, downloadTask: URLSessionDownloadTask,
                    didFinishDownloadingTo location: URL) {
        let destination = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        do {
            try FileManager.default.moveItem(at: location, to: destination)
            downloaded = destination
        } catch { downloadError = error }
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        if let error = error ?? downloadError {
            if let downloaded { try? FileManager.default.removeItem(at: downloaded) }
            completion?.resume(throwing: error)
        } else if let downloaded, let response = task.response {
            completion?.resume(returning: (downloaded, response))
        } else { completion?.resume(throwing: URLError(.badServerResponse)) }
        completion = nil
    }

    func urlSession(_ session: URLSession, downloadTask: URLSessionDownloadTask,
                    didWriteData bytesWritten: Int64, totalBytesWritten: Int64,
                    totalBytesExpectedToWrite: Int64) {
        guard totalBytesWritten <= maximum, totalBytesExpectedToWrite <= maximum else {
            downloadTask.cancel()
            return
        }
        guard Date().timeIntervalSince(lastUpdate) >= 0.15 || totalBytesWritten == totalBytesExpectedToWrite else { return }
        lastUpdate = Date()
        let callback = progress
        Task { @MainActor in callback?(totalBytesWritten, max(0, totalBytesExpectedToWrite)) }
    }
}

private func downloadHTTPS(_ url: URL, maxBytes: Int,
                           progress: (@MainActor @Sendable (Int64, Int64) -> Void)? = nil) async throws -> URL {
    guard url.scheme?.lowercased() == "https", maxBytes > 0 else { throw URLError(.badURL) }
    var request = URLRequest(url: url, timeoutInterval: 120)
    request.setValue("shixpeer-ward", forHTTPHeaderField: "User-Agent")
    let configuration = URLSessionConfiguration.ephemeral
    configuration.timeoutIntervalForRequest = 60
    configuration.timeoutIntervalForResource = 900
    configuration.waitsForConnectivity = false
    let delegate = ArchiveDownloadProgress(maximum: maxBytes, progress: progress)
    let session = URLSession(configuration: configuration, delegate: delegate, delegateQueue: nil)
    defer { session.finishTasksAndInvalidate() }
    let (temp, response) = try await withCheckedThrowingContinuation { continuation in
        delegate.completion = continuation
        session.downloadTask(with: request).resume()
    }
    guard let http = response as? HTTPURLResponse,
          (200..<300).contains(http.statusCode),
          response.url?.scheme?.lowercased() == "https" else {
        try? FileManager.default.removeItem(at: temp)
        throw URLError(.badServerResponse)
    }
    let size = (try? FileManager.default.attributesOfItem(atPath: temp.path)[.size] as? NSNumber)?.intValue ?? 0
    guard size > 0, size <= maxBytes else {
        try? FileManager.default.removeItem(at: temp)
        throw WardError("The update archive is larger than Ward will install.")
    }
    let suffix = archiveSuffix(url.lastPathComponent.lowercased()) ?? ".zip"
    let dest = FileManager.default.temporaryDirectory.appendingPathComponent("shixpeer-ward-\(UUID().uuidString)" + suffix)
    try FileManager.default.moveItem(at: temp, to: dest)
    return dest
}

private func unpackArchive(_ file: URL, to root: URL, maxUnpacked: Int64) throws {
    let name = file.lastPathComponent.lowercased()
    if name.hasSuffix(".dmg") {
        try unpackDMG(file, to: root, maxUnpacked: maxUnpacked)
        return
    }
    if name.hasSuffix(".zip") {
        try runTool("/usr/bin/ditto", ["-x", "-k", file.path, root.path])
    } else if archiveSuffix(name) != nil {
        try runTool("/usr/bin/tar", ["-xf", file.path, "-C", root.path])
    } else {
        throw WardError("Ward does not install this archive type.")
    }
    try rejectArchiveLayout(root, maxUnpacked: maxUnpacked)
}

private func unpackDMG(_ file: URL, to root: URL, maxUnpacked: Int64) throws {
    let mount = try mountDMG(file)
    defer { detachDMG(mount) }
    let entries = try FileManager.default.contentsOfDirectory(at: mount, includingPropertiesForKeys: [.isSymbolicLinkKey])
    let apps = entries.filter { $0.pathExtension == "app" }
    guard apps.count == 1, let app = apps.first,
          try app.resourceValues(forKeys: [.isSymbolicLinkKey]).isSymbolicLink != true else {
        throw WardError("The disk image must contain one application bundle.")
    }
    try rejectArchiveLayout(app, maxUnpacked: maxUnpacked)
    try runTool("/usr/bin/ditto", [app.path, root.appendingPathComponent(app.lastPathComponent).path])
    try rejectArchiveLayout(root, maxUnpacked: maxUnpacked)
}

private func mountDMG(_ file: URL) throws -> URL {
    let output = try toolResult("/usr/bin/hdiutil", ["attach", "-nobrowse", "-readonly", "-plist", file.path]).stdout
    guard let data = output.data(using: .utf8),
          let plist = try PropertyListSerialization.propertyList(from: data, options: [], format: nil) as? [String: Any],
          let entities = plist["system-entities"] as? [[String: Any]] else {
        throw WardError("The disk image could not be opened.")
    }
    for entity in entities {
        if let point = entity["mount-point"] as? String, !point.isEmpty {
            return URL(fileURLWithPath: point, isDirectory: true)
        }
    }
    throw WardError("The disk image did not mount.")
}

private func detachDMG(_ mount: URL) {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/usr/bin/hdiutil")
    process.arguments = ["detach", mount.path]
    process.standardOutput = Pipe()
    process.standardError = Pipe()
    try? process.run()
    process.waitUntilExit()
}

private func runTool(_ path: String, _ arguments: [String]) throws {
    _ = try toolResult(path, arguments)
}

private func toolResult(_ path: String, _ arguments: [String]) throws -> (stdout: String, stderr: String) {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: path)
    process.arguments = arguments
    let output = Pipe()
    let errors = Pipe()
    process.standardOutput = output
    process.standardError = errors
    process.standardInput = FileHandle.nullDevice
    try process.run()
    let stdout = String(decoding: output.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
    let stderr = String(decoding: errors.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
    process.waitUntilExit()
    guard process.terminationStatus == 0 else {
        throw WardError(URL(fileURLWithPath: path).lastPathComponent + " failed. " + String((stderr.isEmpty ? stdout : stderr).prefix(300)))
    }
    return (stdout, stderr)
}

private func rejectArchiveLayout(_ root: URL, maxUnpacked: Int64) throws {
    let rootPath = root.standardizedFileURL.path
    let prefix = rootPath.hasSuffix("/") ? rootPath : rootPath + "/"
    guard let enumerator = FileManager.default.enumerator(at: root, includingPropertiesForKeys: [.fileSizeKey, .isSymbolicLinkKey]) else {
        throw WardError("The unpacked update could not be read.")
    }
    var total: Int64 = 0
    for case let url as URL in enumerator {
        let resolved = url.resolvingSymlinksInPath().standardizedFileURL.path
        guard resolved == rootPath || resolved.hasPrefix(prefix) else {
            throw WardError("The archive layout is not safe to install.")
        }
        total += Int64((try? url.resourceValues(forKeys: [.fileSizeKey]).fileSize) ?? 0)
        if total > maxUnpacked { throw WardError("The unpacked update is larger than Ward will install.") }
    }
}

private func signingTeam(_ app: URL) -> String? {
    guard let result = try? toolResult("/usr/bin/codesign", ["-d", "--verbose=2", app.path]) else { return nil }
    let output = result.stdout + "\n" + result.stderr
    for raw in output.split(separator: "\n") {
        let line = raw.trimmingCharacters(in: .whitespaces)
        guard line.hasPrefix("TeamIdentifier=") else { continue }
        let team = String(line.dropFirst("TeamIdentifier=".count)).trimmingCharacters(in: .whitespaces)
        if team.isEmpty || team == "not set" { return nil }
        return team
    }
    return nil
}

private func sparkleApp(in root: URL, bundleID: String, version: String) throws -> URL {
    guard let enumerator = FileManager.default.enumerator(at: root, includingPropertiesForKeys: [.isDirectoryKey]) else {
        throw WardError("The unpacked update could not be read.")
    }
    var matches: [URL] = []
    for case let url as URL in enumerator {
        guard url.pathExtension == "app" else { continue }
        enumerator.skipDescendants()
        let info = url.appendingPathComponent("Contents/Info.plist")
        guard let plist = NSDictionary(contentsOf: info),
              (plist["CFBundleIdentifier"] as? String) == bundleID else { continue }
        let short = plist["CFBundleShortVersionString"] as? String
        let build = plist["CFBundleVersion"] as? String
        guard short == version || build == version else { continue }
        matches.append(url)
    }
    guard matches.count == 1, let app = matches.first else {
        throw WardError("The archive does not contain one \(version) copy of this application.")
    }
    let rootPath = root.standardizedFileURL.path
    let prefix = rootPath.hasSuffix("/") ? rootPath : rootPath + "/"
    let resolved = app.resolvingSymlinksInPath().standardizedFileURL.path
    guard resolved == rootPath || resolved.hasPrefix(prefix) else {
        throw WardError("The archive layout is not safe to install.")
    }
    return app
}

private func sparkleVersions(_ xml: String) -> [String] {
    let fromItems = sparkleItemBodies(xml).compactMap(sparkleItemVersion)
    if !fromItems.isEmpty { return fromItems }
    let short = regexValues(xml, #"sparkle:shortVersionString\s*=\s*"([^"]+)""#)
    if !short.isEmpty { return short }
    return regexValues(xml, #"sparkle:version\s*=\s*"([^"]+)""#)
}

private func regexValues(_ text: String, _ pattern: String) -> [String] {
    guard let expression = try? NSRegularExpression(pattern: pattern) else { return [] }
    let range = NSRange(text.startIndex..., in: text)
    return expression.matches(in: text, range: range).prefix(40).compactMap { match in
        guard match.numberOfRanges > 1, let slice = Range(match.range(at: 1), in: text) else { return nil }
        let value = text[slice].trimmingCharacters(in: .whitespacesAndNewlines)
        return value.isEmpty ? nil : value
    }
}

private func newestComparable(_ versions: [String]) -> String? {
    let comparable = versions.filter { versionOrder($0, $0) != nil }
    if let first = comparable.first {
        return comparable.dropFirst().reduce(first) { versionOrder($0, $1) == .orderedAscending ? $1 : $0 }
    }
    return versions.first
}

private func versionOrder(_ lhs: String, _ rhs: String) -> ComparisonResult? {
    func parts(_ raw: String) -> [Int]? {
        var release = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        // Some Sparkle short versions append a parenthesized numeric build.
        if let suffix = release.range(of: #"\s*\([0-9]+\)$"#, options: .regularExpression) {
            release.removeSubrange(suffix)
        }
        let pieces = release.split(separator: ".", omittingEmptySubsequences: false)
        guard !pieces.isEmpty, pieces.count <= 8 else { return nil }
        var numbers: [Int] = []
        for piece in pieces {
            guard piece.count <= 9, piece.allSatisfy(\.isNumber), let number = Int(piece) else { return nil }
            numbers.append(number)
        }
        return numbers
    }
    guard var left = parts(lhs), var right = parts(rhs) else { return nil }
    let count = max(left.count, right.count)
    while left.count < count { left.append(0) }
    while right.count < count { right.append(0) }
    if left == right { return .orderedSame }
    return left.lexicographicallyPrecedes(right) ? .orderedAscending : .orderedDescending
}

private enum PackageFilter: String, CaseIterable, Identifiable {
    case all = "All"
    case findings = "Findings"
    case review = "Needs review"
    case unchecked = "Incomplete or not checked"
    var id: String { rawValue }

    func includes(_ result: String) -> Bool {
        switch self {
        case .all: return true
        case .findings: return result == "AFFECTED"
        case .review: return result == "REQUIRES_REVIEW"
        case .unchecked: return result == "INCOMPLETE" || result == "NOT_CHECKED"
        }
    }
}

private struct FixRequest: Identifiable {
    let id = UUID()
    let actions: [HomebrewAction]
}

private enum AppInstallKind {
    case sparkle
    case developerZip
    case vendorArchive
    case system(SystemSoftwareUpdate)
}

private struct AppInstallRequest: Identifiable {
    let id = UUID()
    let bundleID: String
    let name: String
    let fromVersion: String
    let toVersion: String
    let kind: AppInstallKind
    var systemUpdate: SystemSoftwareUpdate? {
        if case .system(let update) = kind { return update }
        return nil
    }
}

private enum AppUpdateLifecycle {
    static func isAlive(_ pid: pid_t) -> Bool {
        guard pid > 0 else { return false }
        return kill(pid, 0) == 0 || errno == EPERM
    }
    static func waitForExit(_ pids: [pid_t], timeout: Duration = .seconds(30),
                            isAlive: (pid_t) -> Bool = Self.isAlive) async throws -> Bool {
        let deadline = ContinuousClock.now + timeout
        while pids.contains(where: isAlive) {
            if ContinuousClock.now >= deadline { return false }
            try await Task.sleep(for: .milliseconds(100))
        }
        return true
    }
    static func matches(_ url: URL, bundleID: String, version: String) -> Bool {
        guard let data = try? Data(contentsOf: url.appendingPathComponent("Contents/Info.plist")),
              let plist = (try? PropertyListSerialization.propertyList(from: data, format: nil)) as? [String: Any] else { return false }
        return plist["CFBundleIdentifier"] as? String == bundleID && plist["CFBundleShortVersionString"] as? String == version
    }
    static func progress(stage: String, bytes: Int64, total: Int64) -> Double {
        if stage.hasPrefix("Downloading") { return 0.05 + (total > 0 ? Double(max(0, min(bytes, total))) / Double(total) * 0.60 : 0) }
        if stage.hasPrefix("Unpacking") { return 0.70 }
        if stage.hasPrefix("Verifying") { return 0.78 }
        if stage.hasPrefix("Asking") || stage.hasPrefix("Waiting") { return 0.82 }
        if stage.hasPrefix("Replacing") || stage.hasPrefix("Requesting administrator") { return 0.90 }
        if stage.hasPrefix("Installed") || stage == "Update installed" { return 0.95 }
        if stage.hasPrefix("Reopening") { return 0.97 }
        return 0.02
    }
    static func shortStage(_ stage: String) -> String {
        if stage.hasPrefix("Downloading") { return "Downloading…" }
        if stage.hasPrefix("Replacing") { return "Installing…" }
        if stage.hasPrefix("Installed") { return "Installed" }
        return stage
    }
}

/// SwiftUI's visibility preference still follows overlay scroller auto-hiding.
/// Reserve a visible scrollbar so the queue length remains discoverable.
private struct UpdateQueueScroller: NSViewRepresentable {
    func makeNSView(context: Context) -> NSView { NSView() }
    func updateNSView(_ view: NSView, context: Context) {
        DispatchQueue.main.async {
            guard let scroll = view.enclosingScrollView else { return }
            scroll.hasVerticalScroller = true
            scroll.autohidesScrollers = false
            scroll.scrollerStyle = .legacy
        }
    }
}

private struct DetailRequest: Identifiable {
    let id = UUID()
    let findings: [Report.Finding]
}

private struct HomebrewAction: Identifiable, Sendable {
    let executable: String
    let formula: String
    let olderCopy: Bool
    let version: String
    let alreadyChanged: Bool
    var id: String { executable + formula }
    var command: String {
        executable + (olderCopy ? " cleanup " : " upgrade --formula ") + formula
    }
    var checkCommand: String {
        executable + (olderCopy ? " cleanup -n " : " outdated --formula --verbose ") + formula
    }
}

private struct DeviceSectionBanner: View {
    let page: DevicePage
    let subtitle: String
    var status = ""
    var actionTitle = ""
    var actionDisabled = false
    var action: (() -> Void)?
    var secondaryTitle = ""
    var secondaryDisabled = false
    var secondaryAction: (() -> Void)?

    var body: some View {
        HStack(spacing: 20) {
            VStack(alignment: .leading, spacing: 8) {
                Text(page.title).font(.largeTitle.weight(.semibold))
                Text(subtitle)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                if !status.isEmpty {
                    Text(status).font(.caption).foregroundStyle(.secondary)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            if let secondaryAction {
                BannerAction(title: secondaryTitle, symbol: "arrow.down.circle", tint: page.tint, action: secondaryAction)
                    .disabled(secondaryDisabled)
            }
            if let action {
                BannerAction(title: actionTitle, symbol: page.symbol, tint: page.tint, action: action)
                    .disabled(actionDisabled)
            } else {
                Image(systemName: page.symbol)
                    .font(.system(size: 32, weight: .medium))
                    .foregroundStyle(page.tint.gradient)
                    .frame(width: 72, height: 72)
                    .background(page.tint.opacity(0.15), in: Circle())
                    .accessibilityHidden(true)
            }
        }
        .padding(28)
        .wardBanner(tint: page.tint)
    }
}

struct ReportView: View {
    @EnvironmentObject private var model: WardModel
    private enum BatchOutcome {
        case verified
        case noUpgrade(String)
        case open(String)
        case failed(String)

        var label: String {
            switch self {
            case .verified: return "Verified fixed"
            case .noUpgrade: return "No Homebrew upgrade available"
            case .open: return "Finding still open"
            case .failed: return "Could not verify"
            }
        }

        var tint: Color {
            switch self {
            case .verified: return .mint
            case .noUpgrade, .open: return .orange
            case .failed: return .red
            }
        }

        var detail: String? {
            switch self {
            case .verified: return nil
            case .noUpgrade(let detail), .open(let detail), .failed(let detail): return detail
            }
        }
    }

    @State private var batchLogExpanded = false
    @State private var batchRunning = false
    @State private var batchOutcomes: [BatchOutcome] = []
    @State private var fixMessage = ""
    @State private var fixNeedsOptions = false
    @State private var fixLog = ""
    @State private var confirmingUpgrade = false
    let device: Device
    let page: DevicePage
    let subtitle: String
    var focus: String?
    var onOpen: (DevicePage, String?) -> Void = { _, _ in }
    var onClearFocus: () -> Void = {}
    @State private var expandedApplications: Set<String> = []
    @State private var selectedAppFilter: AppFilter?
    private var appFilter: AppFilter { selectedAppFilter ?? (device.id == "local" ? .updates : .user) }
    @State private var extraApplications: [Report.Inventory.Application] = []
    @State private var appQuery = ""
    private var updateChecks: [String: AppUpdateRecord] {
        get { device.id == "local" ? model.appUpdateChecks : [:] }
        nonmutating set { model.appUpdateChecks = newValue }
    }
    private var checkingUpdates: Bool { model.checkingAppVersions }
    private var updateNote: String { model.applicationUpdateNote }
    private struct AppUpdateBatch: Identifiable {
        let id = UUID()
        let requests: [AppInstallRequest]
    }
    @State private var appUpdateBatch: AppUpdateBatch?
    @State private var updateAllResults: [String: String] = [:]
    @State private var stopUpdateAll = false
    @State private var updateAllFinished = false
    @State private var activeUpdateID: String?
    @State private var updateProgress: [String: Double] = [:]
    @State private var failedUpdateIDs = Set<String>()
    @State private var warningUpdateIDs = Set<String>()
    @State private var appInstall: AppInstallRequest?
    @State private var installLog = ""
    @State private var installStage = ""
    @State private var installBytes: Int64 = 0
    @State private var installTotal: Int64 = 0
    @State private var installMessage = ""
    private var installing: Bool { model.installingApplication }
    @State private var packageFilter: PackageFilter = .all
    @State private var packageSource: String?
    @State private var packageQuery = ""
    private var report: Report { device.report }
    private var components: [Report.Component] { report.components ?? [] }
    private var skipped: [Report.Component] { components.filter { ["NOT_CHECKED", "INCOMPLETE"].contains($0.result) } }
    private var reasons: [(key: String, value: Int)] {
        Dictionary(grouping: skipped) { $0.reason ?? "Reason unavailable" }
            .mapValues(\.count).sorted { ($1.value, $0.key) < ($0.value, $1.key) }
    }
    @State private var expanded: Set<[String]> = []
    @State private var reviewOpen: Set<String> = []
    @State private var reviewTab = ""
    @State private var reviewContainer = ""
    @State private var action: HomebrewAction?
    @State private var selectedFixes: Set<String> = []
    @State private var primedFixes = false
    @State private var fixRequest: FixRequest?
    @State private var detailRequest: DetailRequest?
    @State private var showReviewReasons = false
    private var affected: [(key: [String], items: [Report.Finding])] {
        let byComponent = Dictionary(grouping: report.findings.filter { $0.status == "affected" }) {
            [$0.component, $0.installed_version, $0.origin ?? ""]
        }
        return byComponent.map { key, items in
            (key: key, items: items.sorted { (rank($0.severity), $0.id) < (rank($1.severity), $1.id) })
        }.sorted {
            let a = $0.items[0], b = $1.items[0]
            return (rank(a.severity), a.component, a.origin ?? "", a.installed_version) <
                   (rank(b.severity), b.component, b.origin ?? "", b.installed_version)
        }
    }
    private var visibleAffected: [(key: [String], items: [Report.Finding])] {
        guard let focus, !focus.isEmpty else { return affected }
        return affected.filter { $0.items[0].component == focus }
    }
    private func rank(_ severity: String) -> Int {
        ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NEGLIGIBLE"].firstIndex(of: severity.uppercased()) ?? 5
    }
    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            if page == .applications && device.id == "local" {
                DeviceSectionBanner(page: page, subtitle: subtitle, status: updateNote,
                                    actionTitle: checkingUpdates ? "Checking…" : "Check updates",
                                    actionDisabled: checkingUpdates || installing || model.busy, action: { checkNewerVersions(showProgress: true) },
                                    secondaryTitle: "Update all",
                                    secondaryDisabled: availableInstallRequests.isEmpty || checkingUpdates || installing || model.busy,
                                    secondaryAction: presentAllAppUpdates)
                    .padding(.bottom, 8)
            } else if page == .findings && device.id == "local" && !fixableIDs.isEmpty {
                DeviceSectionBanner(page: page, subtitle: subtitle, actionTitle: "Fix",
                                    actionDisabled: selectedFixCount == 0 || model.busy, action: requestSelectedFixes)
                    .padding(.bottom, 8)
            } else {
                DeviceSectionBanner(page: page, subtitle: subtitle)
                    .padding(.bottom, 8)
            }
            if let focus, !focus.isEmpty, page == .findings || page == .review {
                HStack {
                    Label(focus, systemImage: "line.3.horizontal.decrease.circle")
                    Spacer()
                    Button("Show all", action: onClearFocus).wardGlassButton()
                }
                .padding(10)
                .wardGlass(radius: 14)
            }
            LazyVStack(alignment: .leading, spacing: 16) {
                switch page {
                case .findings:
                    if device.id == "local" { findingsToolbar }
                    let groups = Dictionary(grouping: visibleAffected) { containerScope($0.key[2]) }
                    ForEach(groups.keys.sorted(), id: \.self) { scope in
                        containerSection(scope) {
                            ForEach(groups[scope] ?? [], id: \.key) { entry in
                                findingCard(entry)
                            }
                        }
                    }
                    if visibleAffected.isEmpty {
                        Text(focus == nil
                             ? "No vulnerability matches in the checks that ran. Review unresolved findings and coverage separately."
                             : "No confirmed findings are saved for this name.")
                            .foregroundStyle(.secondary)
                            .textSelection(.enabled)
                    }
                case .review:
                    HStack(spacing: 16) {
                        metric("On this Mac", report.hostReviewCount, .purple)
                        metric("Docker", report.containerReviewCount, .purple)
                        metric("Saved in this report", report.findings.filter { $0.status == "review" }.count, .secondary)
                    }
                    let rows = report.findings.filter { $0.status == "review" }
                    if let focus, !focus.isEmpty, !rows.contains(where: { $0.component == focus }) {
                        Text("No review records for this name are saved in the report.").foregroundStyle(.secondary)
                    }
                    if let reasons = report.review_reasons, !reasons.isEmpty, focus == nil || focus?.isEmpty == true {
                        Button { showReviewReasons = true } label: {
                            HStack(spacing: 8) {
                                Label {
                                    Text("Why review was needed")
                                } icon: {
                                    Image(systemName: "questionmark.circle")
                                        .foregroundStyle(Color.purple)
                                }
                                Spacer()
                                Text("\(reasons.count.formatted()) reasons").foregroundStyle(.secondary)
                                Image(systemName: "chevron.right").font(.caption.weight(.bold)).foregroundStyle(.secondary)
                            }
                            .padding(.horizontal, 16)
                            .padding(.vertical, 14)
                            .wardGlass(radius: 14)
                        }
                        .buttonStyle(.plain).wardPointer()
                    }
                    reviewCatalog(rows.filter { focus == nil || focus?.isEmpty == true || $0.component == focus })
                case .ports:
                    if report.portProblems.isEmpty {
                        Text("No port warnings in the available checks.").foregroundStyle(.secondary)
                    }
                    ForEach(report.portProblems, id: \.key) { issue in
                        VStack(alignment: .leading, spacing: 6) {
                            Text(issue.key).font(.title3.monospacedDigit().bold())
                            ForEach(issue.details, id: \.self) { Text($0).foregroundStyle(.secondary) }
                        }
                        .padding(14)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .background(.orange.opacity(0.12), in: RoundedRectangle(cornerRadius: 14))
                    }
                case .applications:
                    applicationsPage
                case .packages:
                    packagesPage
                case .containers:
                    containersPage
                case .coverage:
                    if !reasons.isEmpty {
                        Text("Why components were skipped").font(.title3.bold())
                        ForEach(reasons, id: \.key) { reason in
                            HStack {
                                Text(reason.key)
                                Spacer()
                                Text(reason.value.formatted()).font(.headline.monospacedDigit())
                            }
                            .padding(12)
                            .wardGlass(radius: 14)
                        }
                    }
                    ForEach(Array(report.coverage.enumerated()), id: \.offset) { _, note in
                        VStack(alignment: .leading, spacing: 4) {
                            Text(note.source).font(.headline)
                            Text(note.code).font(.caption.weight(.semibold)).foregroundStyle(.teal)
                            Text(note.detail).foregroundStyle(.secondary)
                        }
                        .padding(14)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .wardGlass(radius: 16)
                    }
                }
            }
        }
        .sheet(item: $action) { remedy in
            VStack(alignment: .leading, spacing: 12) {
                Text((remedy.alreadyChanged ? "Recheck " : "Fix ") + remedy.formula).font(.title2.bold())
                if remedy.alreadyChanged {
                    Text("The version from the report is no longer installed. Check the current versions against the same advisories.")
                    HStack {
                        Button("Close") { action = nil }.wardGlassButton().disabled(model.busy)
                        Spacer()
                        Button("Recheck") { runFix(remedy) }.wardGlassButton(prominent: true).disabled(model.busy)
                    }
                } else {
                    Text(remedy.olderCopy
                         ? "Remove superseded Homebrew copies after checking that no service still uses them."
                         : "Ward checks the local Homebrew catalog first and upgrades only when a newer build is available.")
                    Text(remedy.command).font(.system(.callout, design: .monospaced)).textSelection(.enabled)
                    if remedy.olderCopy {
                        Text("Check first").font(.subheadline.bold())
                        Text(remedy.checkCommand).font(.system(.callout, design: .monospaced)).textSelection(.enabled)
                    }
                    HStack {
                        Button("Close") { action = nil }.wardGlassButton().disabled(model.busy)
                        Spacer()
                        Button(remedy.olderCopy ? "Copy Cleanup Command" : "Copy Upgrade Command") {
                            NSPasteboard.general.clearContents()
                            NSPasteboard.general.setString(remedy.command, forType: .string)
                        }.wardGlassButton().disabled(model.busy)
                        Button(remedy.olderCopy ? "Run Cleanup" : "Run Upgrade") { confirmingUpgrade = true }
                            .wardGlassButton(prominent: true).disabled(model.busy)
                    }
                }
                if model.busy { ProgressView(model.activity).controlSize(.small) }
                if !fixLog.isEmpty {
                    Text("Command output").font(.subheadline.bold())
                    ScrollView {
                        Text(fixLog).font(.system(.caption, design: .monospaced))
                            .textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading)
                            .padding(10)
                    }.frame(height: 160).wardGlass(radius: 12)
                }
                if !fixMessage.isEmpty { Text(fixMessage).foregroundStyle(.secondary).textSelection(.enabled) }
                if !fixMessage.isEmpty && fixNeedsOptions { homebrewFixOptions(remedy) }
            }.padding(24).frame(width: 560)
                .interactiveDismissDisabled(model.busy)
                .confirmationDialog((remedy.olderCopy ? "Remove old copy of " : "Upgrade ") + remedy.formula + "?",
                                    isPresented: $confirmingUpgrade) {
                    Button(remedy.olderCopy ? "Remove Old Copy" : "Upgrade",
                           role: remedy.olderCopy ? .destructive : nil) { runFix(remedy) }
                } message: {
                    Text(remedy.olderCopy
                         ? "Confirm that no services still use \(remedy.version). Ward runs cleanup only if Homebrew previews removing that version alone."
                         : "Ward checks the local Homebrew catalog before running an upgrade as your user. Dependencies can change. Ward then checks the result against the signed database.")
                }
        }
        .sheet(item: $fixRequest) { request in
            let total = request.actions.count
            let completed = batchOutcomes.count
            let finished = completed == total && !batchRunning
            VStack(alignment: .leading, spacing: 16) {
                VStack(alignment: .leading, spacing: 8) {
                    Label("Homebrew updates", systemImage: "shippingbox")
                        .font(.title2.weight(.semibold))
                    if batchRunning || finished {
                        Text("\(completed.formatted()) of \(total.formatted()) processed")
                            .font(.callout.monospacedDigit())
                            .foregroundStyle(.secondary)
                        ProgressView(value: Double(completed), total: Double(max(total, 1)))
                            .tint(.indigo)
                    } else {
                        Text("Ward checks for newer builds before upgrading and verifies the findings afterward.")
                            .font(.callout).foregroundStyle(.secondary)
                    }
                }
                .padding(18)
                .frame(maxWidth: .infinity, alignment: .leading)
                .wardBanner(tint: .indigo)

                ScrollView {
                    VStack(alignment: .leading, spacing: 10) {
                        ForEach(Array(request.actions.enumerated()), id: \.offset) { index, item in
                            let outcome = batchOutcomes.indices.contains(index) ? batchOutcomes[index] : nil
                            let active = batchRunning && index == completed
                            VStack(alignment: .leading, spacing: 8) {
                                HStack(alignment: .firstTextBaseline, spacing: 8) {
                                    Text(item.formula).font(.headline)
                                    Text(item.version).font(.caption.monospaced()).foregroundStyle(.secondary)
                                    Spacer()
                                    Text(outcome?.label ?? (active ? "Running…" : "Queued"))
                                        .font(.caption.weight(.semibold))
                                        .foregroundStyle(outcome?.tint ?? (active ? Color.indigo : Color.secondary))
                                }
                                HStack(spacing: 12) {
                                    Text(item.command)
                                        .font(.callout.monospaced())
                                        .textSelection(.enabled)
                                        .frame(maxWidth: .infinity, alignment: .leading)
                                    Button("Copy command", systemImage: "doc.on.doc") {
                                        NSPasteboard.general.clearContents()
                                        NSPasteboard.general.setString(item.command, forType: .string)
                                    }
                                    .wardGlassButton()
                                }
                                if let detail = outcome?.detail {
                                    Text(detail).font(.callout).foregroundStyle(.secondary).textSelection(.enabled)
                                }
                                if case .noUpgrade = outcome { homebrewFixOptions(item) }
                                if active && !model.activity.isEmpty {
                                    Text(model.activity).font(.caption).foregroundStyle(.secondary)
                                }
                            }
                            .padding(12)
                            .wardGlass(radius: 12)
                        }

                        if !fixLog.isEmpty {
                            VStack(alignment: .leading, spacing: 0) {
                                Button { batchLogExpanded.toggle() } label: {
                                    HStack {
                                        Label("Diagnostic log", systemImage: "terminal")
                                        Spacer()
                                        Image(systemName: batchLogExpanded ? "chevron.down" : "chevron.right")
                                            .accessibilityHidden(true)
                                    }
                                    .padding(12)
                                    .contentShape(Rectangle())
                                }
                                .buttonStyle(.plain).wardPointer()
                                .accessibilityHint(batchLogExpanded ? "Collapse log" : "Expand log")
                                if batchLogExpanded {
                                    Divider().padding(.horizontal, 12)
                                    Text(fixLog).font(.caption.monospaced())
                                        .textSelection(.enabled)
                                        .frame(maxWidth: .infinity, alignment: .leading)
                                        .padding(12)
                                }
                            }
                            .wardGlass(radius: 12)
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                }

                Divider()
                HStack(spacing: 10) {
                    if !fixLog.isEmpty {
                        Button("Copy log", systemImage: "doc.on.doc") {
                            NSPasteboard.general.clearContents()
                            NSPasteboard.general.setString(fixLog, forType: .string)
                        }
                        .wardGlassButton()
                    }
                    Spacer()
                    Button(finished ? "Done" : "Close") { fixRequest = nil }
                        .wardGlassButton(prominent: finished)
                        .keyboardShortcut(.cancelAction)
                        .disabled(batchRunning)
                    if !finished {
                        Button(batchRunning ? "Running…" : "Run updates") { runBatch(request.actions) }
                            .wardGlassButton(prominent: true)
                            .disabled(batchRunning || model.busy || request.actions.isEmpty)
                    }
                }
            }
            .padding(24)
            .frame(width: 660, height: 480)
            .interactiveDismissDisabled(batchRunning)
            .onAppear {
                batchOutcomes = []
                batchLogExpanded = false
            }
        }
        .sheet(item: $detailRequest) { request in
            let advisories = Dictionary(grouping: request.findings, by: \.id)
            let ordered = advisories.keys.sorted {
                let a = advisories[$0]?.first?.severity ?? ""
                let b = advisories[$1]?.first?.severity ?? ""
                return (rank(a), $0) < (rank(b), $1)
            }.compactMap { advisories[$0]?.first }
            ScrollView {
                VStack(alignment: .leading, spacing: 12) {
                    Text(request.findings.first?.component ?? "Vulnerability details").font(.title2.bold()).textSelection(.enabled)
                    Text(request.findings.first?.installed_version ?? "").font(.callout.monospaced()).foregroundStyle(.secondary).textSelection(.enabled)
                    ForEach(Array(ordered.enumerated()), id: \.offset) { _, item in
                        Divider()
                        advisoryDetails(item)
                    }
                    HStack {
                        Spacer()
                        Button("Close") { detailRequest = nil }.wardGlassButton().keyboardShortcut(.cancelAction)
                    }
                }
                .padding(24)
                .frame(maxWidth: .infinity, alignment: .leading)
                .textSelection(.enabled)
            }
            .frame(minWidth: 640, minHeight: 420)
        }
        .sheet(isPresented: $showReviewReasons) {
            let reasons = report.review_reasons ?? [:]
            ScrollView {
                VStack(alignment: .leading, spacing: 12) {
                    Text("Why review was needed").font(.title2.bold())
                    Text("Counts for the whole scan, including records that are not saved under the tabs.")
                        .font(.callout).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                    ForEach(reasons.keys.sorted { (-(reasons[$0] ?? 0), $0) < (-(reasons[$1] ?? 0), $1) }, id: \.self) { reason in
                        HStack(alignment: .firstTextBaseline) {
                            Text(reason).font(.callout).textSelection(.enabled)
                            Spacer()
                            Text((reasons[reason] ?? 0).formatted()).font(.headline.monospacedDigit())
                        }
                        .padding(12)
                        .wardGlass(radius: 14)
                    }
                    HStack {
                        Spacer()
                        Button("Close") { showReviewReasons = false }.wardGlassButton().keyboardShortcut(.cancelAction)
                    }
                }
                .padding(24)
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            .frame(minWidth: 640, minHeight: 420)
        }
    }
    private func homebrewFixOptions(_ remedy: HomebrewAction) -> some View {
        let guidance: String
        switch remedy.formula {
        case "ffmpeg": guidance = "For untrusted media, use an isolated environment while waiting for a patched build."
        case "sqlite": guidance = "Review the output of .recover from an untrusted database before feeding it into sqlite3."
        case "wget": guidance = "Use another maintained downloader for untrusted servers until a patched build is available."
        case "python@3.11": guidance = "Check compatibility before moving to a patched Python branch. For the XML issue, check the Expat version used by that build."
        default: guidance = "Check the advisories for a fixed release or a workaround."
        }
        let findings = report.findings.filter {
            $0.origin == "homebrew-formula" && $0.component == remedy.formula &&
                $0.installed_version == remedy.version && $0.status == "affected"
        }
        let links = findings.sorted { $0.id < $1.id }
        return VStack(alignment: .leading, spacing: 6) {
            Text(guidance).font(.callout).foregroundStyle(.secondary)
            ForEach(Array(Set(links.map(\.id))).sorted(), id: \.self) { id in
                if let url = links.first(where: { $0.id == id })?.references?.compactMap({ URL(string: $0) })
                    .first(where: { $0.scheme == "https" && $0.host != nil }) {
                    Link("Patch or advisory: " + id, destination: url).wardPointer()
                } else if id.range(of: "^CVE-[0-9]{4}-[0-9]+$", options: .regularExpression) != nil,
                          let url = URL(string: "https://www.cve.org/CVERecord?id=" + id) {
                    Link("Advisory: " + id, destination: url).wardPointer()
                }
            }
        }
    }

    private func runFix(_ remedy: HomebrewAction) {
        fixMessage = ""
        fixNeedsOptions = false
        fixLog = ""
        Task {
            do {
                try await model.upgrade(remedy, report: report) { line in
                    fixLog = String((fixLog + line + "\n").suffix(32_768))
                }
                fixMessage = "Verified fixed."
            } catch {
                fixNeedsOptions = (error as? FindingStaysOpen)?.noUpgradeAvailable == true
                fixMessage = error.localizedDescription
            }
        }
    }

    private func runBatch(_ actions: [HomebrewAction]) {
        guard !batchRunning, !model.busy, !actions.isEmpty else { return }
        fixLog = ""
        batchOutcomes = []
        batchRunning = true
        Task {
            defer { batchRunning = false }
            for remedy in actions {
                fixLog = String((fixLog + "\n— \(remedy.formula) \(remedy.version) —\n").suffix(32_768))
                do {
                    try await model.upgrade(remedy, report: report) { line in
                        fixLog = String((fixLog + line + "\n").suffix(32_768))
                    }
                    batchOutcomes.append(.verified)
                    fixLog = String((fixLog + "Verified fixed.\n").suffix(32_768))
                } catch let open as FindingStaysOpen {
                    batchOutcomes.append(open.noUpgradeAvailable ? .noUpgrade(open.localizedDescription) : .open(open.localizedDescription))
                    fixLog = String((fixLog + open.localizedDescription + "\n").suffix(32_768))
                } catch {
                    batchOutcomes.append(.failed(error.localizedDescription))
                    fixLog = String((fixLog + error.localizedDescription + "\n").suffix(32_768))
                }
            }
        }
    }

    private func fixID(_ key: [String]) -> String { key.joined(separator: "\u{1f}") }

    private var fixableIDs: [String] {
        visibleAffected.compactMap { entry in
            let first = entry.items[0]
            guard device.id == "local", !model.isVerified(first), homebrewAction(first) != nil else { return nil }
            return fixID(entry.key)
        }
    }

    private let findingRowInset: CGFloat = 10

    private var selectedFixCount: Int {
        selectedFixes.intersection(Set(fixableIDs)).count
    }

    private func requestSelectedFixes() {
        guard device.id == "local", !model.busy else { return }
        let actions = visibleAffected.compactMap { entry -> HomebrewAction? in
            guard selectedFixes.contains(fixID(entry.key)) else { return nil }
            let first = entry.items[0]
            guard !model.isVerified(first) else { return nil }
            return homebrewAction(first)
        }
        guard !actions.isEmpty else { return }
        fixMessage = ""
        fixLog = ""
        fixRequest = FixRequest(actions: actions)
    }

    private var findingsToolbar: some View {
        HStack(spacing: 12) {
            Toggle(isOn: Binding(
                get: { !fixableIDs.isEmpty && fixableIDs.allSatisfy { selectedFixes.contains($0) } },
                set: { on in
                    if on { selectedFixes.formUnion(fixableIDs) }
                    else { fixableIDs.forEach { selectedFixes.remove($0) } }
                }
            )) {
                Text("Select all")
            }
            .toggleStyle(.checkbox)
            .disabled(fixableIDs.isEmpty || model.busy)
            Text(fixableIDs.isEmpty ? "No Homebrew fix for these items" : "\(selectedFixCount) selected")
                .font(.callout).foregroundStyle(.secondary)
            Spacer()
        }
        .padding(.leading, findingRowInset)
        .onAppear {
            guard !primedFixes else { return }
            selectedFixes = Set(fixableIDs)
            primedFixes = true
        }
    }

    private func toggleExpanded(_ key: [String]) {
        if expanded.contains(key) { expanded.remove(key) } else { expanded.insert(key) }
    }

    private func findingCard(_ entry: (key: [String], items: [Report.Finding])) -> some View {
        let group = entry.items
        let first = group[0]
        let key = entry.key
        let verified = device.id == "local" && model.isVerified(first)
        let remedy = verified ? nil : homebrewAction(first)
        let tint = verified ? Color.green : severityColor(first.severity)
        let id = fixID(key)
        return VStack(alignment: .leading, spacing: 8) {
            HStack(alignment: .center, spacing: 10) {
                if remedy != nil {
                    Toggle("", isOn: Binding(
                        get: { selectedFixes.contains(id) },
                        set: { on in if on { selectedFixes.insert(id) } else { selectedFixes.remove(id) } }
                    ))
                    .toggleStyle(.checkbox)
                    .labelsHidden()
                    .disabled(model.busy)
                } else if device.id == "local" {
                    Color.clear.frame(width: 16, height: 16)
                }
                HStack(alignment: .center, spacing: 10) {
                    Image(systemName: expanded.contains(key) ? "chevron.down" : "chevron.right")
                        .frame(width: 16, height: 16)
                    VStack(alignment: .leading, spacing: 2) {
                        Text(first.component).font(.headline).textSelection(.enabled)
                        HStack(spacing: 8) {
                            Text(first.installed_version).font(.callout.monospaced()).foregroundStyle(.secondary).textSelection(.enabled)
                            Text(verified ? "VERIFIED" : first.severity.uppercased()).font(.caption.bold()).foregroundStyle(tint)
                            Text("\(group.count) advisories").font(.caption).foregroundStyle(.secondary).textSelection(.enabled)
                        }
                    }
                    Spacer(minLength: 8)
                    if device.id == "local" { statusBadge(remedy, verified: verified) }
                }
            }
            .frame(minHeight: 44)
            .padding(findingRowInset)
            .contentShape(Rectangle())
            .onTapGesture { toggleExpanded(key) }
            .wardPointer()
            if expanded.contains(key) {
                findingDetails(group)
                    .padding([.horizontal, .bottom], 10)
            }
        }
        .background(tint.opacity(0.13), in: RoundedRectangle(cornerRadius: 8))
        .overlay {
            RoundedRectangle(cornerRadius: 8)
                .strokeBorder(tint.opacity(0.46))
                .allowsHitTesting(false)
        }
    }

    private func statusBadge(_ remedy: HomebrewAction?, verified: Bool) -> some View {
        let title: String
        let color: Color
        if verified {
            title = "Verified"
            color = .green
        } else if let remedy, remedy.alreadyChanged {
            title = "Version changed"
            color = .orange
        } else if let remedy, remedy.olderCopy {
            title = "Old copy"
            color = .orange
        } else if remedy != nil {
            title = "Active"
            color = .green
        } else {
            title = "No Homebrew fix"
            color = .secondary
        }
        return Text(title).font(.caption.weight(.semibold)).foregroundStyle(color)
            .padding(.horizontal, 8).padding(.vertical, 4)
            .wardGlassCapsule(tint: color, opacity: 0.16)
    }

    private func installedPath(_ item: Report.Finding) -> String {
        if item.origin == "homebrew-formula" {
            for prefix in ["/opt/homebrew", "/usr/local"] {
                let keg = prefix + "/Cellar/" + item.component + "/" + item.installed_version
                if FileManager.default.fileExists(atPath: keg) { return keg }
                let linked = prefix + "/opt/" + item.component
                if FileManager.default.fileExists(atPath: linked) { return linked }
            }
        }
        if item.origin == "application-bundle",
           let app = report.inventory.applications.first(where: { $0.name == item.component && $0.version == item.installed_version }),
           !app.identifier.isEmpty,
           let url = NSWorkspace.shared.urlForApplication(withBundleIdentifier: app.identifier) {
            return url.path
        }
        return item.origin ?? "Host"
    }

    private func containerScope(_ origin: String) -> String {
        origin.hasPrefix("docker:") ? String(origin.dropFirst("docker:".count)) : ""
    }

    @ViewBuilder
    private func containerSection<Content: View>(_ name: String, @ViewBuilder content: () -> Content) -> some View {
        if name.isEmpty {
            content()
        } else {
            let shape = RoundedRectangle(cornerRadius: 20, style: .continuous)
            LazyVStack(alignment: .leading, spacing: 12) {
                containerHeading(name)
                Divider()
                content()
            }
            .padding(16)
            .background(alignment: .top) {
                LinearGradient(colors: [DevicePage.containers.tint.opacity(0.19), .clear],
                               startPoint: .top, endPoint: .bottom)
                    .frame(height: 160)
                    .allowsHitTesting(false)
            }
            .clipShape(shape)
            .wardGlass(radius: 20)
        }
    }

    private func containerHeading(_ name: String) -> some View {
        let container = report.inventory.containers?.first { $0.name == name }
        let tint = DevicePage.containers.tint
        return HStack(alignment: .top, spacing: 14) {
            Image(systemName: "shippingbox.fill")
                .font(.system(size: 19, weight: .medium))
                .foregroundStyle(tint)
                .frame(width: 44, height: 44)
                .background(tint.opacity(0.18), in: RoundedRectangle(cornerRadius: 12))
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 10) {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Docker container")
                        .font(.caption.weight(.semibold))
                        .foregroundStyle(.secondary)
                    Text(name).font(.title3.weight(.semibold)).textSelection(.enabled)
                }
                if let container {
                    ViewThatFits(in: .horizontal) {
                        HStack(alignment: .top, spacing: 24) {
                            containerMetadata(container)
                        }
                        .fixedSize(horizontal: true, vertical: false)
                        VStack(alignment: .leading, spacing: 8) {
                            containerMetadata(container)
                        }
                    }
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    @ViewBuilder
    private func containerMetadata(_ container: Report.Inventory.Container) -> some View {
        if let image = container.image, !image.isEmpty {
            containerMetadataField("Image", value: image)
        }
        containerMetadataField("Operating system", value: container.system)
    }

    private func containerMetadataField(_ title: String, value: String) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(title).font(.caption).foregroundStyle(.secondary)
            Text(value).font(.callout).textSelection(.enabled)
        }
    }

    private let packageSectionOrder = ["OS and kernel", "Debian packages (dpkg)", "Homebrew formulas", "Homebrew casks", "Global dependencies", "Unspecified source"]

    private var applicationsPage: some View {
        VStack(alignment: .leading, spacing: 16) {
            searchField("Search applications", text: $appQuery)
            filterChips(AppFilter.allCases.filter { device.id == "local" || $0 != .updates }, selection: Binding(get: { appFilter }, set: { selectedAppFilter = $0 })) { filter in
                switch filter {
                case .updates: return filter.rawValue + "  " + (listedApplications.count { updateChecks[$0.identifier]?.newer == true } + (device.id == "local" ? model.systemSoftwareUpdates.count : 0)).formatted()
                case .flagged: return filter.rawValue + "  " + listedApplications.count { !report.appFindings(for: $0).isEmpty }.formatted()
                default: return filter.rawValue
                }
            }
            if device.id == "local", appFilter == .updates || appFilter == .apple {
                if !model.systemUpdateCheckNote.isEmpty {
                    Label(model.systemUpdateCheckNote, systemImage: "exclamationmark.triangle").font(.callout).foregroundStyle(.orange)
                }
                ForEach(model.systemSoftwareUpdates.filter { appQuery.isEmpty || $0.title.localizedCaseInsensitiveContains(appQuery) }) { update in
                    HStack(spacing: 14) {
                        Image(systemName: "gearshape.arrow.triangle.2.circlepath").font(.title2).foregroundStyle(.blue)
                        VStack(alignment: .leading, spacing: 5) {
                            Text(update.title).font(.headline)
                            Text("Version " + update.version + " · macOS Software Update").font(.callout).foregroundStyle(.secondary)
                        }
                        Spacer()
                        if update.pendingRestart == true {
                            Label("Restart required", systemImage: "restart").font(.callout).foregroundStyle(.orange)
                        } else {
                            Button("Update") {
                                resetUpdateQueue()
                                appInstall = systemInstallRequest(update)
                            }.wardGlassButton(prominent: true).disabled(installing || checkingUpdates || model.busy)
                        }
                    }.padding(16).wardGlass(radius: 18)
                }
            }
            if filteredApplications.isEmpty && !(device.id == "local" && (appFilter == .updates || appFilter == .apple) && !model.systemSoftwareUpdates.isEmpty) {
                Text(listedApplications.isEmpty
                     ? "This report has no application bundles."
                     : (appFilter == .updates
                        ? "No newer versions in the last check."
                        : "No applications match this filter."))
                    .foregroundStyle(.secondary)
            }
            ForEach(filteredApplications, id: \.key) { app in
                applicationRow(app)
            }
        }
        .onAppear {
            guard device.id == "local" else { return }
            let known = Set(report.inventory.applications.map(\.identifier).filter { !$0.isEmpty })
            if extraApplications.isEmpty {
                extraApplications = outsideApplications(known: known)
            }
            refreshApplicationUpdatesIfNeeded()
        }
        .sheet(item: $appUpdateBatch) { batch in
            applicationUpdateSheet(batch.requests, batch: true)
        }
        .sheet(item: $appInstall) { request in
            applicationUpdateSheet([request], batch: false)
        }
    }

    private func applicationUpdateSheet(_ requests: [AppInstallRequest], batch: Bool) -> some View {
        let running = requests.contains { updateButtonTitle($0.bundleID) != "Update" }
        let canUpdate = !requests.isEmpty && requests.allSatisfy { request in
            if request.systemUpdate != nil { return true }
            guard let installed = NSWorkspace.shared.urlForApplication(withBundleIdentifier: request.bundleID) else { return false }
            return canReplaceInstalledApp(installed) || supportsAdminReplacement(installed)
        }
        return VStack(alignment: .leading, spacing: 12) {
            HStack(alignment: .top) {
                VStack(alignment: .leading, spacing: 5) {
                    Text(updateAllFinished ? "Updates finished" : "Install updates").font(.title3.bold())
                    Text(installing ? "Updating \(min(requests.count, updateAllResults.count + 1)) of \(requests.count)"
                         : updateAllFinished ? "\(requests.count - failedUpdateIDs.count - (stopUpdateAll ? requests.filter { updateAllResults[$0.bundleID] == nil }.count : 0)) updated" + (failedUpdateIDs.isEmpty ? "" : " · \(failedUpdateIDs.count) failed") + (warningUpdateIDs.isEmpty ? "" : " · \(warningUpdateIDs.count) need attention")
                         : requests.contains(where: { $0.systemUpdate?.requiresRestart == true }) ? "Restart required afterwards · no automatic restart."
                         : requests.contains(where: { $0.systemUpdate != nil }) ? "macOS may ask for administrator approval."
                         : running ? "Open apps will quit and reopen." : "Install verified updates.")
                        .font(.callout).foregroundStyle(.secondary).lineLimit(1)
                }
                Spacer()
                Text(requests.count.formatted() + (requests.count == 1 ? " update" : " updates"))
                    .font(.callout).foregroundStyle(.secondary)
            }.frame(height: 48, alignment: .top)
            ScrollView {
                LazyVStack(spacing: 0) {
                    ForEach(requests) { request in
                        applicationUpdateQueueRow(request)
                        if request.id != requests.last?.id { Divider().padding(.leading, 52) }
                    }
                }.padding(.trailing, 8)
                    .background(UpdateQueueScroller())
            }.scrollIndicators(.visible).frame(maxWidth: .infinity, maxHeight: .infinity)
            HStack {
                if updateAllFinished {
                    Spacer()
                    Button("Done") { appUpdateBatch = nil; appInstall = nil }
                        .wardGlassButton(prominent: true).tint(.green).keyboardShortcut(.defaultAction)
                } else if installing {
                    Text("\(updateAllResults.count) / \(requests.count)").font(.callout.monospacedDigit()).foregroundStyle(.secondary)
                    Spacer()
                    if requests.count > 1 {
                        Button(stopUpdateAll ? "Stopping…" : "Stop after this app") { stopUpdateAll = true }
                            .wardGlassButton().disabled(stopUpdateAll)
                    }
                } else {
                    Button("Close") { appUpdateBatch = nil; appInstall = nil }.wardGlassButton()
                    Spacer()
                    if !canUpdate { Text("Update in the app itself.").font(.callout).foregroundStyle(.orange) }
                    Button(batch ? (running ? "Quit, Update All & Reopen" : "Update all") : updateButtonTitle(requests.first?.bundleID ?? "")) {
                        runAllAppUpdates(requests)
                    }.wardGlassButton(prominent: true).disabled(!canUpdate)
                }
            }.frame(height: 32)
        }.padding(20).frame(width: 600, height: 144 + min(320, max(104, CGFloat(requests.count) * 104)))
            .background(LinearGradient(colors: [Color(red: 0.16, green: 0.10, blue: 0.28), Color(red: 0.07, green: 0.06, blue: 0.14)], startPoint: .topLeading, endPoint: .bottomTrailing))
            .interactiveDismissDisabled(installing)
            .onChange(of: installStage) { _, _ in captureUpdateProgress() }
            .onChange(of: installBytes) { _, _ in captureUpdateProgress() }
    }

    private func applicationUpdateQueueRow(_ request: AppInstallRequest) -> some View {
        let active = activeUpdateID == request.bundleID
        let failed = failedUpdateIDs.contains(request.bundleID)
        let warning = warningUpdateIDs.contains(request.bundleID)
        let completed = updateAllResults[request.bundleID] != nil
        let tint: Color = failed ? .red : warning ? .orange : completed ? .green : .accentColor
        let status = active ? AppUpdateLifecycle.shortStage(installStage) : updateAllResults[request.bundleID] ?? (installing ? "Waiting…" : updateAllFinished ? "Skipped" : "Ready")
        return HStack(alignment: .top, spacing: 12) {
            Group {
                if request.systemUpdate != nil { Image(systemName: "gearshape.arrow.triangle.2.circlepath").resizable().scaledToFit().foregroundStyle(.blue) }
                else { Image(nsImage: applicationIcon(request.bundleID)).resizable() }
            }.frame(width: 36, height: 36).padding(.top, 2)
            VStack(alignment: .leading, spacing: 6) {
                HStack(alignment: .firstTextBaseline) {
                    Text(request.name).font(.headline).lineLimit(1)
                    Spacer(minLength: 8)
                    Text(request.fromVersion.isEmpty ? request.toVersion : "\(request.fromVersion) → \(request.toVersion)")
                        .font(.callout.monospaced()).foregroundStyle(.secondary).lineLimit(1)
                }
                ProgressView(value: updateProgress[request.bundleID] ?? 0).tint(tint)
                    .progressViewStyle(.linear).frame(height: 6)
                    .animation(.easeInOut(duration: 0.2), value: updateProgress[request.bundleID] ?? 0)
                HStack(alignment: .top, spacing: 6) {
                    if completed { Image(systemName: failed ? "exclamationmark.circle" : warning ? "exclamationmark.triangle" : "checkmark.circle.fill").foregroundStyle(tint) }
                    Text(status).font(.callout).foregroundStyle(failed || warning ? tint : .secondary)
                        .lineLimit(2).frame(maxWidth: .infinity, alignment: .leading).help(status)
                    if active && installTotal > 0 {
                        Text("\(Int(Double(min(installBytes, installTotal)) / Double(installTotal) * 100))%")
                            .font(.caption.monospacedDigit()).foregroundStyle(.secondary)
                    }
                }.frame(height: 32, alignment: .top)
            }
        }.padding(.vertical, 12).frame(height: 104)
    }

    private func captureUpdateProgress() {
        guard let id = activeUpdateID, !id.hasPrefix("system-software:") else { return }
        updateProgress[id] = max(updateProgress[id] ?? 0, AppUpdateLifecycle.progress(stage: installStage, bytes: installBytes, total: installTotal))
    }

    private func resetUpdateQueue() {
        updateAllResults = [:]
        updateAllFinished = false
        activeUpdateID = nil
        updateProgress = [:]
        failedUpdateIDs = []
        warningUpdateIDs = []
        stopUpdateAll = false
        installLog = ""
        installMessage = ""
    }

    private var filteredApplications: [Report.Inventory.Application] {
        let query = appQuery.trimmingCharacters(in: .whitespacesAndNewlines)
        return listedApplications.filter { app in
            switch appFilter {
            case .user: if app.isApple { return false }
            case .apple: if !app.isApple { return false }
            case .updates: if updateChecks[app.identifier]?.newer != true { return false }
            case .flagged: if report.appFindings(for: app).isEmpty { return false }
            }
            guard !query.isEmpty else { return true }
            return app.name.localizedCaseInsensitiveContains(query) || app.identifier.localizedCaseInsensitiveContains(query)
        }.sorted { lhs, rhs in
            let left = updateRank(lhs)
            let right = updateRank(rhs)
            if left != right { return left < right }
            return lhs.name.localizedStandardCompare(rhs.name) == .orderedAscending
        }
    }

    private var listedApplications: [Report.Inventory.Application] {
        report.inventory.applications + extraApplications
    }

    private func updateRank(_ app: Report.Inventory.Application) -> Int {
        guard let record = updateChecks[app.identifier], record.newer else { return 2 }
        return record.canInstall ? 0 : 1
    }

    private func versionIsCurrent(_ record: AppUpdateRecord) -> Bool {
        guard !record.newer, !record.reported.isEmpty, record.text != "Checking…" else { return false }
        return versionOrder(record.installed, record.reported) != nil
    }

    private func cannotCheck(_ app: Report.Inventory.Application) -> Bool {
        if updateChecks[app.identifier] != nil { return false }
        switch appChannel(app) {
        case .sparkleUnlisted, .none, .missing: return true
        case .jetBrains, .appStore, .sparkle, .electron, .vscode, .plain, .productXML, .installerMetadata, .dockerDesktop, .system: return false
        }
    }

    private func applicationRow(_ app: Report.Inventory.Application) -> some View {
        let saved = report.appFindings(for: app)
        let affected = saved.filter { $0.status == "affected" }
        let review = saved.filter { $0.status == "review" }
        let record = updateChecks[app.identifier]
        let newer = record?.newer == true
        let current = record.map(versionIsCurrent) == true
        let unchecked = device.id == "local" && !newer && !current && cannotCheck(app)
        let currentGreen = Color(red: 0.40, green: 0.58, blue: 0.46)
        let tone: Color? = newer ? .orange : (current ? currentGreen : (unchecked ? .gray : nil))
        let shown = device.id == "local" ? liveVersion(app) : app.version
        let canInstall = device.id == "local" && record?.canInstall == true && record?.reported.isEmpty == false
        let versionIsBuild = app.versionKind == "build"
        let scanVersionDiffers = !app.version.isEmpty && shown != app.version
        let hasDetails = versionIsBuild || scanVersionDiffers || !saved.isEmpty
        let open = hasDetails && expandedApplications.contains(app.key)
        let header = HStack(spacing: 14) {
            Image(nsImage: applicationIcon(app.identifier))
                .resizable().frame(width: 48, height: 48)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 4) {
                Text(app.name).font(.headline).lineLimit(1)
                Text(app.identifier.isEmpty ? "Bundle identifier unavailable" : app.identifier)
                    .font(.caption).foregroundStyle(.secondary).lineLimit(1)
            }
            Spacer(minLength: 12)
            VStack(alignment: .trailing, spacing: 4) {
                if let tone, !current {
                    Text(newer ? "Update available" : "No check")
                        .font(.caption.weight(.semibold))
                        .foregroundStyle(tone)
                }
                Text(shown.isEmpty ? "Version unavailable" : shown)
                    .font(.callout.monospaced())
                if let record, !current {
                    Text(record.text).font(.caption).foregroundStyle(.secondary)
                        .multilineTextAlignment(.trailing)
                } else if unchecked {
                    Text(appChannel(app).label).font(.caption).foregroundStyle(.secondary)
                        .multilineTextAlignment(.trailing)
                }
                if !saved.isEmpty {
                    Text("\(saved.count.formatted()) records").font(.caption).foregroundStyle(.secondary)
                }
            }
            if hasDetails {
                Image(systemName: open ? "chevron.down" : "chevron.right")
                    .font(.caption.weight(.semibold)).foregroundStyle(.secondary)
                    .accessibilityHidden(true)
            }
        }
        .padding(16)
        .contentShape(Rectangle())
        return VStack(alignment: .leading, spacing: 0) {
            if hasDetails {
                Button {
                    if open { expandedApplications.remove(app.key) }
                    else { expandedApplications.insert(app.key) }
                } label: {
                    header
                }
                .buttonStyle(.plain).wardPointer()
                .accessibilityHint(open ? "Collapse app details" : "Expand app details")
            } else {
                header
            }
            if open {
                Divider().padding(.horizontal, 16)
                VStack(alignment: .leading, spacing: 10) {
                    if versionIsBuild {
                        Text("Version shown is a build number.").font(.caption).foregroundStyle(.secondary)
                    }
                    if scanVersionDiffers {
                        Text("Scan recorded \(app.version)").font(.caption).foregroundStyle(.secondary)
                    }
                    ForEach(Array((affected + review).enumerated()), id: \.offset) { _, item in
                        VStack(alignment: .leading, spacing: 4) {
                            Text(item.status == "review" ? "Needs review" : "Finding")
                                .font(.caption.weight(.semibold)).foregroundStyle(.secondary)
                            Text(item.reason).font(.caption).foregroundStyle(.secondary).textSelection(.enabled)
                            advisoryDetails(item)
                        }
                        .padding(10)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .wardGlass(radius: 10)
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(16)
            }
            if canInstall, let reported = record?.reported {
                Divider().padding(.horizontal, 16)
                HStack {
                    Label("Update through Ward", systemImage: "checkmark.shield")
                        .font(.caption).foregroundStyle(.secondary)
                    Spacer()
                    Button("Update") {
                        resetUpdateQueue()
                        appInstall = AppInstallRequest(bundleID: app.identifier, name: app.name,
                                                       fromVersion: shown, toVersion: reported,
                                                       kind: applicationInstallKind(app))
                    }
                    .wardGlassButton(prominent: true)
                    .disabled(installing || checkingUpdates || model.busy)
                }
                .padding(.horizontal, 16).padding(.vertical, 12)
            }
        }
        .wardGlass(radius: 18)
        .overlay {
            if let tone {
                RoundedRectangle(cornerRadius: 18, style: .continuous)
                    .strokeBorder(tone.opacity(newer ? 0.75 : (current ? 0.38 : 0.45)), lineWidth: 1.5)
                    .allowsHitTesting(false)
            }
        }
    }

    private func applicationIcon(_ identifier: String) -> NSImage {
        if !identifier.isEmpty, let url = NSWorkspace.shared.urlForApplication(withBundleIdentifier: identifier) {
            let icon = NSWorkspace.shared.icon(forFile: url.path)
            icon.size = NSSize(width: 64, height: 64)
            return icon
        }
        let fallback = NSImage(systemSymbolName: "app.dashed", accessibilityDescription: nil) ?? NSImage()
        fallback.size = NSSize(width: 64, height: 64)
        return fallback
    }

    private func refreshApplicationUpdatesIfNeeded() {
        guard !checkingUpdates, !installing else { return }
        let jobs = updateJobs(for: listedApplications)
        if let cache = AppUpdateStore.load(),
           Date().timeIntervalSince(cache.date) < AppUpdateStore.ttl,
           jobs.allSatisfy({ cache.results[$0.id]?.installed == $0.installed }) { return }
        checkNewerVersions()
    }

    private func checkNewerVersions(showProgress: Bool = false) {
        guard device.id == "local" else { return }
        let apps = listedApplications
        Task { await model.checkApplicationVersions(apps, showProgress: showProgress) }
    }

    private func updateButtonTitle(_ bundleID: String) -> String {
        let running = NSRunningApplication.runningApplications(withBundleIdentifier: bundleID).contains { !$0.isTerminated }
        return running ? "Quit, Update & Reopen" : "Update"
    }

    private func installationDownloadProgress(_ received: Int64, _ total: Int64) {
        guard installStage.hasPrefix("Downloading") else { return }
        installStage = "Downloading update…"
        installBytes = received
        installTotal = total
    }

    private func presentAllAppUpdates() {
        let requests = availableInstallRequests
        guard !requests.isEmpty else { return }
        resetUpdateQueue()
        appUpdateBatch = AppUpdateBatch(requests: requests)
    }

    private func applicationInstallKind(_ app: Report.Inventory.Application) -> AppInstallKind {
        switch appChannel(app) {
        case .vscode: return .developerZip
        case .jetBrains, .electron: return .vendorArchive
        default: return .sparkle
        }
    }

    private func systemInstallRequest(_ update: SystemSoftwareUpdate) -> AppInstallRequest {
        AppInstallRequest(bundleID: update.id, name: update.title, fromVersion: "", toVersion: update.version, kind: .system(update))
    }

    private var availableInstallRequests: [AppInstallRequest] {
        let applications: [AppInstallRequest] = listedApplications.compactMap { app in
            guard let record = updateChecks[app.identifier], record.newer, record.canInstall,
                  app.identifier != Bundle.main.bundleIdentifier,
                  let installed = NSWorkspace.shared.urlForApplication(withBundleIdentifier: app.identifier),
                  canReplaceInstalledApp(installed) || supportsAdminReplacement(installed) else { return nil }
            return AppInstallRequest(bundleID: app.identifier, name: app.name,
                                     fromVersion: liveVersion(app), toVersion: record.reported,
                                     kind: applicationInstallKind(app))
        }
        return applications + (device.id == "local" ? model.systemSoftwareUpdates.filter { $0.pendingRestart != true }.map(systemInstallRequest) : [])
    }

    private func performAppUpdate(_ request: AppInstallRequest) async throws {
        installStage = "Preparing " + request.name + "…"
        installBytes = 0
        installTotal = 0
        if let update = request.systemUpdate {
            installStage = "Waiting for macOS approval…"
            let (outcome, remaining) = try await SystemUpdateInstaller.install(update) { progress in
                installStage = progress.stage
                installBytes = Int64(progress.percent ?? 0)
                installTotal = progress.percent == nil ? 0 : 100
                updateProgress[request.bundleID] = max(updateProgress[request.bundleID] ?? 0, progress.fraction)
            }
            if outcome == .restartRequired { SystemSoftwareUpdate.rememberRestart(update) }
            model.systemSoftwareUpdates = SystemSoftwareUpdate.mergingRestartPending(remaining)
            model.systemUpdateCheckNote = ""
            if let data = try? JSONEncoder().encode(remaining) { UserDefaults.standard.set(data, forKey: "ward.system-software-updates.v1") }
            model.updateAppBadge(updateChecks, for: Set(listedApplications.map(\.identifier)))
            switch outcome {
            case .installed: installMessage = "Updated"
            case .restartRequired:
                warningUpdateIDs.insert(request.bundleID)
                installMessage = "Prepared · restart your Mac to finish"
            }
            installStage = "Update installed"
            installTotal = 0
            return
        }
        guard let installed = NSWorkspace.shared.urlForApplication(withBundleIdentifier: request.bundleID) else {
            throw WardError("Application no longer installed.")
        }
        let target = installed.resolvingSymlinksInPath()
        // Capture before download: an app can quit or update itself in the meantime.
        let originalProcesses = NSRunningApplication.runningApplications(withBundleIdentifier: request.bundleID).filter {
            $0.bundleURL?.resolvingSymlinksInPath() == target && AppUpdateLifecycle.isAlive($0.processIdentifier)
        }
        let originalPIDs = originalProcesses.map(\.processIdentifier)
        let originalTeam = await Task.detached { signingTeam(installed) }.value
        func verifyInstalled() async throws {
            try await Task.detached {
                guard AppUpdateLifecycle.matches(installed, bundleID: request.bundleID, version: request.toVersion) else {
                    throw WardError("The installed version could not be confirmed. Check updates again.")
                }
                if let originalTeam {
                    try verifyDeveloperUpdate(installed, bundleID: request.bundleID, team: originalTeam)
                } else {
                    try runTool("/usr/bin/codesign", ["--verify", "--strict", "--deep", installed.path])
                }
            }.value
        }
        var reopenURL: URL?
        do {
            switch request.kind {
            case .sparkle: reopenURL = try await installSparkleUpdate(request)
            case .developerZip: reopenURL = try await installDeveloperZip(request)
            case .vendorArchive: reopenURL = try await installVendorArchive(request)
            case .system: throw WardError("Unexpected system update request.")
            }
            try await verifyInstalled()
        } catch let installationError {
            // A native updater may finish during quit, or replacement may finish
            // before a later operation fails. Never infer success from exit status.
            guard originalTeam != nil else { throw installationError }
            do { try await verifyInstalled() } catch { throw installationError }
            reopenURL = originalPIDs.isEmpty ? nil : installed
        }
        var record = updateChecks[request.bundleID] ?? AppUpdateRecord(
            text: "", newer: false, canInstall: false, reported: request.toVersion, installed: request.toVersion)
        record.text = "Updated to \(request.toVersion)."
        record.newer = false
        record.canInstall = false
        record.reported = request.toVersion
        record.installed = request.toVersion
        updateChecks[request.bundleID] = record
        AppUpdateStore.save(updateChecks)
        model.updateAppBadge(updateChecks, for: Set(listedApplications.map(\.identifier)))
        installMessage = "Updated"
        installStage = "Update installed"
        installTotal = 0
        if reopenURL != nil || !originalPIDs.isEmpty {
            // Do not silently force-quit an app with unsaved work. Distinguish an
            // installed update from a restart that could not complete.
            guard try await AppUpdateLifecycle.waitForExit(originalPIDs, timeout: .seconds(2)) else {
                warningUpdateIDs.insert(request.bundleID)
                installMessage = "Updated · still open; quit and reopen to finish"
                return
            }
            // A native updater may have relaunched the new copy itself.
            let alreadyReopened = NSRunningApplication.runningApplications(withBundleIdentifier: request.bundleID).contains {
                $0.bundleURL?.resolvingSymlinksInPath() == target &&
                    !originalPIDs.contains($0.processIdentifier) && AppUpdateLifecycle.isAlive($0.processIdentifier)
            }
            if alreadyReopened {
                installMessage = "Updated · reopened"
                return
            }
            do {
                installStage = "Reopening " + request.name + "…"
                let configuration = NSWorkspace.OpenConfiguration()
                configuration.activates = false
                configuration.createsNewApplicationInstance = true
                let reopened = try await NSWorkspace.shared.openApplication(at: installed, configuration: configuration)
                guard AppUpdateLifecycle.isAlive(reopened.processIdentifier) else {
                    throw WardError("The application exited immediately.")
                }
                installMessage = "Updated · reopened"
            } catch {
                warningUpdateIDs.insert(request.bundleID)
                installMessage = "Updated · could not reopen; open the app manually"
                installLog += "Reopen failed: " + error.localizedDescription + "\n"
            }
        }
    }

    private func runAllAppUpdates(_ requests: [AppInstallRequest]) {
        guard !installing, !checkingUpdates, !model.busy else { return }
        model.installingApplication = true
        stopUpdateAll = false
        Task {
            defer {
                activeUpdateID = nil
                updateAllFinished = true
                model.installingApplication = false
            }
            for request in requests {
                if stopUpdateAll { break }
                guard updateAllResults[request.bundleID] == nil else { continue }
                activeUpdateID = request.bundleID
                updateProgress[request.bundleID] = 0.02
                installLog = ""
                do {
                    try await performAppUpdate(request)
                    updateAllResults[request.bundleID] = installMessage
                    updateProgress[request.bundleID] = 1
                } catch {
                    failedUpdateIDs.insert(request.bundleID)
                    updateAllResults[request.bundleID] = error.localizedDescription
                }
            }
        }
    }

    private func canReplaceInstalledApp(_ url: URL) -> Bool {
        let bundle = url.resolvingSymlinksInPath()
        let files = FileManager.default
        return files.isWritableFile(atPath: bundle.path) &&
            files.isWritableFile(atPath: bundle.deletingLastPathComponent().path)
    }

    private func supportsAdminReplacement(_ url: URL) -> Bool {
        url.pathExtension == "app" && url.deletingLastPathComponent().path == "/Applications" &&
            url.resolvingSymlinksInPath().path == url.path
    }

    private func replaceAppWithApproval(_ installed: URL, unpacked: URL, requirement: String,
                                        version: String) async throws {
        let script = #"""
            set -eu
            target=$1
            source=$2
            requirement=$3
            version=$4
            [ ! -L "$target" ] && [ -d "$target" ]
            /usr/bin/codesign --verify --strict -R="$requirement" "$target"
            stage=$(/usr/bin/mktemp -d '/Library/Application Support/.ward-update.XXXXXXXX')
            cleanup() {
                if [ -e "$stage/previous.app" ] && [ ! -e "$target" ] && [ ! -L "$target" ]; then
                    /bin/mv -h "$stage/previous.app" "$target" || return
                fi
                if [ -e "$stage/previous.app" ] && [ -e "$stage/update.app" ]; then
                    return
                fi
                /bin/rm -rf "$stage"
            }
            trap cleanup EXIT
            [ "$(/usr/bin/stat -f %d "$stage")" = "$(/usr/bin/stat -f %d /Applications)" ]
            /usr/bin/ditto "$source" "$stage/update.app"
            /usr/bin/codesign --verify --strict --deep -R="$requirement" "$stage/update.app"
            plist="$stage/update.app/Contents/Info.plist"
            short=$(/usr/libexec/PlistBuddy -c 'Print CFBundleShortVersionString' "$plist" 2>/dev/null || true)
            build=$(/usr/libexec/PlistBuddy -c 'Print CFBundleVersion' "$plist" 2>/dev/null || true)
            [ "$version" = "$short" ] || [ "$version" = "$build" ]
            /usr/bin/codesign --verify --strict -R="$requirement" "$target"
            /bin/mv -h "$target" "$stage/previous.app"
            /bin/mv -h "$stage/update.app" "$target"
            """#
        let appleScript = """
            on run argv
                set cmd to "/bin/sh -c " & quoted form of (item 1 of argv) & " ward-update"
                repeat with i from 2 to count of argv
                    set cmd to cmd & " " & quoted form of (item i of argv)
                end repeat
                do shell script cmd with administrator privileges
            end run
            """
        try await Task.detached {
            try runTool("/usr/bin/osascript", ["-e", appleScript, script, installed.path,
                                             unpacked.path, requirement, version])
        }.value
    }

    private func installSparkleUpdate(_ request: AppInstallRequest) async throws -> URL? {
        func log(_ line: String) {
            installStage = line
            installTotal = 0
            installLog = String((installLog + line + "\n").suffix(8_000))
        }
        guard request.bundleID != "com.shixpeer.ward" else { throw WardError("Ward does not replace itself.") }
        guard let installed = NSWorkspace.shared.urlForApplication(withBundleIdentifier: request.bundleID) else {
            throw WardError("The application is no longer on this Mac.")
        }
        guard canReplaceInstalledApp(installed) || supportsAdminReplacement(installed) else {
            throw WardError("Ward cannot replace this copy. Open \(request.name) to update it there.")
        }
        guard let plist = NSDictionary(contentsOf: installed.appendingPathComponent("Contents/Info.plist")) else {
            throw WardError("The application information could not be read.")
        }
        guard let feed = declaredSparkleFeed(installed, plist: plist) else {
            throw WardError("This application no longer has a Sparkle feed.")
        }
        guard let keyRaw = plist["SUPublicEDKey"] as? String, let publicKey = decodeBase64(keyRaw), publicKey.count == 32 else {
            throw WardError("This application has no Ed25519 update key.")
        }
        log("Reading the Sparkle feed declared by \(request.name).")
        let xml = String(decoding: try await fetchHTTPS(feed), as: UTF8.self)
        guard let newest = newestComparable(sparkleVersions(xml)), newest == request.toVersion else {
            throw WardError("The Sparkle feed changed. Check versions again before updating.")
        }
        guard let archive = sparkleInstallableArchive(xml, version: newest, feed: feed) else {
            throw WardError("The feed has no signed archive for \(newest).")
        }
        log("Downloading \(archive.url.lastPathComponent).")
        let zip = try await downloadHTTPS(archive.url, maxBytes: archive.length ?? AppUpdateStore.maxBytes, progress: { received, total in installationDownloadProgress(received, total) })
        defer { try? FileManager.default.removeItem(at: zip) }
        if let expected = archive.length {
            let size = (try FileManager.default.attributesOfItem(atPath: zip.path)[.size] as? NSNumber)?.intValue ?? 0
            guard size == expected else { throw WardError("The download size does not match the feed.") }
        }
        log("Checking the Ed25519 signature.")
        try await Task.detached {
            let bytes = try Data(contentsOf: zip, options: [.mappedIfSafe])
            let key = try Curve25519.Signing.PublicKey(rawRepresentation: publicKey)
            guard key.isValidSignature(archive.signature, for: bytes) else {
                throw WardError("The update signature does not match the key shipped in the app.")
            }
        }.value
        log("Unpacking the archive.")
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("shixpeer-ward-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { Task.detached { try? FileManager.default.removeItem(at: root) } }
        let unpacked = try await Task.detached {
            try unpackArchive(zip, to: root, maxUnpacked: AppUpdateStore.maxExpandedArchive)
            return try sparkleApp(in: root, bundleID: request.bundleID, version: newest)
        }.value
        return try await replaceUpdatedApp(request, installed: installed, unpacked: unpacked, log: log)
    }

    private func installDeveloperZip(_ request: AppInstallRequest) async throws -> URL? {
        func log(_ line: String) {
            installStage = line
            installTotal = 0
            installLog = String((installLog + line + "\n").suffix(8_000))
        }
        guard request.bundleID != "com.shixpeer.ward" else { throw WardError("Ward does not replace itself.") }
        guard let installed = NSWorkspace.shared.urlForApplication(withBundleIdentifier: request.bundleID) else {
            throw WardError("The application is no longer on this Mac.")
        }
        guard canReplaceInstalledApp(installed) || supportsAdminReplacement(installed) else {
            throw WardError("Ward cannot replace this copy. Open \(request.name) to update it there.")
        }
        guard let channel = vscodeChannel(installed),
              let check = vscodeCheckURL(base: channel.0, platform: channel.1, name: channel.2, quality: channel.3, installed: request.fromVersion) else {
            throw WardError("This application no longer has an update address.")
        }
        log("Reading the update address written in \(request.name).")
        let (data, status) = try await fetchHTTPSStatus(check)
        guard status == 200 else { throw WardError("The updater has nothing newer.") }
        struct Payload: Decodable { let url, name: String; let sha256hash: String? }
        let payload = try JSONDecoder().decode(Payload.self, from: data)
        guard payload.name == request.toVersion, let archive = httpsUpdateURL(payload.url), archive.path.lowercased().hasSuffix(".zip") else {
            throw WardError("The updater changed. Check versions again before updating.")
        }
        log("Downloading \(archive.lastPathComponent).")
        let zip = try await downloadHTTPS(archive, maxBytes: AppUpdateStore.maxDeveloperZip, progress: { received, total in installationDownloadProgress(received, total) })
        defer { try? FileManager.default.removeItem(at: zip) }
        if let checksum = payload.sha256hash {
            log("Verifying archive checksum…")
            try await Task.detached { try verifyArchiveChecksum(zip, sha256: checksum) }.value
        }
        log("Unpacking the archive.")
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("shixpeer-ward-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { Task.detached { try? FileManager.default.removeItem(at: root) } }
        let unpacked = try await Task.detached {
            try unpackArchive(zip, to: root, maxUnpacked: 2_000_000_000)
            let app = try sparkleApp(in: root, bundleID: request.bundleID, version: request.toVersion)
            guard let team = signingTeam(installed) else { throw WardError("The installed developer signature is unavailable.") }
            try verifyDeveloperUpdate(app, bundleID: request.bundleID, team: team)
            return app
        }.value
        return try await replaceUpdatedApp(request, installed: installed, unpacked: unpacked, log: log)
    }

    private func installVendorArchive(_ request: AppInstallRequest) async throws -> URL? {
        guard request.bundleID != Bundle.main.bundleIdentifier else {
            throw WardError("Ward cannot replace its running application.")
        }
        guard let installed = NSWorkspace.shared.urlForApplication(withBundleIdentifier: request.bundleID),
              let plist = NSDictionary(contentsOf: installed.appendingPathComponent("Contents/Info.plist")),
              plist["CFBundleShortVersionString"] as? String == request.fromVersion,
              let team = signingTeam(installed) else {
            throw WardError("The installed version or developer signature changed. Check updates again.")
        }
        let package: VendorPackage
        if let channel = jetBrainsChannel(installed, identifier: request.bundleID),
           case .jetBrains(let code, _) = channel {
            package = try await jetBrainsPackage(code)
        } else if let feed = electronFeed(installed) {
            package = try await electronPackage(feed)
        } else {
            throw WardError("The application no longer declares a supported package feed.")
        }
        guard package.version == request.toVersion, let url = package.url else {
            throw WardError("The package feed changed. Check updates again.")
        }
        func log(_ text: String) {
            installStage = text
            installTotal = 0
            installLog = String((installLog + text + "\n").suffix(8_000))
        }
        log("Downloading " + url.lastPathComponent)
        let file = try await downloadHTTPS(url, maxBytes: package.size ?? AppUpdateStore.maxVendorArchive, progress: { received, total in installationDownloadProgress(received, total) })
        defer { try? FileManager.default.removeItem(at: file) }
        if let size = package.size {
            guard (try file.resourceValues(forKeys: [.fileSizeKey]).fileSize) == size else {
                throw WardError("The archive size differs from its feed.")
            }
        }
        if package.checksumURL != nil || package.sha512 != nil {
            log("Verifying archive checksum…")
            let checksum256: String?
            if let checksumURL = package.checksumURL {
                checksum256 = String(decoding: try await fetchHTTPS(checksumURL), as: UTF8.self).split(whereSeparator: \.isWhitespace).first.map(String.init)
                guard checksum256 != nil else { throw WardError("Empty archive checksum metadata.") }
            } else { checksum256 = nil }
            try await Task.detached { try verifyArchiveChecksum(file, sha256: checksum256, sha512: package.sha512) }.value
        }
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("shixpeer-ward-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { Task.detached { try? FileManager.default.removeItem(at: root) } }
        log("Unpacking the application…")
        let unpacked = try await Task.detached {
            try unpackArchive(file, to: root, maxUnpacked: AppUpdateStore.maxExpandedArchive)
            return try sparkleApp(in: root, bundleID: request.bundleID, version: request.toVersion)
        }.value
        log("Verifying the developer signature…")
        try await Task.detached {
            try verifyDeveloperUpdate(unpacked, bundleID: request.bundleID, team: team)
        }.value
        return try await replaceUpdatedApp(request, installed: installed, unpacked: unpacked, log: log)
    }

    private func replaceUpdatedApp(_ request: AppInstallRequest, installed: URL, unpacked: URL,
                                   log: (String) -> Void) async throws -> URL? {
        guard canReplaceInstalledApp(installed) || supportsAdminReplacement(installed) else {
            throw WardError("Ward cannot replace this copy. Open \(request.name) to update it there.")
        }
        guard let plist = NSDictionary(contentsOf: installed.appendingPathComponent("Contents/Info.plist")),
              (plist["CFBundleShortVersionString"] as? String) == request.fromVersion else {
            throw WardError("The installed version changed. Check updates again.")
        }
        if let team = signingTeam(installed) {
            try await Task.detached {
                try verifyDeveloperUpdate(unpacked, bundleID: request.bundleID, team: team)
            }.value
        }
        let needsAdmin = !canReplaceInstalledApp(installed)
        let requirement: String?
        if needsAdmin {
            guard let team = signingTeam(installed), signingTeam(unpacked) == team,
                  team.range(of: "^[A-Z0-9]{10}$", options: .regularExpression) != nil,
                  request.bundleID.range(of: "^[A-Za-z0-9][A-Za-z0-9.-]*$", options: .regularExpression) != nil else {
                throw WardError("Administrator installation requires the same developer signature on both copies.")
            }
            let verifiedRequirement = "anchor apple generic and identifier \"\(request.bundleID)\" and certificate leaf[subject.OU] = \"\(team)\""
            try await Task.detached {
                try runTool("/usr/bin/codesign", ["--verify", "--strict", "--deep", "-R=" + verifiedRequirement, unpacked.path])
            }.value
            requirement = verifiedRequirement
        } else {
            requirement = nil
        }
        let target = installed.resolvingSymlinksInPath()
        func runningCopies() -> [NSRunningApplication] {
            NSRunningApplication.runningApplications(withBundleIdentifier: request.bundleID).filter {
                $0.bundleURL?.resolvingSymlinksInPath() == target && AppUpdateLifecycle.isAlive($0.processIdentifier)
            }
        }
        let running = runningCopies()
        if !running.isEmpty {
            log("Asking \(request.name) to quit.")
            for app in running where !app.isTerminated {
                guard app.terminate() || app.isTerminated else {
                    throw WardError("Could not ask \(request.name) to quit. Close it and try again.")
                }
            }
            guard try await AppUpdateLifecycle.waitForExit(running.map(\.processIdentifier)) else {
                throw WardError("Could not close \(request.name). Your work was left open.")
            }
        }
        guard runningCopies().isEmpty else {
            throw WardError("\(request.name) reopened before installation. Close it and try again.")
        }
        log("Replacing \(installed.path).")
        if let requirement {
            log("Requesting administrator approval from macOS.")
            try await replaceAppWithApproval(installed, unpacked: unpacked, requirement: requirement,
                                             version: request.toVersion)
        } else {
            _ = try await Task.detached {
                try FileManager.default.replaceItemAt(installed, withItemAt: unpacked,
                                                      backupItemName: nil, options: .usingNewMetadataOnly)
            }.value
        }
        log("Installed \(request.toVersion).")
        return running.isEmpty ? nil : installed
    }

    private var packagesPage: some View {
        let packages = components.filter { $0.origin != "application-bundle" && !$0.origin.hasPrefix("docker:") }
        let sources = Set(packages.map { packageSectionTitle($0.origin) })
        let orderedSources = packageSectionOrder.filter { sources.contains($0) }
            + sources.subtracting(packageSectionOrder).sorted()
        let query = packageQuery.trimmingCharacters(in: .whitespacesAndNewlines)
        let matches = packages.filter { item in
            packageFilter.includes(item.result) && (query.isEmpty ||
                item.name.localizedCaseInsensitiveContains(query) || item.version.localizedCaseInsensitiveContains(query))
        }
        let groups = Dictionary(grouping: matches) { packageSectionTitle($0.origin) }
        let visibleSources = orderedSources.filter { packageSource == nil || packageSource == $0 }
        let count = visibleSources.reduce(0) { $0 + (groups[$1]?.count ?? 0) }
        let findings = Dictionary(grouping: report.findings) {
            [$0.origin ?? "", $0.component, $0.installed_version]
        }
        return LazyVStack(alignment: .leading, spacing: 14) {
            searchField("Search by package name or version", text: $packageQuery)
            ViewThatFits(in: .horizontal) {
                HStack(spacing: 14) {
                    packageFilters(sources: orderedSources)
                    Spacer(minLength: 8)
                    Text("\(count.formatted()) of \(packages.count.formatted())").foregroundStyle(.secondary)
                }
                VStack(alignment: .leading, spacing: 8) {
                    packageFilters(sources: orderedSources)
                    Text("\(count.formatted()) of \(packages.count.formatted())").foregroundStyle(.secondary)
                }
            }
            .font(.callout)
            if count == 0 {
                Text(packages.isEmpty ? "This report has no packages." : "No packages match these filters.")
                    .foregroundStyle(.secondary)
            }
            ForEach(visibleSources, id: \.self) { title in
                if let rows = groups[title], !rows.isEmpty {
                    HStack {
                        Text(title).font(.title3.weight(.semibold))
                        Spacer()
                        Text(rows.count.formatted()).foregroundStyle(.secondary).monospacedDigit()
                    }
                    .padding(.top, 8)
                    ForEach(rows.sorted {
                        ($0.name.localizedLowercase, $0.version) < ($1.name.localizedLowercase, $1.version)
                    }, id: \.rowID) { item in
                        packageRow(item, matched: findings[[item.origin, item.name, item.version]] ?? [])
                    }
                }
            }
        }
    }

    @ViewBuilder
    private func packageFilters(sources: [String]) -> some View {
        Picker("Source", selection: $packageSource) {
            Text("All sources").tag(nil as String?)
            ForEach(sources, id: \.self) { Text($0).tag(Optional($0)) }
        }
        .fixedSize()
        .wardPointer()
        Picker("Result", selection: $packageFilter) {
            ForEach(PackageFilter.allCases) { Text($0 == .all ? "All results" : $0.rawValue).tag($0) }
        }
        .fixedSize()
        .wardPointer()
    }

    private func packageRow(_ item: Report.Component, matched: [Report.Finding]) -> some View {
        let affected = matched.filter { $0.status == "affected" }
        let first = affected.first
        let verified = first.map { device.id == "local" && model.isVerified($0) } ?? false
        let remedy = first.flatMap { verified ? nil : homebrewAction($0) }
        let key = [item.rowID]
        let open = expanded.contains(key)
        return VStack(alignment: .leading, spacing: 0) {
            Button { toggleExpanded(key) } label: {
                HStack(spacing: 12) {
                    Image(systemName: "shippingbox")
                        .foregroundStyle(Color.cyan)
                        .frame(width: 36, height: 36)
                        .background(Color.cyan.opacity(0.12), in: RoundedRectangle(cornerRadius: 9))
                        .accessibilityHidden(true)
                    VStack(alignment: .leading, spacing: 4) {
                        Text(item.name).font(.headline)
                        Text(item.version).font(.callout.monospaced()).foregroundStyle(.secondary)
                    }
                    Spacer(minLength: 8)
                    VStack(alignment: .trailing, spacing: 4) {
                        Text(verified ? "Verified fixed" : resultTitle(item.result))
                            .font(.callout.weight(.semibold))
                            .foregroundStyle(verified ? Color.green : (item.result == "AFFECTED" ? severityColor(first?.severity ?? "") : .secondary))
                        if !affected.isEmpty {
                            Text(affected.count == 1 ? "1 advisory" : "\(affected.count.formatted()) advisories")
                                .font(.caption).foregroundStyle(.secondary)
                        }
                    }
                    Image(systemName: open ? "chevron.down" : "chevron.right")
                        .font(.caption.weight(.semibold)).foregroundStyle(.secondary)
                        .accessibilityHidden(true)
                }
                .padding(16)
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain).wardPointer()
            .accessibilityHint(open ? "Collapse package details" : "Expand package details")
            if open {
                Divider().padding(.horizontal, 16)
                VStack(alignment: .leading, spacing: 10) {
                    LabeledContent("Source", value: managerTitle(item.origin))
                    if let upstream = report.inventory.packages.first(where: {
                        $0.manager == item.origin && $0.name == item.name && $0.version == item.version
                    })?.upstream_version, !upstream.isEmpty, upstream != item.version {
                        LabeledContent("Upstream version", value: upstream)
                    }
                    if let reason = item.reason, !reason.isEmpty {
                        Text(reason).foregroundStyle(.secondary).textSelection(.enabled)
                    }
                    if matched.contains(where: { $0.status == "review" }) {
                        Button("View review records") { onOpen(.review, item.name) }.wardGlassButton()
                    }
                    if let remedy {
                        Button(remedy.alreadyChanged ? "Recheck" : "Fix") {
                            fixMessage = ""
                            fixLog = ""
                            action = remedy
                        }.wardGlassButton()
                    }
                    if !affected.isEmpty {
                        findingDetails(affected.sorted { (rank($0.severity), $0.id) < (rank($1.severity), $1.id) })
                    }
                }
                .padding(16)
            }
        }
        .wardGlass(radius: 16)
    }

    private func managerTitle(_ origin: String) -> String {
        switch origin {
        case "homebrew-formula": return "Homebrew formula"
        case "homebrew-cask": return "Homebrew cask"
        case "global-dependency": return "Dependency"
        case "operating-system": return "Operating system"
        case "running-kernel": return "Running kernel"
        case "dpkg": return "Debian package"
        default: return origin.isEmpty ? "Package" : origin
        }
    }

    private func resultTitle(_ result: String) -> String {
        switch result {
        case "AFFECTED": return "Findings"
        case "REQUIRES_REVIEW": return "Needs review"
        case "NO_ADVISORY_FOUND": return "No advisory"
        case "NOT_CHECKED": return "Not checked"
        case "NO_MATCH_IN_AVAILABLE_RULES": return "No matching rules"
        case "INCOMPLETE": return "Incomplete"
        default: return result.replacingOccurrences(of: "_", with: " ").capitalized
        }
    }

    private func packageSectionTitle(_ origin: String) -> String {
        switch origin {
        case "operating-system", "running-kernel": return "OS and kernel"
        case "dpkg": return "Debian packages (dpkg)"
        case "homebrew-formula": return "Homebrew formulas"
        case "homebrew-cask": return "Homebrew casks"
        case "global-dependency": return "Global dependencies"
        default: return origin.isEmpty ? "Unspecified source" : origin
        }
    }

    private var containersPage: some View {
        let containers = report.inventory.containers ?? []
        return VStack(alignment: .leading, spacing: 12) {
            if containers.isEmpty {
                Text("No running containers in this report.").foregroundStyle(.secondary)
            } else {
                let images = Dictionary(grouping: containers, by: \.imageKey)
                ForEach(images.keys.sorted(), id: \.self) { key in
                    containerCard(key, images[key] ?? [])
                }
                Text("Package counts are checks of packages inside each container. The Docker total on Needs review counts advisory records and is larger.")
                    .font(.callout).foregroundStyle(.secondary)
            }
        }
    }

    private func containerCard(_ key: String, _ containers: [Report.Inventory.Container]) -> some View {
        let names = Set(containers.compactMap(\.image)).sorted()
        return VStack(alignment: .leading, spacing: 10) {
            Text(names.isEmpty ? "Unknown image" : names.joined(separator: " · ")).font(.title3.bold())
            if !key.hasPrefix("unknown:"), !names.contains(key) {
                Text(key).font(.caption.monospaced()).textSelection(.enabled).lineLimit(2)
            }
            ForEach(containers.sorted { $0.name < $1.name }, id: \.name) { container in
                let rows = components.filter { $0.origin == "docker:" + container.name }
                let review = rows.filter { $0.result == "REQUIRES_REVIEW" }.count
                let clean = rows.filter { $0.result == "NO_ADVISORY_FOUND" }.count
                VStack(alignment: .leading, spacing: 4) {
                    Text(container.name).font(.headline)
                    Text([container.system, container.architecture].compactMap { $0 }.joined(separator: " · "))
                        .foregroundStyle(.secondary)
                    Text("\(rows.count.formatted()) packages · \(review.formatted()) need review · \(clean.formatted()) with no advisory")
                        .font(.callout)
                    if let digest = container.digest, digest != key {
                        Text(digest).font(.caption.monospaced()).textSelection(.enabled).lineLimit(1)
                    }
                    if let started = container.started_at {
                        Text("Started " + started).font(.caption).foregroundStyle(.secondary)
                    }
                }
                .padding(10)
                .frame(maxWidth: .infinity, alignment: .leading)
                .wardGlass(radius: 14)
            }
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .wardGlass(radius: 20)
    }

    private func searchField(_ prompt: String, text: Binding<String>) -> some View {
        HStack(spacing: 8) {
            Image(systemName: "magnifyingglass").foregroundStyle(.secondary)
            TextField(prompt, text: text).textFieldStyle(.plain)
            if !text.wrappedValue.isEmpty {
                Button { text.wrappedValue = "" } label: {
                    Image(systemName: "xmark.circle.fill")
                }.buttonStyle(.plain).wardPointer().foregroundStyle(.secondary)
            }
        }
        .padding(10)
        .wardGlass(radius: 14)
    }

    private func filterChips<Option: Identifiable & Hashable>(_ options: [Option], selection: Binding<Option>, title: @escaping (Option) -> String) -> some View {
        HStack(spacing: 8) {
            ForEach(options) { option in
                let selected = selection.wrappedValue == option
                Button { selection.wrappedValue = option } label: {
                    Text(title(option))
                        .font(.caption.weight(.semibold))
                        .padding(.horizontal, 10)
                        .padding(.vertical, 6)
                        .foregroundStyle(selected ? Color.primary : Color.secondary)
                        .wardGlassCapsule(tint: selected ? Color.accentColor : nil, opacity: 0.22)
                        .contentShape(Capsule())
                }
                .buttonStyle(.plain).wardPointer()
            }
            Spacer(minLength: 0)
        }
    }

    private func reviewGroupKey(_ item: Report.Finding) -> String {
        (item.origin ?? "") + "\t" + item.component + "\t" + item.installed_version
    }

    private func reviewGroups(_ rows: [Report.Finding]) -> [(key: String, items: [Report.Finding])] {
        Dictionary(grouping: rows, by: reviewGroupKey).map { key, items in
            (key: key, items: items.sorted { $0.id < $1.id })
        }.sorted {
            ($0.items[0].component.localizedLowercase, $0.items[0].installed_version) <
                ($1.items[0].component.localizedLowercase, $1.items[0].installed_version)
        }
    }

    private func reviewCatalog(_ rows: [Report.Finding]) -> some View {
        let tabs = reviewTabs(rows)
        let selected = tabs.first { $0.id == reviewTab } ?? tabs.first
        let containers = Dictionary(grouping: selected?.id == "containers" ? (selected?.rows ?? []) : []) {
            containerScope($0.origin ?? "")
        }
        let containerNames = containers.keys.sorted()
        let container = containerNames.contains(reviewContainer) ? reviewContainer : containerNames.first
        return VStack(alignment: .leading, spacing: 20) {
            if tabs.count > 1 {
                ScrollView(.horizontal, showsIndicators: false) {
                    HStack(spacing: 10) {
                        ForEach(tabs, id: \.id) { tab in
                            reviewTabButton(tab.title, count: Set(tab.rows.map(reviewGroupKey)).count, on: tab.id == selected?.id) {
                                reviewTab = tab.id
                            }
                        }
                    }
                }
            }
            if selected?.id == "containers", let container {
                if containerNames.count > 1 {
                    ScrollView(.horizontal, showsIndicators: false) {
                        HStack(spacing: 10) {
                            ForEach(containerNames, id: \.self) { name in
                                reviewTabButton(name, count: Set((containers[name] ?? []).map(reviewGroupKey)).count, on: name == container) {
                                    reviewContainer = name
                                }
                            }
                        }
                    }
                }
                containerSection(container) {
                    reviewSection(nil, containers[container] ?? [])
                }
            } else if selected?.id == "homebrew" {
                let formulas = (selected?.rows ?? []).filter { ($0.origin ?? "") == "homebrew-formula" }
                let casks = (selected?.rows ?? []).filter { ($0.origin ?? "") == "homebrew-cask" }
                if !formulas.isEmpty && !casks.isEmpty {
                    reviewSection("Formulas", formulas)
                    reviewSection("Casks", casks)
                } else {
                    reviewSection(nil, selected?.rows ?? [])
                }
            } else if let selected {
                reviewSection(nil, selected.rows)
            }
        }
    }

    private func reviewTabs(_ rows: [Report.Finding]) -> [(id: String, title: String, rows: [Report.Finding])] {
        let host = rows.filter { !($0.origin ?? "").hasPrefix("docker:") }
        var tabs: [(id: String, title: String, rows: [Report.Finding])] = []
        let applications = host.filter { ($0.origin ?? "") == "application-bundle" }
        if !applications.isEmpty { tabs.append(("applications", "Applications", applications)) }
        let homebrew = host.filter { ["homebrew-formula", "homebrew-cask"].contains($0.origin ?? "") }
        if !homebrew.isEmpty { tabs.append(("homebrew", "Homebrew", homebrew)) }
        let dependencies = host.filter { ($0.origin ?? "") == "global-dependency" }
        if !dependencies.isEmpty { tabs.append(("dependencies", "Dependencies", dependencies)) }
        let system = host.filter { ["operating-system", "running-kernel"].contains($0.origin ?? "") }
        if !system.isEmpty { tabs.append(("system", "System", system)) }
        let used: Set<String> = ["application-bundle", "homebrew-formula", "homebrew-cask", "global-dependency", "operating-system", "running-kernel"]
        let other = host.filter { !used.contains($0.origin ?? "") }
        if !other.isEmpty { tabs.append(("other", "Other", other)) }
        let containers = rows.filter { ($0.origin ?? "").hasPrefix("docker:") }
        if !containers.isEmpty { tabs.append(("containers", "Containers", containers)) }
        return tabs
    }

    private func reviewTabButton(_ title: String, count: Int, on: Bool, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            HStack(spacing: 6) {
                Text(title)
                Text(count.formatted()).monospacedDigit().foregroundStyle(on ? Color.primary : Color.secondary)
            }
            .font(.caption.weight(.semibold))
            .padding(.horizontal, 10)
            .padding(.vertical, 6)
            .foregroundStyle(on ? Color.primary : Color.secondary)
            .wardGlassCapsule(tint: on ? Color.accentColor : nil, opacity: 0.22)
        }
        .buttonStyle(.plain).wardPointer()
    }

    @ViewBuilder
    private func reviewSection(_ title: String?, _ rows: [Report.Finding]) -> some View {
        let groups = reviewGroups(rows)
        if !groups.isEmpty {
            VStack(alignment: .leading, spacing: 12) {
                if let title {
                    HStack(alignment: .firstTextBaseline) {
                        Text(title).font(.title3.bold())
                        Spacer()
                        Text("\(groups.count.formatted()) · \(rows.count.formatted()) records")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                }
                ForEach(groups, id: \.key) { group in
                    reviewGroupCard(group.key, group.items)
                }
            }
        }
    }

    private func reviewApp(_ item: Report.Finding) -> Report.Inventory.Application? {
        let named = report.inventory.applications.filter { !$0.identifier.isEmpty && $0.name == item.component }
        if item.origin == "application-bundle" {
            return named.first { $0.version == item.installed_version } ?? named.first
        }
        return named.count == 1 ? named[0] : nil
    }

    private func reviewGroupCard(_ key: String, _ items: [Report.Finding]) -> some View {
        let first = items[0]
        let open = reviewOpen.contains(key)
        let reasons = Array(Set(items.map(\.reason))).sorted()
        let app = reviewApp(first)
        return VStack(alignment: .leading, spacing: 12) {
            HStack(alignment: .center, spacing: 12) {
                if let app {
                    Image(nsImage: applicationIcon(app.identifier))
                        .resizable()
                        .frame(width: 36, height: 36)
                        .accessibilityHidden(true)
                }
                VStack(alignment: .leading, spacing: 4) {
                    Text(first.component).font(.headline).textSelection(.enabled)
                    Text(first.installed_version.isEmpty ? "Version unavailable" : first.installed_version)
                        .font(.callout.monospaced()).foregroundStyle(.secondary).textSelection(.enabled)
                    Text(reasons.count == 1 ? reasons[0] : "\(reasons.count.formatted()) reasons")
                        .font(.caption).foregroundStyle(.secondary).lineLimit(2).textSelection(.enabled)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                Text(items.count.formatted()).font(.headline.monospacedDigit()).textSelection(.enabled)
                Image(systemName: open ? "chevron.down" : "chevron.right")
                    .frame(width: 16, height: 16)
            }
            .padding(16)
            .contentShape(Rectangle())
            .onTapGesture {
                if open { reviewOpen.remove(key) } else { reviewOpen.insert(key) }
            }
            .wardPointer()
            if open {
                VStack(alignment: .leading, spacing: 12) {
                    ForEach(Array(items.enumerated()), id: \.offset) { _, item in
                        VStack(alignment: .leading, spacing: 4) {
                            HStack {
                                Text(item.id).font(.callout.monospaced()).textSelection(.enabled)
                                Spacer()
                                Text(item.severity.uppercased()).font(.caption.bold())
                                    .foregroundStyle(severityColor(item.severity))
                            }
                            Text(item.reason).font(.caption).foregroundStyle(.secondary).textSelection(.enabled)
                            advisoryDetails(item, showID: false)
                        }
                        .padding(8)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .background(.quaternary.opacity(0.55), in: RoundedRectangle(cornerRadius: 8))
                    }
                }
                .padding([.horizontal, .bottom], 16)
            }
        }
        .wardGlass(radius: 16)
    }

    @ViewBuilder
    private func advisoryDetails(_ item: Report.Finding, showID: Bool = true) -> some View {
        let cve = ([item.id] + (item.aliases ?? [])).first {
            $0.range(of: "^CVE-[0-9]{4}-[0-9]{4,}$", options: .regularExpression) != nil
        }
        let references = Set(item.references ?? []).sorted().compactMap { URL(string: $0) }.filter {
            $0.scheme?.lowercased() == "https" && $0.host != nil && $0.user == nil && $0.password == nil
        }
        VStack(alignment: .leading, spacing: 4) {
            if showID {
                HStack {
                    Text(cve ?? item.id).font(.headline)
                    Text(item.severity.uppercased()).font(.caption.bold())
                        .foregroundStyle(severityColor(item.severity))
                }
            }
            Text(item.summary ?? "Description unavailable in this database revision.")
                .foregroundStyle(.secondary)
                .textSelection(.enabled)
            let evidence = [item.source, item.ecosystem, item.known_exploited == true ? "Known exploited" : nil,
                            item.epss.map { "EPSS " + $0.formatted(.percent.precision(.fractionLength(1))) }]
            Text(evidence.compactMap { $0 }.joined(separator: " · ")).font(.caption).foregroundStyle(.secondary)
            ForEach(references, id: \.self) { url in
                Link(url.absoluteString, destination: url).wardPointer().lineLimit(1).truncationMode(.middle)
            }
            if references.isEmpty, let cve, let url = URL(string: "https://www.cve.org/CVERecord?id=" + cve) {
                Link("Open CVE record", destination: url).wardPointer()
            }
        }.padding(.vertical, 4)
    }

    private func severityColor(_ severity: String) -> Color {
        switch severity.uppercased() {
        case "CRITICAL": return .pink
        case "HIGH": return .red
        case "MEDIUM": return .orange
        case "LOW": return .blue
        default: return .secondary
        }
    }

    private func findingDetails(_ group: [Report.Finding]) -> some View {
        let first = group[0]
        let fixed = Set(group.flatMap { $0.fixed_versions ?? [] }).sorted()
        let action = device.id == "local" && model.isVerified(first) ? nil : homebrewAction(first)
        return VStack(alignment: .leading, spacing: 6) {
            Text("Path").font(.caption.weight(.semibold)).foregroundStyle(.secondary)
            Text(installedPath(first)).font(.callout.monospaced()).textSelection(.enabled)
            Text(first.reason.contains("NVD CPE")
                 ? "Why flagged: the installed version falls within the affected range in the NVD advisory."
                 : "Why flagged: " + first.reason)
                .textSelection(.enabled)
            if !fixed.isEmpty { Text("Reported fixes: " + fixed.joined(separator: ", ")).textSelection(.enabled) }
            Text(vendorFixStatus(group)).textSelection(.enabled)
            if let action, action.alreadyChanged {
                Text("Next step: recheck the currently installed version.").textSelection(.enabled)
            } else if let action {
                Text(action.olderCopy
                     ? "Next step: check dependencies, then remove the older copy."
                     : "Next step: ask Homebrew to upgrade this formula. If it has no newer bottle, the finding stays open.")
                    .textSelection(.enabled)
                Text(action.command).font(.system(.callout, design: .monospaced))
                    .textSelection(.enabled)
                    .padding(8)
                    .wardGlass(radius: 10)
            } else if device.id == "local" && model.isVerified(first) {
                Text("Verified by a targeted scan against the signed database.").textSelection(.enabled)
            } else if let recommendation = first.recommendation {
                Text("Next step: " + recommendation).textSelection(.enabled)
            }
            HStack(spacing: 12) {
                Button("Vulnerability details") {
                    detailRequest = DetailRequest(findings: group)
                }
                .wardGlassButton()
                if let action {
                    Button("Fix it") {
                        fixMessage = ""
                        fixLog = ""
                        fixRequest = FixRequest(actions: [action])
                    }
                    .buttonStyle(.plain).wardPointer()
                    .font(.callout.weight(.semibold))
                    .foregroundStyle(Color.accentColor)
                }
            }
        }.font(.callout)
    }

    private func vendorFixStatus(_ group: [Report.Finding]) -> String {
        let recorded = group.filter { !($0.fixed_versions ?? []).isEmpty }
        let versions = Set(recorded.flatMap { $0.fixed_versions ?? [] }).sorted()
        let through = Set(group.compactMap { $0.evidence?.context?.cpe?.match?.versionEndIncluding }).sorted()
        let before = Set(group.compactMap { $0.evidence?.context?.cpe?.match?.versionEndExcluding }).sorted()
        var parts: [String] = []
        if recorded.isEmpty {
            parts.append("No vendor fix is recorded.")
        } else if recorded.count == group.count {
            parts.append("Vendor fix recorded: \(versions.joined(separator: ", ")).")
        } else {
            parts.append("A fix is recorded for \(recorded.count) of \(group.count): \(versions.joined(separator: ", ")).")
        }
        if !through.isEmpty {
            parts.append("NVD still includes versions through \(through.joined(separator: ", ")).")
        }
        if !before.isEmpty {
            parts.append("NVD ends other ranges before \(before.joined(separator: ", ")). That boundary is not a confirmed fix.")
        }
        return parts.joined(separator: " ")
    }

    private func homebrewAction(_ item: Report.Finding) -> HomebrewAction? {
        let safeName = "^[A-Za-z0-9][A-Za-z0-9@._+~-]*$"
        guard device.id == "local", item.origin == "homebrew-formula",
              item.component.range(of: safeName, options: .regularExpression) != nil,
              item.installed_version.range(of: safeName, options: .regularExpression) != nil else { return nil }
        let name = item.component
        let installs = ["/opt/homebrew", "/usr/local"].compactMap { prefix -> HomebrewAction? in
            let executable = prefix + "/bin/brew"
            let cellar = URL(fileURLWithPath: prefix + "/Cellar/" + name).resolvingSymlinksInPath()
            let active = URL(fileURLWithPath: prefix + "/opt/" + name).resolvingSymlinksInPath()
            guard FileManager.default.isExecutableFile(atPath: executable),
                  active.deletingLastPathComponent().path == cellar.path,
                  FileManager.default.fileExists(atPath: active.path)
            else { return nil }
            let installed = FileManager.default.fileExists(atPath: cellar.appendingPathComponent(item.installed_version).path)
            return HomebrewAction(executable: executable, formula: name,
                                  olderCopy: installed && active.lastPathComponent != item.installed_version,
                                  version: item.installed_version, alreadyChanged: !installed)
        }
        return installs.count == 1 ? installs.first : nil
    }

    private func metric(_ label: String, _ value: Int, _ color: Color) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(value.formatted()).font(.system(.title, design: .rounded).bold()).foregroundStyle(color)
            Text(label).foregroundStyle(.secondary)
        }.frame(maxWidth: .infinity, alignment: .leading).padding(16)
            .wardGlass(radius: 14)
    }
}

extension View {
    fileprivate func wardBanner(tint: Color) -> some View {
        let shape = RoundedRectangle(cornerRadius: 22, style: .continuous)
        return background {
            shape.fill(
                LinearGradient(colors: [tint.opacity(0.25), tint.opacity(0.10), Color.primary.opacity(0.045)],
                               startPoint: .topTrailing, endPoint: .bottomLeading)
            )
            .overlay { shape.strokeBorder(Color.primary.opacity(0.10)) }
        }
    }

    @ViewBuilder
    func wardGlass(tint: Color? = nil, radius: CGFloat = 16, strong: Bool = false, interactive: Bool = false) -> some View {
        let shape = RoundedRectangle(cornerRadius: radius, style: .continuous)
        self.background { wardGlassFill(tint: tint, shape: shape, strong: strong) }
    }

    @ViewBuilder
    func wardGlassCapsule(tint: Color? = nil, opacity: CGFloat = 0.28, clear: Bool = false, interactive: Bool = false) -> some View {
        self.background((tint ?? Color.primary).opacity(tint == nil ? 0.12 : opacity), in: Capsule())
    }

    @ViewBuilder
    func wardGlassButton(prominent: Bool = false) -> some View {
        if prominent {
            self.buttonStyle(.borderedProminent).wardPointer()
        } else {
            self.buttonStyle(.bordered).wardPointer()
        }
    }
}

@ViewBuilder
private func wardGlassFill(tint: Color?, shape: RoundedRectangle, strong: Bool) -> some View {
    if let tint {
        shape.fill(LinearGradient(colors: [tint.opacity(strong ? 0.72 : 0.55), Color(red: 0.12, green: 0.08, blue: 0.25)],
                                  startPoint: .bottomTrailing, endPoint: .topLeading))
            .overlay {
                shape.strokeBorder(strong ? Color.white.opacity(0.16) : tint.opacity(0.45))
            }
    } else {
        shape.fill(.quaternary)
            .overlay { shape.strokeBorder(Color.primary.opacity(0.10)) }
    }
}

private extension View {
    func wardPointer() -> some View {
        modifier(WardPointer())
    }
}

private struct WardPointer: ViewModifier {
    @Environment(\.isEnabled) private var isEnabled
    @State private var hovered = false

    func body(content: Content) -> some View {
        if #available(macOS 15, *) {
            content.pointerStyle(isEnabled ? .link : nil)
        } else {
            content
                .onHover { inside in
                    hovered = inside
                    updateCursor()
                }
                .onChange(of: isEnabled) { _, _ in
                    if hovered { updateCursor() }
                }
                .onDisappear {
                    if hovered {
                        hovered = false
                        updateCursor()
                    }
                }
        }
    }

    private func updateCursor() {
        if hovered && isEnabled {
            NSCursor.pointingHand.set()
        } else if NSCursor.current == NSCursor.pointingHand {
            NSCursor.arrow.set()
        }
    }
}

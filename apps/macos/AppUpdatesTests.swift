import Foundation
import zlib

@main struct AppUpdatesTests {
    static func deflate(_ data: Data) -> Data {
        var result = Data(count: Int(compressBound(uLong(data.count))))
        var count = uLongf(result.count)
        let status = result.withUnsafeMutableBytes { dest in
            data.withUnsafeBytes { source in
                compress(dest.bindMemory(to: Bytef.self).baseAddress!, &count, source.bindMemory(to: Bytef.self).baseAddress!, uLong(data.count))
            }
        }
        precondition(status == Z_OK); result.count = Int(count); return result
    }
    static func header(_ compressed: Int, _ expanded: Int) -> Data {
        var data = Data("xar!".utf8)
        func append(_ number: UInt64, _ size: Int) { for index in (0..<size).reversed() { data.append(UInt8(truncatingIfNeeded: number >> (index * 8))) } }
        append(28,2); append(1,2); append(UInt64(compressed),8); append(UInt64(expanded),8); append(0,4)
        return data
    }
    @MainActor static func main() async throws {
        let launch = LaunchChecks()
        var order: [LaunchChecks.Step] = []
        await launch.run(enabled: false, ready: { true }, perform: { order.append($0) })
        precondition(!launch.started && order.isEmpty)
        await launch.run(enabled: true, ready: { true }, perform: { step in order.append(step); await Task.yield() })
        precondition(order == [.database, .scan, .applications])
        await launch.run(enabled: true, ready: { true }, perform: { order.append($0) })
        precondition(order.count == 3, "Reopening a window must not repeat launch checks")
        let cancelledLaunch = LaunchChecks()
        await cancelledLaunch.run(enabled: true, ready: { false }, perform: { _ in fatalError("Started while not ready") })
        print("PASS: launch check order, disabled startup, once-only scheduling and readiness gating")
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let systemOutput = """
        Software Update Tool
        Finding available software
        Software Update found the following new or updated software:
        * Label: FixtureTools-2.0
            Title: Fixture Tools, Version: 2.0, Size: 123KiB, Recommended: YES,
        * Label: OS-27.1
            Title: macOS Fixture, Version: 27.1, Size: 456KiB, Recommended: YES, Action: restart,
        """
        let system = try SystemSoftwareUpdate.parse(systemOutput)
        precondition(system.count == 2 && system[0].title == "Fixture Tools" && system[0].version == "2.0")
        precondition(system[1].id == "system-software:OS-27.1")
        let noSystemUpdates = try SystemSoftwareUpdate.parse("No new software available.")
        precondition(noSystemUpdates.isEmpty)
        do { _ = try SystemSoftwareUpdate.parse("Finding available software"); fatalError("Incomplete response accepted") } catch {}
        do { _ = try SystemSoftwareUpdate.parse("* Label: Fixture-2\nTitle: Fixture, Version: , Size: 1KiB"); fatalError("Missing version accepted") } catch {}
        let systemRecord = AppUpdateRecord(text: "Available", newer: true, canInstall: false, reported: "2.0", installed: "")
        precondition(AppUpdateAlerts.pending([system[0].id: systemRecord], notified: [:]).count == 1)
        precondition(AppUpdateAlerts.pending([system[0].id: systemRecord], notified: [system[0].id: "2.0"]).isEmpty)
        print("PASS: native system update parsing, incomplete-response rejection and alert deduplication")
        precondition(system[1].requiresRestart && !system[0].requiresRestart)
        let oldSystemCache = try JSONDecoder().decode(SystemSoftwareUpdate.self, from: Data(#"{"label":"Fixture-1","title":"Fixture","version":"1"}"#.utf8))
        precondition(!oldSystemCache.requiresRestart && oldSystemCache.pendingRestart == nil)
        let downloading = SystemInstallProgress.latest("Downloading: 12.5%\rDownloading: 55.0%")!
        precondition(downloading.stage == "Downloading update…" && downloading.percent == 55)
        let installing = SystemInstallProgress.latest("Downloaded Fixture\nInstalling: 23.5%")!
        precondition(installing.stage == "Installing update…" && installing.percent == 23.5)
        precondition(installing.fraction > downloading.fraction)
        precondition(SystemInstallProgress.latest("Installing: 999%")?.percent == 100)
        precondition(SystemInstallProgress.latest("no progress here") == nil)
        try SystemUpdateInstaller.validate("Fixture Tools-2.0")
        for label in ["", "--all", "Fixture\n--restart", String(repeating: "x", count: 513)] {
            do { try SystemUpdateInstaller.validate(label); fatalError("Invalid label accepted") } catch {}
        }
        let installedSystem = try SystemUpdateInstaller.verify(system[0], exitCode: 0, output: "Done with Fixture Tools\nDone.", remaining: [])
        precondition(installedSystem == .installed)
        let preparedSystem = try SystemUpdateInstaller.verify(system[1], exitCode: 0, output: "Done with macOS Fixture. You must restart your computer.", remaining: [])
        precondition(preparedSystem == .restartRequired)
        do { _ = try SystemUpdateInstaller.verify(system[0], exitCode: 1, output: "Done with Fixture", remaining: []); fatalError("Failed exit accepted") } catch {}
        do { _ = try SystemUpdateInstaller.verify(system[0], exitCode: 0, output: "No updates are available.", remaining: []); fatalError("No-op accepted as installed") } catch {}
        do { _ = try SystemUpdateInstaller.verify(system[0], exitCode: 0, output: "Done with Fixture Tools", remaining: [system[0]]); fatalError("Still offered accepted") } catch {}
        precondition(SystemUpdateInstaller.failure("Failed to authenticate as volume owner").localizedDescription.contains("owner authorization"))
        precondition(!SystemUpdateInstaller.launchScript.contains("--restart"))
        precondition(!SystemUpdateInstaller.launchScript.contains("--all"))
        precondition(!SystemUpdateInstaller.launchScript.contains("--agree-to-license"))
        // Exercise the production launch/progress/exit-file shell protocol with
        // an unprivileged local fixture, never the real system updater.
        let fakeUpdater = root.appendingPathComponent("fake-softwareupdate")
        let argumentsFile = root.appendingPathComponent("native-arguments")
        let fakeBody = "#!/bin/sh\nprintf '%s\\n' \"$@\" > " + ServerEnrollmentCommand.quote(argumentsFile.path) + "\nprintf 'Downloading: 50%%\\n'\nsleep 0.2\nprintf 'Installing: 100%%\\nDone with Fixture Tools\\n'\n"
        try Data(fakeBody.utf8).write(to: fakeUpdater)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: fakeUpdater.path)
        let fixtureScript = SystemUpdateInstaller.launchScript
            .replacingOccurrences(of: "/usr/sbin/softwareupdate", with: ServerEnrollmentCommand.quote(fakeUpdater.path))
            .replacingOccurrences(of: "/Library/Application Support/.ward-system-update.XXXXXXXX", with: root.path + "/native.XXXXXXXX")
            .replacingOccurrences(of: "(/bin/sleep 600; /bin/rm -rf -- \"$work\") </dev/null >/dev/null 2>&1 &", with: ":")
        let labelWithShellText = "Fixture Tools; $(echo should-not-run)"
        let nativeRoot = try toolResult("/bin/sh", ["-c", fixtureScript, "fixture", labelWithShellText]).stdout
        let statusFile = URL(fileURLWithPath: nativeRoot).appendingPathComponent("status")
        for _ in 0..<100 {
            if FileManager.default.fileExists(atPath: statusFile.path) { break }
            try await Task.sleep(for: .milliseconds(50))
        }
        let exitStatus = try String(contentsOf: statusFile, encoding: .utf8).trimmingCharacters(in: .whitespacesAndNewlines)
        precondition(exitStatus == "0")
        let nativeArguments = try String(contentsOf: argumentsFile, encoding: .utf8).split(separator: "\n").map(String.init)
        precondition(nativeArguments == ["--install", labelWithShellText, "--verbose"])
        let progressOutput = try String(contentsOf: URL(fileURLWithPath: nativeRoot).appendingPathComponent("output"), encoding: .utf8)
        precondition(SystemInstallProgress.latest(progressOutput)?.percent == 100)
        print("PASS: system installation staging, exact label arguments, streamed progress, failure/no-op rejection and restart result")

        let app = root.appendingPathComponent("Fixture.app")
        let contents = app.appendingPathComponent("Contents")
        try FileManager.default.createDirectory(at: contents, withIntermediateDirectories: true)
        let plist = contents.appendingPathComponent("Info.plist")
        func writeVersion(_ version: String, id: String = "org.example.fixture") throws {
            try PropertyListSerialization.data(fromPropertyList: ["CFBundleIdentifier": id, "CFBundleShortVersionString": version], format: .xml, options: 0).write(to: plist, options: .atomic)
        }
        try writeVersion("1.0")
        let pendingUpdate = AppUpdateRecord(text: "Newer 2.0", newer: true, canInstall: true, reported: "2.0", installed: "1.0")
        let beforeExternalUpdate = AppUpdateReconciliation.reconcile(pendingUpdate, installed: AppUpdateReconciliation.installedVersion(at: app))
        precondition(beforeExternalUpdate.newer && beforeExternalUpdate.canInstall)
        precondition(AppUpdateReconciliation.reconcile(pendingUpdate, installed: nil) == pendingUpdate, "A bundle being replaced must not be marked current")
        try writeVersion("2.0")
        let externallyUpdated = AppUpdateReconciliation.reconcile(pendingUpdate, installed: AppUpdateReconciliation.installedVersion(at: app))
        precondition(!externallyUpdated.newer && !externallyUpdated.canInstall && externallyUpdated.installed == "2.0")
        precondition(AppUpdateAlerts.pending(["fixture": externallyUpdated], notified: [:]).isEmpty)
        try writeVersion("3.0")
        let newerThanFeed = AppUpdateReconciliation.reconcile(pendingUpdate, installed: AppUpdateReconciliation.installedVersion(at: app))
        precondition(!newerThanFeed.newer && newerThanFeed.reported == "3.0")
        let downgraded = AppUpdateReconciliation.reconcile(externallyUpdated, installed: "1.5")
        precondition(downgraded.newer && !downgraded.canInstall, "A downgrade must not be hidden, and installation requires a fresh channel check")
        let changedScheme = AppUpdateReconciliation.reconcile(pendingUpdate, installed: "unknown-build")
        precondition(changedScheme.newer && !changedScheme.canInstall)
        try Data("incomplete replacement".utf8).write(to: plist)
        precondition(AppUpdateReconciliation.reconcile(pendingUpdate, installed: AppUpdateReconciliation.installedVersion(at: app)) == pendingUpdate)
        print("PASS: external update reconciliation, newer local versions, downgrade detection and interrupted replacement")
        try writeVersion("1.0")
        precondition(!AppUpdateLifecycle.matches(app, bundleID: "org.example.fixture", version: "2.0"))
        try writeVersion("2.0")
        precondition(AppUpdateLifecycle.matches(app, bundleID: "org.example.fixture", version: "2.0"))
        precondition(!AppUpdateLifecycle.matches(app, bundleID: "org.example.other", version: "2.0"))
        try Data("not a plist".utf8).write(to: plist)
        precondition(!AppUpdateLifecycle.matches(app, bundleID: "org.example.fixture", version: "2.0"))
        var polls = 0
        let exited = try await AppUpdateLifecycle.waitForExit([123], timeout: .seconds(1)) { _ in
            polls += 1; return polls < 3
        }
        precondition(exited && polls == 3, "Must re-query process liveness, not retain a snapshot")
        let blocked = try await AppUpdateLifecycle.waitForExit([123], timeout: .zero) { _ in true }
        precondition(!blocked, "A running app must block replacement")
        let notRunning = try await AppUpdateLifecycle.waitForExit([], timeout: .zero) { _ in true }
        precondition(notRunning)
        precondition(!AppUpdateLifecycle.isAlive(-1))
        precondition(AppUpdateLifecycle.progress(stage: "Downloading update…", bytes: 50, total: 100) == 0.35)
        precondition(AppUpdateLifecycle.progress(stage: "Replacing /Applications/Fixture.app", bytes: 0, total: 0) == 0.90)
        print("PASS: installed-version reconciliation, process exit polling/timeout, progress stages")
        let fixtureApp = URL(fileURLWithPath: ProcessInfo.processInfo.environment["WARD_TEST_LIFECYCLE_APP"]!)
        let configuration = NSWorkspace.OpenConfiguration()
        configuration.activates = false
        configuration.createsNewApplicationInstance = true
        let first = try await NSWorkspace.shared.openApplication(at: fixtureApp, configuration: configuration)
        precondition(AppUpdateLifecycle.isAlive(first.processIdentifier))
        precondition(first.terminate())
        let closed = try await AppUpdateLifecycle.waitForExit([first.processIdentifier], timeout: .seconds(10))
        precondition(closed, "Fixture did not quit")
        let reopened = try await NSWorkspace.shared.openApplication(at: fixtureApp, configuration: configuration)
        precondition(AppUpdateLifecycle.isAlive(reopened.processIdentifier) && reopened.processIdentifier != first.processIdentifier)
        precondition(reopened.terminate())
        let closedAgain = try await AppUpdateLifecycle.waitForExit([reopened.processIdentifier], timeout: .seconds(10))
        precondition(closedAgain)
        print("PASS: real isolated app quit and reopen at its original bundle path")
        let executable = root.appendingPathComponent("Fixture")
        let mapping = #"const links={macos:"https://updates.example/app-intel.pkg",macos_m1:"https://updates.example/app-arm.pkg"}"#
        var binary = Data(repeating: 0, count: 1024 * 1024 - 20)
        binary.append(Data(mapping.utf8));try binary.write(to: executable)
        precondition(NativeInstallerUpdates.candidates(executable: executable, arm: true).map(\.lastPathComponent) == ["app-arm.pkg"])
        precondition(NativeInstallerUpdates.candidates(executable: executable, arm: false).map(\.lastPathComponent) == ["app-intel.pkg"])
        let info = Data(#"<?xml version="1.0"?><pkg-info version="999.0"><bundle id="org.example.fixture" CFBundleShortVersionString="3.4.5"/></pkg-info>"#.utf8)
        precondition(NativeInstallerUpdates.bundleVersion(info, id: "org.example.fixture") == "3.4.5")
        precondition(NativeInstallerUpdates.bundleVersion(info, id: "org.example.other") == nil)
        precondition(NativeInstallerUpdates.bundleVersion(Data(#"<!DOCTYPE x [<!ENTITY a "3.4.5">]><bundle id="org.example.fixture" CFBundleShortVersionString="&a;"/>"#.utf8), id: "org.example.fixture") == nil)
        let compressedInfo = deflate(info)
        let inflated = try NativeInstallerUpdates.inflate(compressedInfo, maximum: 262144)
        precondition(inflated == info)
        do { _ = try NativeInstallerUpdates.inflate(compressedInfo, maximum: 2); fatalError("Unbounded expansion") } catch {}
        let xml = Data(#"<xar><toc><file><name>Fixture.pkg</name><file><name>PackageInfo</name><name>PackageInfo</name><data><offset>123</offset><length>45</length><size>120</size><encoding style="application/x-gzip"/></data></file></file></toc></xar>"#.utf8)
        let compressed = deflate(xml)
        let (base, members) = try NativeInstallerUpdates.members(header: header(compressed.count, xml.count), toc: compressed)
        precondition(base == 28 + compressed.count && members.count == 1 && members[0].offset == 123)
        do { _ = try NativeInstallerUpdates.members(header: Data(repeating: 0, count: 28), toc: compressed); fatalError("Bad XAR accepted") } catch {}
        let record = AppUpdateRecord(text: "new", newer: true, canInstall: false, reported: "2.0", installed: "1.0")
        precondition(AppUpdateAlerts.pending(["fixture": record], notified: [:]).count == 1, "Discovery/cache must not count as notification")
        precondition(AppUpdateAlerts.pending(["fixture": record], notified: ["fixture":"2.0"]).isEmpty)
        precondition(AppUpdateAlerts.pending(["fixture": record], notified: ["fixture":"1.5"]).count == 1)
        print("PASS: binary platform links, boundary chunks, bundle identity, bounded XAR/deflate, XML rejection and notification deduplication")
    }
}

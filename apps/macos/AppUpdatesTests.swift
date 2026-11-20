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
    static func main() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
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

import Foundation
import zlib

/// Discover literal macOS package links declared in an application's own embedded
/// platform map. Package bundle IDs, not filenames or product names, select a match.
enum NativeInstallerUpdates {
    private static let lock = NSLock()
    private static var cache: [String: (Date, Int, [URL])] = [:]
    static func candidates(executable: URL, arm: Bool) -> [URL] {
        guard let attrs = try? executable.resourceValues(forKeys: [.fileSizeKey, .contentModificationDateKey]),
              let size = attrs.fileSize, size > 0, size <= 128 * 1024 * 1024, let date = attrs.contentModificationDate else { return [] }
        let key = executable.path + (arm ? "-arm" : "-intel")
        lock.lock(); let saved = cache[key]; lock.unlock()
        if let saved, saved.0 == date, saved.1 == size { return saved.2 }
        guard let data = try? Data(contentsOf: executable, options: [.mappedIfSafe]),
              let regex = try? NSRegularExpression(pattern: #"\b(macos(?:_m1|_arm64|_amd64|_x64)?|darwin(?:_arm64|_amd64|_x64)?):\"(https://[^\"\s]{1,500}\.pkg)\""#) else { return [] }
        var urls = Set<URL>()
        let chunk = 1024 * 1024
        for start in stride(from: 0, to: data.count, by: chunk) {
            let text = String(decoding: data[start..<min(data.count, start + chunk + 1024)], as: UTF8.self)
            for match in regex.matches(in: text, range: NSRange(text.startIndex..., in: text)) {
                guard let kr = Range(match.range(at: 1), in: text), let ur = Range(match.range(at: 2), in: text) else { continue }
                let platform = String(text[kr])
                let isArm = platform.hasSuffix("_m1") || platform.hasSuffix("_arm64")
                guard isArm == arm, let url = URL(string: String(text[ur])), url.scheme == "https", url.user == nil,
                      url.password == nil, url.fragment == nil else { continue }
                urls.insert(url)
            }
        }
        let result = urls.count <= 4 ? urls.sorted { $0.absoluteString < $1.absoluteString } : []
        lock.lock()
        if cache.count >= 128 { cache.removeAll() }
        cache[key] = (date, size, result)
        lock.unlock()
        return result
    }

    static func inflate(_ input: Data, maximum: Int) throws -> Data {
        var output = Data(count: maximum)
        var length = uLongf(maximum)
        let result = output.withUnsafeMutableBytes { target in
            input.withUnsafeBytes { source in
                uncompress(target.bindMemory(to: Bytef.self).baseAddress!, &length,
                           source.bindMemory(to: Bytef.self).baseAddress!, uLong(input.count))
            }
        }
        guard result == Z_OK, length <= maximum else { throw WardError("Installer metadata decompression failed.") }
        output.count = Int(length)
        return output
    }

    struct Member { let offset, length, size: Int; let compressed: Bool }
    private final class TOC: NSObject, XMLParserDelegate {
        var paths: [String] = []; var stack: [(name: String, offset: String, length: String, size: String, encoding: String, previousName: String)] = []
        var members: [Member] = []; var invalid = false
        func parser(_ parser: XMLParser, didStartElement name: String, namespaceURI: String?, qualifiedName: String?, attributes: [String: String]) {
            paths.append(name)
            if paths.count > 64 { invalid = true; parser.abortParsing(); return }
            if name == "file" { stack.append(("", "", "", "", "", "")) }
            if name == "name", !stack.isEmpty {
                let i = stack.count - 1
                stack[i].previousName = stack[i].name
                stack[i].name = ""
            }
            if name == "encoding", !stack.isEmpty, paths.dropLast().last == "data" { stack[stack.count - 1].encoding = attributes["style"] ?? "" }
        }
        func parser(_ parser: XMLParser, foundCharacters text: String) {
            guard !stack.isEmpty, let field = paths.last else { return }
            let i = stack.count - 1
            if field == "name" { stack[i].name += text }
            if paths.dropLast().last == "data" {
                switch field { case "offset": stack[i].offset += text; case "length": stack[i].length += text; case "size": stack[i].size += text; default: break }
            }
        }
        func parser(_ parser: XMLParser, didEndElement name: String, namespaceURI: String?, qualifiedName: String?) {
            if name == "name", let current = stack.last, !current.previousName.isEmpty, current.previousName != current.name { invalid = true }
            if name == "file", let file = stack.popLast(), file.name == "PackageInfo" {
                if let offset = Int(file.offset), let length = Int(file.length), let size = Int(file.size),
                   offset >= 0, offset <= 1_000_000_000, length > 0, length <= 65536, size > 0, size <= 262144,
                   ["application/octet-stream", "application/x-gzip"].contains(file.encoding), members.count < 16 {
                    members.append(Member(offset: offset, length: length, size: size, compressed: file.encoding == "application/x-gzip"))
                } else { invalid = true }
            }
            if !paths.isEmpty { paths.removeLast() }
        }
    }
    static func members(header: Data, toc: Data) throws -> (Int, [Member]) {
        func number(_ start: Int, _ count: Int) -> UInt64 { header[start..<start+count].reduce(0) { ($0 << 8) | UInt64($1) } }
        guard header.count == 28, header.prefix(4) == Data("xar!".utf8), number(4,2) == 28, number(6,2) == 1,
              number(8,8) > 0, number(8,8) <= 1_048_576, number(16,8) > 0, number(16,8) <= 4_194_304,
              toc.count == Int(number(8,8)) else { throw WardError("Unsupported installer metadata header.") }
        let xml = try inflate(toc, maximum: Int(number(16,8)))
        guard xml.range(of: Data("<!DOCTYPE".utf8)) == nil else { throw WardError("Installer metadata declarations are not supported.") }
        let delegate = TOC(); let parser = XMLParser(data: xml); parser.delegate = delegate; parser.shouldResolveExternalEntities = false
        guard parser.parse(), !delegate.invalid else { throw WardError("Invalid installer metadata index.") }
        return (28 + toc.count, delegate.members)
    }
    private final class BundleInfo: NSObject, XMLParserDelegate {
        let id: String; var versions: [String] = []
        init(id: String) { self.id = id }
        func parser(_ parser: XMLParser, didStartElement name: String, namespaceURI: String?, qualifiedName: String?, attributes: [String: String]) {
            if name == "bundle", attributes["id"] == id, let version = attributes["CFBundleShortVersionString"],
               version.range(of: "^[0-9]+(?:\\.[0-9]+){1,4}$", options: .regularExpression) != nil { versions.append(version) }
        }
    }
    static func bundleVersion(_ data: Data, id: String) -> String? {
        guard data.count <= 262144, data.range(of: Data("<!DOCTYPE".utf8)) == nil else { return nil }
        let delegate = BundleInfo(id: id); let parser = XMLParser(data: data); parser.shouldResolveExternalEntities = false; parser.delegate = delegate
        guard parser.parse(), Set(delegate.versions).count == 1 else { return nil }
        return delegate.versions.first
    }
}

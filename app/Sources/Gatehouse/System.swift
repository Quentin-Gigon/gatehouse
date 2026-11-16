import Foundation

enum Paths {
    static let prefix = "/opt/gatehouse"
    static let installedVersion = prefix + "/VERSION"
    static let daemonPlist = "/Library/LaunchDaemons/com.gatehouse.broker.plist"
    static let admin = "/usr/local/bin/gatehouse-admin"
    static let connect = "/usr/local/bin/gatehouse-connect"
    static let broker = URL(string: "http://127.0.0.1:8737")!

    static var configDir: URL {
        FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".config/gatehouse")
    }
    static func agentConfig(_ name: String) -> URL { configDir.appendingPathComponent("agent-\(name).json") }

    /// The service files bundled inside the app (src, deploy, pyproject.toml).
    static var payload: URL? { Bundle.main.resourceURL?.appendingPathComponent("payload") }

    static var bundledVersion: String? {
        guard let p = payload?.appendingPathComponent("pyproject.toml"),
              let text = try? String(contentsOf: p, encoding: .utf8) else { return nil }
        for line in text.split(separator: "\n") where line.hasPrefix("version = ") {
            return line.replacingOccurrences(of: "version = ", with: "").trimmingCharacters(in: CharacterSet(charactersIn: "\" "))
        }
        return nil
    }

    static var isInstalled: Bool {
        FileManager.default.fileExists(atPath: daemonPlist) && FileManager.default.fileExists(atPath: admin)
    }

    static var installedVersionString: String? {
        (try? String(contentsOfFile: installedVersion, encoding: .utf8))?.trimmingCharacters(in: .whitespacesAndNewlines)
    }
}

struct CommandError: LocalizedError {
    let message: String
    var errorDescription: String? { message }
}

enum Shell {
    /// Quote for /bin/sh.
    static func quote(_ s: String) -> String { "'" + s.replacingOccurrences(of: "'", with: "'\\''") + "'" }

    /// Run a program and return its standard output. Throws with its error output on failure.
    @discardableResult
    static func run(_ exe: String, _ args: [String], input: Data? = nil) async throws -> String {
        try await withCheckedThrowingContinuation { cont in
            let p = Process()
            p.executableURL = URL(fileURLWithPath: exe)
            p.arguments = args
            let out = Pipe(), err = Pipe()
            p.standardOutput = out
            p.standardError = err
            let inPipe = input.map { _ in Pipe() }
            if let inPipe { p.standardInput = inPipe }
            p.terminationHandler = { proc in
                let o = String(data: out.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
                let e = String(data: err.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
                if proc.terminationStatus == 0 {
                    cont.resume(returning: o)
                } else {
                    let msg = e.trimmingCharacters(in: .whitespacesAndNewlines)
                    cont.resume(throwing: CommandError(message: msg.isEmpty ? o : msg))
                }
            }
            do {
                try p.run()
                if let inPipe, let input {
                    inPipe.fileHandleForWriting.write(input)
                    try? inPipe.fileHandleForWriting.close()
                }
            } catch {
                cont.resume(throwing: error)
            }
        }
    }

    /// A command in the user's login shell, so it finds `claude` and `codex` wherever they were installed.
    static func login(_ command: String) async throws -> String {
        try await run("/bin/zsh", ["-lc", command])
    }

    /// Run a shell command as root after the standard macOS administrator prompt (password or Touch ID).
    /// This is the only way the app gains rights: agents running as you cannot answer this dialog.
    static func admin(_ command: String, prompt: String) async throws -> String {
        func esc(_ s: String) -> String { s.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"") }
        let script = "do shell script \"\(esc(command))\" with prompt \"\(esc(prompt))\" with administrator privileges"
        do {
            return try await run("/usr/bin/osascript", ["-e", script])
        } catch let e as CommandError where e.message.contains("-128") {
            throw CommandError(message: "Cancelled.")
        }
    }
}

/// Talks to the broker on 127.0.0.1. The admin token lives only in this process's memory.
final class BrokerAPI {
    var token: String?
    private let session: URLSession = {
        let c = URLSessionConfiguration.ephemeral
        c.timeoutIntervalForRequest = 30
        return URLSession(configuration: c)
    }()
    private let decoder: JSONDecoder = {
        let d = JSONDecoder()
        d.keyDecodingStrategy = .convertFromSnakeCase
        return d
    }()

    enum APIError: LocalizedError {
        case locked, notRunning, server(String)
        var errorDescription: String? {
            switch self {
            case .locked: return "Gatehouse is locked."
            case .notRunning: return "The Gatehouse service isn't running."
            case .server(let m): return m
            }
        }
    }

    func attention() async throws -> Attention {
        do {
            let (data, _) = try await session.data(from: Paths.broker.appendingPathComponent("v1/attention"))
            return try decoder.decode(Attention.self, from: data)
        } catch is DecodingError {
            throw APIError.server("Unexpected answer from the service.")
        } catch {
            throw APIError.notRunning
        }
    }

    func call<T: Decodable>(_ path: String, _ body: [String: Any] = [:], as: T.Type = T.self) async throws -> T {
        guard let token else { throw APIError.locked }
        var req = URLRequest(url: Paths.broker.appendingPathComponent("admin/" + path))
        req.httpMethod = "POST"
        req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.httpBody = try JSONSerialization.data(withJSONObject: body)
        let data: Data, resp: URLResponse
        do {
            (data, resp) = try await session.data(for: req)
        } catch {
            throw APIError.notRunning
        }
        let status = (resp as? HTTPURLResponse)?.statusCode ?? 0
        if status == 401 {
            self.token = nil
            throw APIError.locked
        }
        if status != 200 {
            let msg = (try? JSONSerialization.jsonObject(with: data) as? [String: Any])?["error"] as? String
            throw APIError.server(msg ?? "The service answered with an error (\(status)).")
        }
        return try decoder.decode(T.self, from: data)
    }

    /// For calls whose answer the app does not need.
    func send(_ path: String, _ body: [String: Any] = [:]) async throws {
        _ = try await call(path, body, as: Empty.self)
    }

    /// Raw JSON, for the agent config written to disk as is.
    func rawCall(_ path: String, _ body: [String: Any]) async throws -> Data {
        struct Raw: Decodable {}
        guard let token else { throw APIError.locked }
        var req = URLRequest(url: Paths.broker.appendingPathComponent("admin/" + path))
        req.httpMethod = "POST"
        req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.httpBody = try JSONSerialization.data(withJSONObject: body)
        let (data, resp) = try await session.data(for: req)
        let status = (resp as? HTTPURLResponse)?.statusCode ?? 0
        if status == 401 { self.token = nil; throw APIError.locked }
        guard status == 200 else {
            let msg = (try? JSONSerialization.jsonObject(with: data) as? [String: Any])?["error"] as? String
            throw APIError.server(msg ?? "The service answered with an error (\(status)).")
        }
        return data
    }
}

struct Empty: Decodable {}

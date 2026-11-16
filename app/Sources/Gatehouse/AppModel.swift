import AppKit
import Foundation
import ServiceManagement
import UserNotifications

@MainActor
final class AppModel: ObservableObject {
    enum ServiceState: Equatable { case notInstalled, notRunning, running }

    @Published var service: ServiceState = .notInstalled
    @Published var attention: Attention?
    @Published var overview: Overview = .empty
    @Published var activity: [ActivityRow] = []
    @Published var unlocked = false
    @Published var busy: String?             // short description of a running task
    @Published var error: String?
    @Published var installLog = ""
    @Published var installedHarnesses: Set<String> = []
    @Published var selection: SidebarItem? = .websites

    let api = BrokerAPI()
    let filler = FillerClient()
    private var timer: Timer?
    private var notified = Set<String>()

    init() {
        refreshService()
        timer = Timer.scheduledTimer(withTimeInterval: 4, repeats: true) { [weak self] _ in
            Task { @MainActor in await self?.poll() }
        }
        Task { await poll() }
        Task { await detectHarnesses() }
        filler.start()
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound]) { _, _ in }
    }

    var needsUpdate: Bool {
        // Installs from before the app wrote no VERSION file: those need the update too.
        // Compares version and the fingerprint of the service files, so a rebuilt app with the same
        // version number still updates the service.
        guard Paths.isInstalled, let b = Paths.bundledBuild ?? Paths.bundledVersion else { return false }
        return Paths.installedVersionString != b
    }

    // MARK: polling

    func refreshService() {
        if !Paths.isInstalled { service = .notInstalled }
    }

    func poll() async {
        guard Paths.isInstalled else { service = .notInstalled; attention = nil; return }
        do {
            let a = try await api.attention()
            service = .running
            if a != attention { attention = a; notify(a) }
        } catch {
            service = .notRunning
            attention = nil
        }
        if unlocked && api.token == nil { unlocked = false }
    }

    private func notify(_ a: Attention) {
        for h in a.handoffs where !notified.contains(h.requestId) {
            notified.insert(h.requestId)
            let c = UNMutableNotificationContent()
            c.title = "\(Harness.byAgentName[h.agent]?.title ?? h.agent) needs your help"
            c.body = "Signing in to \(h.account.isEmpty ? h.origin : h.account) needs a person (CAPTCHA or code). Open Gatehouse to finish it."
            c.sound = .default
            UNUserNotificationCenter.current().add(UNNotificationRequest(identifier: h.requestId, content: c, trigger: nil))
        }
        if a.approvals > 0 && !notified.contains("approvals-\(a.approvals)") {
            notified.insert("approvals-\(a.approvals)")
            let c = UNMutableNotificationContent()
            c.title = "An agent is asking for access"
            c.body = "Open Gatehouse to allow or deny it."
            UNUserNotificationCenter.current().add(UNNotificationRequest(identifier: "approvals", content: c, trigger: nil))
        }
    }

    // MARK: lock

    func unlock() async -> Bool {
        if unlocked, api.token != nil { return true }
        do {
            let out = try await Shell.admin(Shell.quote(Paths.admin) + " admin-token",
                                            prompt: "Gatehouse needs your password to unlock its settings.")
            let token = out.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !token.isEmpty, !token.contains(" ") else { throw CommandError(message: "Could not unlock: \(out)") }
            api.token = token
            unlocked = true
            await reload()
            return true
        } catch {
            if (error as? CommandError)?.message != "Cancelled." { self.error = error.localizedDescription }
            return false
        }
    }

    func lock() {
        Task { try? await api.send("lock") }
        api.token = nil
        unlocked = false
        overview = .empty
        activity = []
    }

    func reload() async {
        guard api.token != nil else { return }
        do {
            overview = try await api.call("overview")
            struct Rows: Decodable { var rows: [ActivityRow] }
            activity = try await api.call("activity", ["limit": 300], as: Rows.self).rows
        } catch BrokerAPI.APIError.locked {
            unlocked = false
        } catch {
            self.error = error.localizedDescription
        }
    }

    /// Run an admin action, unlocking first if needed, then refresh. Returns false on failure.
    @discardableResult
    func perform(_ label: String, _ action: @escaping () async throws -> Void) async -> Bool {
        guard await unlock() else { return false }
        busy = label
        defer { busy = nil }
        do {
            try await action()
            await reload()
            await poll()
            return true
        } catch BrokerAPI.APIError.locked {
            unlocked = false
            error = "Gatehouse locked itself after a while without use. Unlock and try again."
        } catch {
            self.error = error.localizedDescription
        }
        return false
    }

    // MARK: install

    /// Where root writes the bundled scripts' output: a folder only root can change, so nothing
    /// running as you can point the log at another file.
    static let runLog = URL(fileURLWithPath: "/var/log/gatehouse/run.log")

    /// Run one of the bundled service scripts as root. Root first copies the whole app into a fresh
    /// root-only folder and verifies the copy's signature, so a script edited inside the app (which
    /// your account can write to) is refused instead of run.
    private func runBundled(_ script: String, _ args: [String], prompt: String) async throws {
        let argv = args.map(Shell.quote).joined(separator: " ")
        let cmd = [
            "L=/var/log/gatehouse",
            "[ ! -L \"$L\" ] || exit 90",
            "mkdir -p \"$L\" && chown root:wheel \"$L\" && chmod 755 \"$L\" && rm -f \"$L/run.log\" || exit 91",
            "D=\"$(mktemp -d /tmp/gatehouse-app.XXXXXX)\" || exit 92",
            "trap 'rm -rf \"$D\"' EXIT",
            "{ ditto \(Shell.quote(Bundle.main.bundlePath)) \"$D/Gatehouse.app\" && codesign --verify --deep --strict \"$D/Gatehouse.app\"; } > \"$L/run.log\" 2>&1"
                + " || { echo 'This copy of Gatehouse was changed after it was built, so it was not run. Download it again.' >> \"$L/run.log\"; exit 93; }",
            "/bin/bash \"$D/Gatehouse.app/Contents/Resources/payload/deploy/macos/\(script)\" \(argv) >> \"$L/run.log\" 2>&1",
        ].joined(separator: "; ")
        _ = try await Shell.admin(cmd, prompt: prompt)
    }

    func install() async {
        guard Paths.payload != nil else { error = "This copy of the app is incomplete."; return }
        let log = Self.runLog
        installLog = ""
        busy = "Installing…"
        let tail = Task { @MainActor in
            while !Task.isCancelled {
                installLog = (try? String(contentsOf: log, encoding: .utf8)) ?? installLog
                try? await Task.sleep(nanoseconds: 500_000_000)
            }
        }
        defer { tail.cancel(); busy = nil }
        do {
            // --yes: this window is the confirmation the terminal installer would otherwise ask for.
            try await runBundled("install.sh", ["--yes", "--user", NSUserName()],
                                 prompt: "Gatehouse needs your password to install its background service.")
            installLog = (try? String(contentsOf: log, encoding: .utf8)) ?? installLog
            await poll()
        } catch {
            installLog = (try? String(contentsOf: log, encoding: .utf8)) ?? installLog
            if (error as? CommandError)?.message != "Cancelled." {
                self.error = "Installation failed. The log below says where it stopped."
            }
        }
    }

    func uninstall(purge: Bool) async {
        guard Paths.payload != nil else { return }
        busy = "Removing…"
        defer { busy = nil }
        do {
            try await runBundled("uninstall.sh", purge ? ["--purge"] : [],
                                 prompt: "Gatehouse needs your password to remove its background service.")
            for h in Harness.all { try? FileManager.default.removeItem(at: Paths.agentConfig(h.agentName)) }
            api.token = nil
            unlocked = false
            await poll()
        } catch {
            if (error as? CommandError)?.message != "Cancelled." { self.error = error.localizedDescription }
        }
    }

    // MARK: agents

    func detectHarnesses() async {
        var found = Set<String>()
        if (try? await Shell.login("command -v claude")) != nil { found.insert("claude-code") }
        if (try? await Shell.login("command -v codex")) != nil { found.insert("codex") }
        if FileManager.default.fileExists(atPath: "/Applications/Claude.app")
            || FileManager.default.fileExists(atPath: NSHomeDirectory() + "/Applications/Claude.app") {
            found.insert("claude-desktop")
        }
        installedHarnesses = found
    }

    func isConnected(_ h: Harness) -> Bool {
        overview.activeAgent(named: h.agentName) != nil && FileManager.default.fileExists(atPath: Paths.agentConfig(h.agentName).path)
    }

    /// Register the agent (new keys if it exists; its access stays), store its keys for you only,
    /// and add the Gatehouse tools to the app.
    func connect(_ h: Harness) async {
        await perform("Connecting \(h.title)…") { [self] in
            let data = try await api.rawCall("agent/connect", ["name": h.agentName])
            let fm = FileManager.default
            try fm.createDirectory(at: Paths.configDir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
            let url = Paths.agentConfig(h.agentName)
            try? fm.removeItem(at: url)
            guard fm.createFile(atPath: url.path, contents: data, attributes: [.posixPermissions: 0o600]) else {
                throw CommandError(message: "Could not save the agent's keys in \(url.path).")
            }
            _ = try await Shell.login(Shell.quote(Paths.connect) + " " + Shell.quote(h.agentName))
        }
    }

    func disconnect(_ h: Harness) async {
        guard let agent = overview.activeAgent(named: h.agentName) else { return }
        await perform("Disconnecting \(h.title)…") { [self] in
            try await api.send("agent/revoke", ["agent_id": agent.id])
            try? FileManager.default.removeItem(at: Paths.agentConfig(h.agentName))
            switch h.agentName {
            case "claude-code":
                _ = try? await Shell.login("claude mcp remove gatehouse -s user; claude mcp remove gatehouse-browser -s user")
            case "codex":
                _ = try? await Shell.login("codex mcp remove gatehouse; codex mcp remove gatehouse-browser")
            default:
                break
            }
        }
    }

    func setAccess(agent: Agent, account: Account, allowed: Bool, duration: AccessDuration = .forever) async {
        await perform(allowed ? "Allowing…" : "Removing access…") { [self] in
            try await api.send("access", ["agent_id": agent.id, "account_id": account.id,
                                          "allowed": allowed, "duration": duration.rawValue])
        }
    }

    // MARK: Safari

    var safariReady: Bool { SafariFiller.hasPermission && attention?.appConnected == true }

    /// Let agents that control the screen sign in to this account in Safari, typed by this app.
    func setSafari(_ account: Account, allowed: Bool) async {
        let ok = await perform(allowed ? "Allowing in Safari…" : "Turning off Safari…") { [self] in
            if allowed && (FillerKey.load() == nil || attention?.appConnected != true) {
                struct Key: Decodable { var fillerKey: String }
                FillerKey.save(try await api.call("filler/register", as: Key.self).fillerKey)
                filler.restart()
            }
            try await api.send("account/edit", ["account_id": account.id, "allow_safari": allowed])
        }
        if ok && allowed {
            if !SafariFiller.hasPermission { SafariFiller.askForPermission() }
            if !launchAtLogin { launchAtLogin = true }   // Safari sign-ins need the app running
        }
    }

    // MARK: settings

    var launchAtLogin: Bool {
        get { SMAppService.mainApp.status == .enabled }
        set {
            do {
                if newValue { try SMAppService.mainApp.register() } else { try SMAppService.mainApp.unregister() }
            } catch {
                self.error = "Couldn't change the login item: \(error.localizedDescription)"
            }
            objectWillChange.send()
        }
    }
}

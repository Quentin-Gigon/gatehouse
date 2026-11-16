import AppKit
import SwiftUI
import WebKit

// MARK: - Agents

struct AgentsView: View {
    @EnvironmentObject var model: AppModel

    var body: some View {
        Form {
            Section {
                ForEach(Harness.all) { h in HarnessRow(harness: h) }
            } header: {
                Text("AI apps")
            } footer: {
                Text("Connecting gives the app its own Gatehouse identity and adds two tools to it: one to ask for sign-ins, and the browser where it then works. Restart the app (or start a new session) afterwards. T3 Code uses the Claude Code and Codex connections.")
            }
            let others = model.overview.agents.filter { $0.active && Harness.byAgentName[$0.name] == nil && $0.name != "selftest" }
            if !others.isEmpty {
                Section("Other connected agents") {
                    ForEach(others) { a in
                        HStack {
                            Text(a.name)
                            Spacer()
                            Button("Disconnect", role: .destructive) {
                                Task { await model.perform("Disconnecting…") { try await model.api.send("agent/revoke", ["agent_id": a.id]) } }
                            }
                        }
                    }
                }
            }
            Section {
                Text("""
                Agents sign in through Gatehouse's own browser, not yours, so it works whichever browser you use. \
                Tell an agent: "Use the gatehouse tools to sign in to <website>, then do the task in the gatehouse browser."
                """)
                .foregroundStyle(.secondary)
            } header: {
                Text("Using it")
            }
        }
        .formStyle(.grouped)
        .navigationTitle("Agents")
        .task { await model.detectHarnesses() }
    }
}

struct HarnessRow: View {
    @EnvironmentObject var model: AppModel
    let harness: Harness

    var body: some View {
        let connected = model.isConnected(harness)
        let installed = model.installedHarnesses.contains(harness.agentName)
        HStack(spacing: 12) {
            Image(systemName: harness.symbol).font(.title2).frame(width: 32).foregroundStyle(.tint)
            VStack(alignment: .leading, spacing: 2) {
                Text(harness.title).font(.headline)
                Text(connected ? "Connected" : installed ? harness.detail : "Not found on this Mac")
                    .font(.caption).foregroundStyle(connected ? .green : .secondary)
            }
            Spacer()
            if connected {
                Menu("Options") {
                    Button("Reconnect") { Task { await model.connect(harness) } }
                    Button("Disconnect", role: .destructive) { Task { await model.disconnect(harness) } }
                }
                .fixedSize()
            } else {
                Button("Connect") { Task { await model.connect(harness) } }
                    .buttonStyle(.borderedProminent)
                    .disabled(!installed)
            }
        }
        .padding(.vertical, 4)
        if connected, let agent = model.overview.activeAgent(named: harness.agentName), !model.overview.accounts.isEmpty {
            DisclosureGroup("Websites \(harness.title) may use") {
                ForEach(model.overview.accounts.filter { !$0.origins.isEmpty }) { a in
                    AccessToggle(agent: agent, account: a)
                }
            }
            .padding(.leading, 44)
        }
    }
}

// MARK: - Needs you

struct NeedsYouView: View {
    @EnvironmentObject var model: AppModel
    @Environment(\.openWindow) private var openWindow
    @Local private var duration: AccessDuration = .forever

    var body: some View {
        let o = model.overview
        Group {
            if o.handoffs.isEmpty && o.approvals.isEmpty {
                ContentUnavailableView("Nothing needs you", systemImage: "checkmark.circle",
                                       description: Text("When a website shows a CAPTCHA or an agent asks for new access, it appears here and as a notification."))
            } else {
                Form {
                    if !o.handoffs.isEmpty {
                        Section {
                            ForEach(o.handoffs) { h in
                                HStack {
                                    VStack(alignment: .leading, spacing: 2) {
                                        Text("\(Harness.byAgentName[h.agent]?.title ?? h.agent) is signing in to \(h.account)").font(.headline)
                                        Text("The site wants a person: solve the CAPTCHA or enter the code it sent you.")
                                            .font(.caption).foregroundStyle(.secondary)
                                    }
                                    Spacer()
                                    Button("Help Sign In…") { openWindow(id: "handoff", value: h.token) }
                                        .buttonStyle(.borderedProminent)
                                }
                            }
                        } header: {
                            Text("Waiting for you")
                        } footer: {
                            Text("The agent keeps waiting for up to 15 minutes.")
                        }
                    }
                    if !o.approvals.isEmpty {
                        Section("Access requests") {
                            Picker("If allowed", selection: $duration) {
                                ForEach(AccessDuration.allCases) { Text($0.label).tag($0) }
                            }
                            ForEach(o.approvals) { r in
                                HStack {
                                    VStack(alignment: .leading, spacing: 2) {
                                        Text("\(Harness.byAgentName[r.agent]?.title ?? r.agent) wants to use \(r.account)").font(.headline)
                                        Text("on \(r.origin)").font(.caption).foregroundStyle(.secondary)
                                    }
                                    Spacer()
                                    Button("Deny") {
                                        Task { await model.perform("Denying…") { try await model.api.send("approval/deny", ["approval_id": r.id]) } }
                                    }
                                    Button("Allow") {
                                        Task { await model.perform("Allowing…") {
                                            try await model.api.send("approval/approve", ["approval_id": r.id, "duration": duration.rawValue])
                                        } }
                                    }
                                    .buttonStyle(.borderedProminent)
                                }
                            }
                        }
                    }
                }
                .formStyle(.grouped)
            }
        }
        .navigationTitle("Needs You")
        .task {
            while !Task.isCancelled {
                await model.reload()
                try? await Task.sleep(nanoseconds: 4_000_000_000)
            }
        }
    }
}

/// The live sign-in page for a CAPTCHA or code. The app fills in the handoff code itself.
struct HandoffView: View {
    @EnvironmentObject var model: AppModel
    let handoff: HandoffInfo

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Image(systemName: "hand.raised.fill").foregroundStyle(.orange)
                Text("Finish signing \(Harness.byAgentName[handoff.agent]?.title ?? handoff.agent) in to \(handoff.account): solve the check below. The password is already filled in; you won't see it.")
                    .font(.callout)
                Spacer()
            }
            .padding(10)
            .background(.bar)
            HandoffWeb(url: URL(string: handoff.url)!, code: handoff.code)
        }
        .frame(minWidth: 900, minHeight: 700)
    }
}

struct HandoffWeb: NSViewRepresentable {
    let url: URL
    let code: String

    func makeCoordinator() -> Coordinator { Coordinator(code: code) }

    func makeNSView(context: Context) -> WKWebView {
        let config = WKWebViewConfiguration()
        config.websiteDataStore = .nonPersistent()
        let web = WKWebView(frame: .zero, configuration: config)
        web.navigationDelegate = context.coordinator
        web.load(URLRequest(url: url))
        return web
    }

    func updateNSView(_ nsView: WKWebView, context: Context) {}

    final class Coordinator: NSObject, WKNavigationDelegate {
        let code: String
        private var submitted = false
        init(code: String) { self.code = code }

        func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
            guard !submitted else { return }
            submitted = true
            // The code page has one input named "code"; on the live page this finds nothing and does nothing.
            let js = """
            (() => { const i = document.querySelector('input[name="code"]');
                     if (i) { i.value = \(String(reflecting: code)); i.form.submit(); } })();
            """
            webView.evaluateJavaScript(js)
        }

        func webView(_ webView: WKWebView, decidePolicyFor action: WKNavigationAction,
                     decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
            // Stay on the local handoff page; anything else opens nowhere.
            decisionHandler(action.request.url?.host == "127.0.0.1" ? .allow : .cancel)
        }
    }
}

// MARK: - Activity

struct ActivityView: View {
    @EnvironmentObject var model: AppModel
    @Local private var showAll = false

    var body: some View {
        let rows = model.activity.filter { showAll || ActivityText.important($0) }
        List(rows) { r in
            HStack(alignment: .top, spacing: 10) {
                Image(systemName: ActivityText.symbol(r)).foregroundStyle(ActivityText.color(r)).frame(width: 20)
                VStack(alignment: .leading, spacing: 2) {
                    Text(ActivityText.sentence(r))
                    Text(Date(timeIntervalSince1970: r.ts).formatted(date: .abbreviated, time: .shortened))
                        .font(.caption).foregroundStyle(.secondary)
                }
            }
            .padding(.vertical, 2)
        }
        .overlay { if rows.isEmpty { ContentUnavailableView("No activity yet", systemImage: "clock") } }
        .navigationTitle("Activity")
        .toolbar {
            Toggle("Show technical events", isOn: $showAll).toggleStyle(.checkbox)
            Button { Task { await model.reload() } } label: { Label("Refresh", systemImage: "arrow.clockwise") }
        }
    }
}

enum ActivityText {
    static func who(_ r: ActivityRow) -> String {
        guard let a = r.agent, !a.isEmpty else { return "An agent" }
        return Harness.byAgentName[a]?.title ?? a
    }
    static func what(_ r: ActivityRow) -> String { r.account ?? r.origin ?? "a website" }
    static func status(_ r: ActivityRow) -> (String, String) {
        let parts = (r.result ?? "").split(separator: ":", maxSplits: 1).map(String.init)
        return (parts.first ?? "", parts.count > 1 ? parts[1].replacingOccurrences(of: "_", with: " ") : "")
    }

    static func important(_ r: ActivityRow) -> Bool {
        !["browser_started", "login_request", "api_rejected", "browser_discarded"].contains(r.action)
            || (r.action == "login_request" && r.decision == "denied")
    }

    static func sentence(_ r: ActivityRow) -> String {
        let (s, detail) = status(r)
        switch r.action {
        case "login_result":
            switch s {
            case "signed_in": return "\(who(r)) signed in to \(what(r))"
            case "already_signed_in": return "\(who(r)) was already signed in to \(what(r))"
            case "cancelled": return "\(who(r)) cancelled signing in to \(what(r))"
            case "human_verification_timeout": return "\(who(r)) gave up on \(what(r)): nobody solved the check in time"
            case "permission_required": return "\(who(r)) needs your OK to sign in to \(what(r)) (\(detail))"
            default: return "\(who(r)) couldn't sign in to \(what(r))\(detail.isEmpty ? "" : ": \(detail)")"
            }
        case "login_request": return "\(who(r)) was refused \(what(r))\(detail.isEmpty ? "" : ": \(detail)")"
        case "grant_added": return "\(who(r)) was allowed to use \(what(r))"
        case "grant_revoked": return "\(who(r)) can no longer use \(what(r))"
        case "approval": return r.decision == "allowed" ? "You allowed \(who(r)) to use \(what(r))" : "You denied \(who(r)) access to \(what(r))"
        case "account_added": return "You added \(what(r))"
        case "account_edited": return "You changed \(what(r))"
        case "account_removed": return "You removed a website"
        case "accounts_imported": return "You imported logins"
        case "agent_added": return "\(who(r)) was connected"
        case "agent_keys_rotated": return "\(who(r)) was reconnected"
        case "agent_revoked": return "\(who(r)) was disconnected"
        case "handoff_opened": return "\(who(r)) needed your help signing in to \(what(r))"
        case "handoff_claimed": return "You opened the sign-in check for \(what(r))"
        case "handoff_claim_refused": return "Someone entered a wrong code for the sign-in check on \(what(r))"
        case "logout": return "\(who(r)) signed out of \(what(r)) locally"
        case "logins_disabled": return "You paused all sign-ins"
        case "logins_enabled": return "You resumed sign-ins"
        case "broker_started": return "Gatehouse started"
        case "browser_started": return "\(who(r))'s browser started"
        case "api_rejected": return "A request with invalid keys was rejected"
        default: return r.action.replacingOccurrences(of: "_", with: " ")
        }
    }

    static func symbol(_ r: ActivityRow) -> String {
        let (s, _) = status(r)
        if r.action == "login_result" { return s == "signed_in" || s == "already_signed_in" ? "checkmark.circle.fill" : "xmark.circle.fill" }
        if r.decision == "denied" || r.action.hasSuffix("refused") || r.action == "api_rejected" { return "hand.raised.fill" }
        if r.action.hasPrefix("handoff") { return "person.fill.questionmark" }
        return "circle.fill"
    }

    static func color(_ r: ActivityRow) -> Color {
        switch symbol(r) {
        case "checkmark.circle.fill": return .green
        case "xmark.circle.fill", "hand.raised.fill": return .orange
        default: return .secondary
        }
    }
}

// MARK: - Settings

struct SettingsView: View {
    @EnvironmentObject var model: AppModel
    @Local private var confirmRemove = false
    @Local private var purge = false

    var body: some View {
        Form {
            Section("General") {
                Toggle("Open Gatehouse at login", isOn: Binding(get: { model.launchAtLogin }, set: { model.launchAtLogin = $0 }))
                Toggle("Pause all sign-ins", isOn: Binding(get: { model.attention?.loginsDisabled ?? false }, set: { on in
                    Task { await model.perform(on ? "Pausing…" : "Resuming…") { try await model.api.send("logins", ["enabled": !on]) } }
                }))
                Text("Pausing stops every agent from signing in anywhere until you switch it back. Use it if something looks wrong.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            Section {
                LabeledContent("Accessibility permission") {
                    if SafariFiller.hasPermission {
                        Label("Granted", systemImage: "checkmark.circle.fill").foregroundStyle(.green)
                    } else {
                        Button("Grant…") { SafariFiller.askForPermission() }
                    }
                }
                LabeledContent("Connected to the service", value: model.attention?.appConnected == true ? "Yes" : "No")
            } header: {
                Text("Safari sign-in")
            } footer: {
                Text("Used only for websites where you switched on \u{201C}Also allow in Safari\u{201D}. The app must be running, so it opens at login.")
            }
            Section("Service") {
                LabeledContent("Status", value: model.service == .running ? "Running" : "Not running")
                LabeledContent("Installed version", value: Paths.installedVersionString ?? "–")
                LabeledContent("This app's version", value: Paths.bundledVersion ?? "–")
                HStack {
                    Button(model.needsUpdate ? "Update Service" : "Repair Service") { Task { await model.install() } }
                    Spacer()
                    Button("Remove Gatehouse…", role: .destructive) { confirmRemove = true }
                }
                if !model.installLog.isEmpty { InstallLog(text: model.installLog) }
            }
            Section("Backup") {
                Text("Your logins live in an encrypted vault on this Mac only. To keep a copy, run this in Terminal and store the file somewhere safe (it can unlock your passwords):")
                    .font(.callout)
                Text("sudo tar -C /var/db -czf ~/gatehouse-backup.tgz gatehouse/home/vault.json gatehouse/passphrase")
                    .font(.system(.caption, design: .monospaced)).textSelection(.enabled)
            }
        }
        .formStyle(.grouped)
        .navigationTitle("Settings")
        .confirmationDialog("Remove Gatehouse from this Mac?", isPresented: $confirmRemove) {
            Button("Remove, keep my saved logins") { Task { await model.uninstall(purge: false) } }
            Button("Remove everything, including saved logins", role: .destructive) { Task { await model.uninstall(purge: true) } }
        } message: {
            Text("Agents will no longer be able to sign in. Websites they're signed in to aren't signed out.")
        }
    }
}

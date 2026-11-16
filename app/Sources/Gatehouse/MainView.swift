import SwiftUI

enum SidebarItem: String, Hashable, CaseIterable, Identifiable {
    case needsYou, websites, agents, activity, settings
    var id: String { rawValue }
    var title: String {
        switch self {
        case .needsYou: return "Needs You"
        case .websites: return "Websites"
        case .agents: return "Agents"
        case .activity: return "Activity"
        case .settings: return "Settings"
        }
    }
    var symbol: String {
        switch self {
        case .needsYou: return "bell.badge"
        case .websites: return "globe"
        case .agents: return "sparkles"
        case .activity: return "clock"
        case .settings: return "gearshape"
        }
    }
}

struct MainView: View {
    @EnvironmentObject var model: AppModel

    var body: some View {
        Group {
            if model.service == .notInstalled {
                WelcomeView()
            } else {
                NavigationSplitView {
                    List(SidebarItem.allCases, selection: $model.selection) { item in
                        Label(item.title, systemImage: item.symbol)
                            .badge(item == .needsYou ? (model.attention?.count ?? 0) : 0)
                            .tag(item)
                    }
                    .navigationSplitViewColumnWidth(min: 180, ideal: 200)
                } detail: {
                    detail
                        .toolbar { LockButton() }
                }
            }
        }
        .overlay(alignment: .bottom) {
            if let busy = model.busy {
                HStack(spacing: 8) { ProgressView().controlSize(.small); Text(busy) }
                    .padding(.horizontal, 14).padding(.vertical, 8)
                    .background(.regularMaterial, in: Capsule())
                    .padding()
            }
        }
        .alert("Something went wrong", isPresented: Binding(get: { model.error != nil }, set: { if !$0 { model.error = nil } })) {
            Button("OK") { model.error = nil }
        } message: {
            Text(model.error ?? "")
        }
    }

    @ViewBuilder private var detail: some View {
        if model.needsUpdate && model.selection != .settings {
            UpdateView()
        } else if model.service == .notRunning {
            ServiceDownView()
        } else if !model.unlocked && model.selection != .settings {
            LockedView()
        } else {
            switch model.selection ?? .websites {
            case .needsYou: NeedsYouView()
            case .websites: WebsitesView()
            case .agents: AgentsView()
            case .activity: ActivityView()
            case .settings: SettingsView()
            }
        }
    }
}

struct LockButton: View {
    @EnvironmentObject var model: AppModel
    var body: some View {
        if model.unlocked {
            Button { model.lock() } label: { Label("Lock", systemImage: "lock.open") }
                .help("Lock Gatehouse. Changes will need your password again.")
        } else {
            Button { Task { await model.unlock() } } label: { Label("Unlock", systemImage: "lock") }
                .help("Unlock with your Mac password or Touch ID")
        }
    }
}

struct LockedView: View {
    @EnvironmentObject var model: AppModel
    var body: some View {
        VStack(spacing: 18) {
            Image(systemName: "lock.shield").font(.system(size: 54)).foregroundStyle(.secondary)
            Text("Gatehouse is locked").font(.title2.bold())
            Text("Unlock with your Mac password or Touch ID to manage websites and agents.\nYour AI agents can't do this: they don't know your password.")
                .multilineTextAlignment(.center).foregroundStyle(.secondary)
            Button { Task { await model.unlock() } } label: { Text("Unlock").frame(minWidth: 120) }
                .buttonStyle(.borderedProminent).controlSize(.large)
            if let a = model.attention, a.count > 0 {
                Label("\(a.count) thing\(a.count == 1 ? "" : "s") need\(a.count == 1 ? "s" : "") you", systemImage: "bell.badge.fill")
                    .foregroundStyle(.orange)
            }
        }
        .padding(40)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

struct ServiceDownView: View {
    @EnvironmentObject var model: AppModel
    var body: some View {
        VStack(spacing: 16) {
            Image(systemName: "exclamationmark.triangle").font(.system(size: 48)).foregroundStyle(.orange)
            Text("The Gatehouse service isn't running").font(.title2.bold())
            Text("It normally starts on its own with your Mac. Repairing reinstalls it and keeps your websites and agents.")
                .multilineTextAlignment(.center).foregroundStyle(.secondary).frame(maxWidth: 460)
            Button("Repair") { Task { await model.install() } }.buttonStyle(.borderedProminent)
            if !model.installLog.isEmpty { InstallLog(text: model.installLog) }
        }
        .padding(40)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

struct UpdateView: View {
    @EnvironmentObject var model: AppModel
    var body: some View {
        VStack(spacing: 16) {
            Image(systemName: "arrow.down.circle").font(.system(size: 48)).foregroundStyle(.tint)
            Text("Update the Gatehouse service").font(.title2.bold())
            Text("This app is newer than the service on your Mac (\(Paths.installedVersionString ?? "older version") → \(Paths.bundledBuild ?? Paths.bundledVersion ?? "?")). Updating keeps your websites, agents and their access, and asks for your Mac password once.")
                .multilineTextAlignment(.center).foregroundStyle(.secondary).frame(maxWidth: 480)
            Button { Task { await model.install() } } label: { Text(model.busy == nil ? "Update" : "Updating…").frame(minWidth: 140) }
                .buttonStyle(.borderedProminent).controlSize(.large).disabled(model.busy != nil)
            if !model.installLog.isEmpty { InstallLog(text: model.installLog) }
        }
        .padding(40)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

struct InstallLog: View {
    let text: String
    var body: some View {
        ScrollViewReader { proxy in
            ScrollView {
                Text(text.replacingOccurrences(of: "\u{1B}[1m", with: "").replacingOccurrences(of: "\u{1B}[0m", with: ""))
                    .font(.system(.caption, design: .monospaced))
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(10)
                    .id("end")
            }
            .frame(maxWidth: 640, maxHeight: 220)
            .background(.quaternary.opacity(0.5), in: RoundedRectangle(cornerRadius: 8))
            .onChange(of: text) { proxy.scrollTo("end", anchor: .bottom) }
        }
    }
}

struct WelcomeView: View {
    @EnvironmentObject var model: AppModel
    var body: some View {
        ScrollView {
            VStack(spacing: 22) {
                Image(systemName: "lock.shield.fill").font(.system(size: 64)).foregroundStyle(.tint)
                Text("Welcome to Gatehouse").font(.largeTitle.bold())
                Text("Let your AI agents sign in to the websites you choose, without ever seeing your passwords.")
                    .font(.title3).multilineTextAlignment(.center).foregroundStyle(.secondary)
                VStack(alignment: .leading, spacing: 14) {
                    Point(symbol: "key.fill", title: "Your passwords stay locked away",
                          text: "They're kept in an encrypted vault that only Gatehouse's own hidden helper can open. Agents never get to read them.")
                    Point(symbol: "hand.raised.fill", title: "You decide who gets in where",
                          text: "Pick which agent may sign in to which website. Change it any time.")
                    Point(symbol: "moon.stars.fill", title: "Works while you're away",
                          text: "Once allowed, an agent can sign in on its own, for scheduled tasks too. You're only asked if a site shows a CAPTCHA.")
                }
                .frame(maxWidth: 520)
                if model.busy != nil || !model.installLog.isEmpty {
                    InstallLog(text: model.installLog.isEmpty ? "Starting…" : model.installLog)
                }
                Button { Task { await model.install() } } label: {
                    Text(model.busy == nil ? "Set Up Gatehouse" : "Setting up…").frame(minWidth: 200)
                }
                .buttonStyle(.borderedProminent).controlSize(.large)
                .disabled(model.busy != nil)
                Text("Setup takes a few minutes and asks for your Mac password once.")
                    .font(.callout).foregroundStyle(.secondary)
            }
            .padding(48)
            .frame(maxWidth: .infinity)
        }
    }

    struct Point: View {
        let symbol: String, title: String, text: String
        var body: some View {
            HStack(alignment: .top, spacing: 14) {
                Image(systemName: symbol).font(.title2).foregroundStyle(.tint).frame(width: 30)
                VStack(alignment: .leading, spacing: 3) {
                    Text(title).font(.headline)
                    Text(text).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                }
            }
        }
    }
}

import AppKit
import SwiftUI
import UniformTypeIdentifiers

struct WebsitesView: View {
    @EnvironmentObject var model: AppModel
    @Local private var selected: Account.ID?
    @Local private var adding = false
    @Local private var importing = false

    var body: some View {
        HSplitView {
            VStack(spacing: 0) {
                if model.overview.accounts.isEmpty {
                    ContentUnavailableView {
                        Label("No websites yet", systemImage: "globe")
                    } description: {
                        Text("Add the logins your agents may use, one by one or from your password manager.")
                    } actions: {
                        Button("Add Website…") { adding = true }.buttonStyle(.borderedProminent)
                        Button("Import from Passwords App…") { importing = true }
                    }
                } else {
                    List(model.overview.accounts.sorted { $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending },
                         selection: $selected) { a in
                        WebsiteRow(account: a).tag(a.id)
                    }
                }
            }
            .frame(minWidth: 260, idealWidth: 300, maxWidth: 380)

            Group {
                if let a = model.overview.accounts.first(where: { $0.id == selected }) {
                    WebsiteDetail(account: a)
                } else {
                    Text(model.overview.accounts.isEmpty ? "" : "Select a website")
                        .foregroundStyle(.secondary).frame(maxWidth: .infinity, maxHeight: .infinity)
                }
            }
            .frame(minWidth: 380, maxWidth: .infinity, maxHeight: .infinity)
        }
        .navigationTitle("Websites")
        .toolbar {
            ToolbarItemGroup {
                Button { importing = true } label: { Label("Import", systemImage: "square.and.arrow.down") }
                    .help("Import logins from Apple Passwords, Chrome, 1Password or Bitwarden")
                Button { adding = true } label: { Label("Add Website", systemImage: "plus") }
            }
        }
        .sheet(isPresented: $adding) { AccountForm(account: nil) }
        .sheet(isPresented: $importing) { ImportSheet() }
    }
}

struct WebsiteRow: View {
    @EnvironmentObject var model: AppModel
    let account: Account
    var body: some View {
        HStack(spacing: 10) {
            Favicon(host: account.host)
            VStack(alignment: .leading, spacing: 2) {
                Text(account.name).font(.headline)
                Text(account.username).font(.caption).foregroundStyle(.secondary)
            }
            Spacer()
            let n = model.overview.agents.filter { $0.active && model.overview.activeGrant(agent: $0.id, account: account.id) != nil }.count
            if account.origins.isEmpty {
                Image(systemName: "exclamationmark.circle").foregroundStyle(.orange).help("Needs a website address")
            } else if n > 0 {
                Text("\(n) agent\(n == 1 ? "" : "s")").font(.caption).foregroundStyle(.secondary)
            }
        }
        .padding(.vertical, 3)
    }
}

struct Favicon: View {
    let host: String
    var body: some View {
        ZStack {
            RoundedRectangle(cornerRadius: 7).fill(Color.accentColor.opacity(0.15))
            Text(String(host.first ?? "?").uppercased()).font(.headline).foregroundStyle(.tint)
        }
        .frame(width: 30, height: 30)
    }
}

struct WebsiteDetail: View {
    @EnvironmentObject var model: AppModel
    let account: Account
    @Local private var editing = false
    @Local private var confirmDelete = false

    var body: some View {
        Form {
            Section {
                HStack(spacing: 14) {
                    Favicon(host: account.host).scaleEffect(1.5).frame(width: 46, height: 46)
                    VStack(alignment: .leading) {
                        Text(account.name).font(.title2.bold())
                        Text(account.username).foregroundStyle(.secondary)
                    }
                }
                LabeledContent("Sign-in page", value: account.loginUrl.isEmpty ? "Not set" : account.loginUrl)
                LabeledContent("Websites", value: account.origins.isEmpty ? "None yet" : account.origins.joined(separator: "\n"))
                LabeledContent("Password", value: "Stored, never shown")
                LabeledContent("Two-factor codes", value: account.hasTotp ? "Filled in automatically" : "Not set up")
                if account.failures >= 2 {
                    HStack {
                        Label("Paused after \(account.failures) failed sign-ins. Check the password.", systemImage: "exclamationmark.triangle.fill")
                            .foregroundStyle(.orange)
                        Spacer()
                        Button("Resume") {
                            Task { await model.perform("Resuming…") { try await model.api.send("account/unblock", ["account_id": account.id]) } }
                        }
                    }
                }
            }

            Section {
                let agents = model.overview.agents.filter(\.active).filter { $0.name != "selftest" }
                if agents.isEmpty {
                    Text("Connect an agent in Agents first.").foregroundStyle(.secondary)
                } else if account.origins.isEmpty {
                    Text("Add the website address first (Edit).").foregroundStyle(.secondary)
                } else {
                    ForEach(agents) { agent in AccessToggle(agent: agent, account: account) }
                }
            } header: {
                Text("Who may sign in")
            } footer: {
                Text("An allowed agent can sign in on its own, any time, without asking you. It never sees the password.")
            }

            Section {
                HStack {
                    Button("Edit…") { editing = true }
                    Spacer()
                    Button("Remove Website…", role: .destructive) { confirmDelete = true }
                }
            }
        }
        .formStyle(.grouped)
        .sheet(isPresented: $editing) { AccountForm(account: account) }
        .confirmationDialog("Remove \(account.name)?", isPresented: $confirmDelete) {
            Button("Remove", role: .destructive) {
                Task { await model.perform("Removing…") { try await model.api.send("account/remove", ["account_id": account.id]) } }
            }
        } message: {
            Text("The login is deleted from Gatehouse and no agent can use it any more. Agents already signed in stay signed in until the website logs them out.")
        }
    }
}

struct AccessToggle: View {
    @EnvironmentObject var model: AppModel
    let agent: Agent
    let account: Account
    @Local private var duration: AccessDuration = .forever

    var body: some View {
        let grant = model.overview.activeGrant(agent: agent.id, account: account.id)
        HStack {
            Toggle(isOn: Binding(get: { grant != nil }, set: { on in
                Task { await model.setAccess(agent: agent, account: account, allowed: on, duration: duration) }
            })) {
                VStack(alignment: .leading, spacing: 2) {
                    Text(agent.displayName)
                    if let g = grant {
                        Text(describe(g)).font(.caption).foregroundStyle(.secondary)
                    }
                }
            }
            .toggleStyle(.switch)
            if grant == nil {
                Picker("", selection: $duration) {
                    ForEach(AccessDuration.allCases) { Text($0.label).tag($0) }
                }
                .labelsHidden().frame(width: 190)
            }
        }
    }

    private func describe(_ g: Grant) -> String {
        switch g.kind {
        case "once": return "For one sign-in"
        case "session": return "Until Gatehouse restarts"
        case "until": return "Until " + Date(timeIntervalSince1970: g.expiresAt ?? 0).formatted(date: .abbreviated, time: .shortened)
        default: return g.usedCount > 0 ? "Always · used \(g.usedCount)×" : "Always"
        }
    }
}

// MARK: - Add / edit

struct AccountForm: View {
    @EnvironmentObject var model: AppModel
    @Environment(\.dismiss) private var dismiss
    let account: Account?

    @Local private var name = ""
    @Local private var address = ""
    @Local private var username = ""
    @Local private var password = ""
    @Local private var totp = ""
    @Local private var removeTotp = false
    @Local private var extraSites = ""
    @Local private var preClick = ""
    @Local private var successSelector = ""
    @Local private var allowAgents = Set<String>()
    @Local private var showAdvanced = false

    var body: some View {
        VStack(spacing: 0) {
            Form {
                Section {
                    TextField("Name", text: $name, prompt: Text("e.g. Moodle"))
                    TextField("Sign-in page", text: $address, prompt: Text("e.g. moodle.myschool.ch/login"))
                    TextField("Username or email", text: $username)
                        .textContentType(.username)
                    SecureField(account == nil ? "Password" : "New password", text: $password,
                                prompt: Text(account == nil ? "" : "Leave empty to keep the current one"))
                } footer: {
                    Text("Tip: open the website's sign-in page in your browser and copy its address.")
                }

                Section {
                    SecureField("Setup key", text: $totp, prompt: Text(account?.hasTotp == true ? "Set up; leave empty to keep" : "Optional"))
                    if account?.hasTotp == true { Toggle("Turn off automatic codes", isOn: $removeTotp) }
                } header: {
                    Text("Two-factor codes (authenticator app)")
                } footer: {
                    Text("If the site uses an authenticator app, paste its setup key (or the otpauth:// link) here and Gatehouse types the 6-digit codes itself. Codes sent by text or email can't be automated: you'll be asked to type those.")
                }

                if account == nil {
                    let agents = model.overview.agents.filter(\.active).filter { $0.name != "selftest" }
                    if !agents.isEmpty {
                        Section("Allow these agents to use it") {
                            ForEach(agents) { a in
                                Toggle(a.displayName, isOn: Binding(get: { allowAgents.contains(a.id) },
                                                                    set: { if $0 { allowAgents.insert(a.id) } else { allowAgents.remove(a.id) } }))
                            }
                        }
                    }
                }

                Section {
                    DisclosureGroup("Advanced", isExpanded: $showAdvanced) {
                        TextField("Other websites used to sign in", text: $extraSites, prompt: Text("e.g. login.microsoftonline.com"))
                        TextField("Button to click first", text: $preClick, prompt: Text("CSS selector, e.g. button.sign-in-with-email"))
                        TextField("Only present when signed in", text: $successSelector, prompt: Text("CSS selector, e.g. #account-menu"))
                        Text("Only needed if sign-in doesn't work out of the box. Separate several websites with commas.")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                }
            }
            .formStyle(.grouped)

            HStack {
                Spacer()
                Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction)
                Button(account == nil ? "Add Website" : "Save") { save() }
                    .keyboardShortcut(.defaultAction)
                    .disabled(name.isEmpty || address.isEmpty || username.isEmpty || (account == nil && password.isEmpty))
            }
            .padding()
        }
        .frame(width: 540, height: 620)
        .onAppear(perform: load)
    }

    private func load() {
        guard let a = account else { return }
        name = a.name
        address = a.loginUrl.isEmpty ? (a.origins.first ?? a.importedUrl) : a.loginUrl
        username = a.username
        let main = address.isEmpty ? nil : URL(string: address.contains("://") ? address : "https://" + address).flatMap { u in
            u.scheme.map { "\($0)://\(u.host ?? "")" }
        }
        extraSites = a.origins.filter { $0 != main }.map { $0.replacingOccurrences(of: "https://", with: "") }.joined(separator: ", ")
        preClick = a.preClick.joined(separator: ", ")
        successSelector = a.successSelector
        showAdvanced = !extraSites.isEmpty || !preClick.isEmpty || !successSelector.isEmpty
    }

    private func save() {
        let extras = extraSites.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
        let clicks = preClick.isEmpty ? [] : [preClick.trimmingCharacters(in: .whitespaces)]
        Task {
            let ok = await model.perform(account == nil ? "Adding…" : "Saving…") {
                if let a = account {
                    var body: [String: Any] = ["account_id": a.id, "name": name, "username": username,
                                               "login_url": address, "pre_click": clicks, "success_selector": successSelector]
                    let loginHost = address.contains("://") ? address : "https://" + address
                    body["websites"] = [loginHost] + extras
                    if !password.isEmpty { body["password"] = password }
                    if !totp.isEmpty { body["totp"] = totp } else if removeTotp { body["totp"] = "" }
                    try await model.api.send("account/edit", body)
                } else {
                    struct Added: Decodable { var accountId: String }
                    let added = try await model.api.call("account/add", [
                        "name": name, "username": username, "password": password, "login_url": address,
                        "totp": totp, "extra_websites": extras, "pre_click": clicks, "success_selector": successSelector,
                    ], as: Added.self)
                    for agentId in allowAgents {
                        try await model.api.send("access", ["agent_id": agentId, "account_id": added.accountId,
                                                            "allowed": true, "duration": "forever"])
                    }
                }
            }
            if ok {
                password = ""; totp = ""
                dismiss()
            }
        }
    }
}

// MARK: - Import

struct ImportSheet: View {
    @EnvironmentObject var model: AppModel
    @Environment(\.dismiss) private var dismiss
    @Local private var fileURL: URL?
    @Local private var csv = ""
    @Local private var preview: ImportPreview?
    @Local private var picked = Set<Int>()
    @Local private var search = ""
    @Local private var result: ImportResult?

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Import logins").font(.title2.bold())
            if let result {
                done(result)
            } else if let preview {
                choose(preview)
            } else {
                intro
            }
        }
        .padding(24)
        .frame(width: 640, height: 560)
    }

    private var intro: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Export your passwords from your password manager as a CSV file, then choose it here. You'll pick exactly which logins to bring in; nothing else is imported.")
            GroupBox {
                VStack(alignment: .leading, spacing: 8) {
                    Label("Apple Passwords: File › Export All Passwords…", systemImage: "key")
                    Label("Chrome: Settings › Passwords › Settings › Export passwords", systemImage: "globe")
                    Label("1Password or Bitwarden: File › Export (CSV)", systemImage: "lock.rectangle")
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(4)
            }
            Label("The export file contains your passwords in plain text. Gatehouse offers to delete it when you're done.",
                  systemImage: "exclamationmark.triangle").foregroundStyle(.orange).font(.callout)
            Spacer()
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction)
                Button("Choose File…") { pick() }.keyboardShortcut(.defaultAction)
            }
        }
    }

    private func choose(_ p: ImportPreview) -> some View {
        let rows = p.entries.filter { search.isEmpty || $0.name.localizedCaseInsensitiveContains(search)
            || $0.url.localizedCaseInsensitiveContains(search) || $0.username.localizedCaseInsensitiveContains(search) }
        return VStack(alignment: .leading, spacing: 10) {
            HStack {
                Text("Tick the logins your agents should be able to use (\(picked.count) selected).")
                Spacer()
                TextField("Search", text: $search).textFieldStyle(.roundedBorder).frame(width: 180)
            }
            List(rows) { e in
                Toggle(isOn: Binding(get: { picked.contains(e.index) },
                                     set: { if $0 { picked.insert(e.index) } else { picked.remove(e.index) } })) {
                    HStack {
                        VStack(alignment: .leading) {
                            Text(e.name).font(.headline)
                            Text("\(e.username) · \(e.url)").font(.caption).foregroundStyle(.secondary).lineLimit(1)
                        }
                        Spacer()
                        if !e.totp.isEmpty { Text("2FA").font(.caption2).padding(3).background(.quaternary, in: RoundedRectangle(cornerRadius: 4)) }
                        if !e.hasPassword { Text("no password").font(.caption).foregroundStyle(.orange) }
                    }
                }
                .disabled(!e.hasPassword)
            }
            Text("Each ticked login's website becomes the place agents may sign in. You still choose which agents may use it afterwards.")
                .font(.caption).foregroundStyle(.secondary)
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction)
                Button("Import \(picked.count)") { apply() }.keyboardShortcut(.defaultAction).disabled(picked.isEmpty)
            }
        }
    }

    private func done(_ r: ImportResult) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            Label("Imported \(r.imported.count) login\(r.imported.count == 1 ? "" : "s")", systemImage: "checkmark.circle.fill")
                .font(.title3).foregroundStyle(.green)
            if !(r.skipped + r.notes).isEmpty {
                ScrollView { Text((r.skipped + r.notes).joined(separator: "\n")).font(.callout).frame(maxWidth: .infinity, alignment: .leading) }
                    .frame(maxHeight: 160)
            }
            Text("Next: open each website and switch on the agents that may use it.").foregroundStyle(.secondary)
            Spacer()
            HStack {
                if let fileURL {
                    Button("Move Export File to Trash") {
                        NSWorkspace.shared.recycle([fileURL]) { _, _ in }
                        self.fileURL = nil
                    }
                }
                Spacer()
                Button("Done") { dismiss() }.keyboardShortcut(.defaultAction)
            }
        }
    }

    private func pick() {
        let panel = NSOpenPanel()
        panel.allowedContentTypes = [.commaSeparatedText, .plainText]
        panel.allowsMultipleSelection = false
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do {
            var text = try String(contentsOf: url, encoding: .utf8)
            if text.hasPrefix("\u{FEFF}") { text.removeFirst() }
            csv = text
            fileURL = url
            Task {
                await model.perform("Reading…") {
                    preview = try await model.api.call("import/preview", ["csv": csv], as: ImportPreview.self)
                }
            }
        } catch {
            model.error = "Couldn't read that file: \(error.localizedDescription)"
        }
    }

    private func apply() {
        Task {
            await model.perform("Importing…") {
                result = try await model.api.call("import/apply", ["csv": csv, "selected": Array(picked), "on_duplicate": "skip"],
                                                  as: ImportResult.self)
            }
            csv = ""
        }
    }
}

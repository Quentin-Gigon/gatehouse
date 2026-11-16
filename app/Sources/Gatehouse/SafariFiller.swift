import AppKit
import ApplicationServices
import Foundation
import Security

/// The app's key for the service's Safari channel, kept in your login keychain. Other programs,
/// agents included, can only read it if you click Allow in a keychain prompt.
enum FillerKey {
    private static let service = "io.github.gatehouse.safari-channel"

    static func load() -> String? {
        let q: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service,
                                kSecReturnData as String: true, kSecMatchLimit as String: kSecMatchLimitOne]
        var out: CFTypeRef?
        guard SecItemCopyMatching(q as CFDictionary, &out) == errSecSuccess, let d = out as? Data else { return nil }
        return String(data: d, encoding: .utf8)
    }

    static func save(_ key: String) {
        let base: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service]
        SecItemDelete(base as CFDictionary)
        var add = base
        add[kSecValueData as String] = Data(key.utf8)
        add[kSecAttrLabel as String] = "Gatehouse Safari sign-in channel"
        SecItemAdd(add as CFDictionary, nil)
    }
}

/// Holds the connection to the service and runs the Safari sign-ins it sends, one at a time.
@MainActor
final class FillerClient: ObservableObject {
    @Published var connected = false
    private var task: URLSessionWebSocketTask?
    private var running = false
    private let filler = SafariFiller()

    func start() {
        guard !running else { return }
        running = true
        Task { await loop() }
    }

    func restart() {
        task?.cancel(with: .goingAway, reason: nil)
        start()
    }

    private func loop() async {
        while true {
            if let key = FillerKey.load() {
                await session(key: key)
            }
            connected = false
            try? await Task.sleep(nanoseconds: 5_000_000_000)
        }
    }

    private func session(key: String) async {
        var req = URLRequest(url: URL(string: "ws://127.0.0.1:8737/filler/ws")!)
        req.setValue("Bearer \(key)", forHTTPHeaderField: "Authorization")
        let t = URLSession(configuration: .ephemeral).webSocketTask(with: req)
        task = t
        t.resume()
        while true {
            guard let msg = try? await t.receive() else { return }
            connected = true
            guard case .string(let text) = msg,
                  let data = text.data(using: .utf8),
                  let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let rid = obj["request_id"] as? String else { continue }
            switch obj["type"] as? String {
            case "fill":
                let job = SafariFiller.Job(
                    requestId: rid, account: obj["account"] as? String ?? "", loginURL: obj["login_url"] as? String ?? "",
                    origins: Set(obj["origins"] as? [String] ?? []), username: obj["username"] as? String ?? "",
                    password: obj["password"] as? String ?? "", totp: obj["totp"] as? String)
                let (status, detail) = await filler.run(job) { detail in
                    Self.send(t, ["type": "status", "request_id": rid, "detail": detail])
                }
                Self.send(t, ["type": "result", "request_id": rid, "status": status, "detail": detail])
            case "cancel":
                filler.cancel(rid)
            default:
                break
            }
        }
    }

    private static func send(_ t: URLSessionWebSocketTask, _ obj: [String: Any]) {
        guard let d = try? JSONSerialization.data(withJSONObject: obj), let s = String(data: d, encoding: .utf8) else { return }
        t.send(.string(s)) { _ in }
    }
}

/// Types a login into Safari through the macOS accessibility interface.
///
/// Before every character it checks, on the field it is about to type into, that the field still has
/// the keyboard focus, that the page holding it (the frame, not just the tab) is on an approved
/// website, and, for the password, that it is a real password field. If anything moves, it stops.
/// When the sign-in doesn't go through, it empties the password field so nothing is left behind.
@MainActor
final class SafariFiller {
    struct Job {
        let requestId, account, loginURL: String
        let origins: Set<String>
        let username, password: String
        let totp: String?
    }

    private var cancelled = Set<String>()
    private var useHID = false        // fall back to system-wide key events if Safari ignores targeted ones

    func cancel(_ id: String) { cancelled.insert(id) }

    static var hasPermission: Bool { AXIsProcessTrusted() }

    static func askForPermission() {
        let opts = [kAXTrustedCheckOptionPrompt.takeUnretainedValue() as String: true] as CFDictionary
        _ = AXIsProcessTrustedWithOptions(opts)
    }

    struct Stop: Error { let status: String, detail: String }

    func run(_ job: Job, progress: (String) -> Void) async -> (String, String) {
        defer { cancelled.remove(job.requestId) }
        do {
            guard Self.hasPermission else { throw Stop(status: "login_failed", detail: "gatehouse_app_needs_accessibility_permission_ask_the_user") }
            guard let url = URL(string: job.loginURL) else { throw Stop(status: "unsupported_login_flow", detail: "bad_sign_in_address") }
            progress("opening_safari")
            let safari = try await openInSafari(url)
            let app = AXUIElementCreateApplication(safari.processIdentifier)

            progress("waiting_for_sign_in_page")
            var fields = try await waitForFields(app, job, needPassword: false)
            if let user = fields.user, !job.username.isEmpty {
                progress("typing_username")
                try await type(job.username, into: user, app: app, pid: safari.processIdentifier, job: job, secure: false)
            }
            if fields.password == nil {
                // Username first, password on the next step.
                try pressReturn(on: fields.user, app: app, pid: safari.processIdentifier, job: job)
                fields = try await waitForFields(app, job, needPassword: true)
            }
            guard let pw = fields.password else { throw Stop(status: "unsupported_login_flow", detail: "no_password_field_found") }
            progress("typing_password")
            try await type(job.password, into: pw, app: app, pid: safari.processIdentifier, job: job, secure: true)
            try pressReturn(on: pw, app: app, pid: safari.processIdentifier, job: job)

            progress("waiting_for_website")
            return try await outcome(app, job, pid: safari.processIdentifier, password: pw)
        } catch let s as Stop {
            return (s.status, s.detail)
        } catch {
            return ("login_failed", "safari_error")
        }
    }

    // MARK: steps

    private func openInSafari(_ url: URL) async throws -> NSRunningApplication {
        guard let safariURL = NSWorkspace.shared.urlForApplication(withBundleIdentifier: "com.apple.Safari") else {
            throw Stop(status: "unsupported_login_flow", detail: "safari_not_found")
        }
        let cfg = NSWorkspace.OpenConfiguration()
        cfg.activates = true
        do {
            return try await NSWorkspace.shared.open([url], withApplicationAt: safariURL, configuration: cfg)
        } catch {
            throw Stop(status: "login_failed", detail: "could_not_open_safari")
        }
    }

    private struct Fields { var user: AXUIElement?; var password: AXUIElement?; var others: [AXUIElement] }

    private func waitForFields(_ app: AXUIElement, _ job: Job, needPassword: Bool, timeout: Double = 25) async throws -> Fields {
        let end = Date().addingTimeInterval(timeout)
        while Date() < end {
            try check(job)
            if let area = AX.frontWebArea(app), let origin = AX.origin(of: area), job.origins.contains(origin) {
                let f = scan(area, job)
                if f.password != nil || (!needPassword && f.user != nil) { return f }
            }
            try await Task.sleep(nanoseconds: 400_000_000)
        }
        if let area = AX.frontWebArea(app), let origin = AX.origin(of: area), !job.origins.contains(origin) {
            throw Stop(status: "permission_required", detail: "safari_is_on_an_unapproved_website")
        }
        throw Stop(status: "unsupported_login_flow", detail: needPassword ? "no_password_field_found" : "no_login_form_found")
    }

    /// Text fields in page order, keeping only those inside frames on approved websites.
    private func scan(_ area: AXUIElement, _ job: Job) -> Fields {
        var texts: [AXUIElement] = []
        var password: AXUIElement?
        var userBeforePassword: AXUIElement?
        AX.walk(area, limit: 6000) { el, role, subrole in
            guard role == "AXTextField" else { return }
            guard let frame = AX.webArea(containing: el), let o = AX.origin(of: frame), job.origins.contains(o) else { return }
            if subrole == "AXSecureTextField" {
                if password == nil { password = el; userBeforePassword = texts.last }
            } else {
                texts.append(el)
            }
        }
        let user = password != nil ? userBeforePassword : texts.first(where: AX.looksLikeUsername) ?? texts.first
        return Fields(user: user, password: password, others: texts)
    }

    /// Re-checked before every key: focus is on `field`, its frame is on an approved website, and
    /// for the password it is a password field.
    private func verify(_ field: AXUIElement, app: AXUIElement, job: Job, secure: Bool) throws {
        try check(job)
        guard let frame = AX.webArea(containing: field), let o = AX.origin(of: frame), job.origins.contains(o) else {
            throw Stop(status: "permission_required", detail: "page_left_the_approved_website")
        }
        if secure && AX.string(field, kAXSubroleAttribute) != "AXSecureTextField" {
            throw Stop(status: "unsupported_login_flow", detail: "password_field_changed")
        }
        if !AX.isFocused(field, in: app) {
            AXUIElementSetAttributeValue(field, kAXFocusedAttribute as CFString, kCFBooleanTrue)
            if !AX.isFocused(field, in: app) { throw Stop(status: "login_failed", detail: "focus_moved_stopped_typing") }
        }
    }

    private func type(_ text: String, into field: AXUIElement, app: AXUIElement, pid: pid_t, job: Job, secure: Bool) async throws {
        try verify(field, app: app, job: job, secure: secure)
        Keys.selectAllAndDelete(pid: pid, hid: useHID)
        try await Task.sleep(nanoseconds: 80_000_000)
        var first = true
        for ch in text {
            try verify(field, app: app, job: job, secure: secure)
            Keys.type(ch, pid: pid, hid: useHID)
            try await Task.sleep(nanoseconds: 15_000_000)
            if first && !secure {
                first = false
                // Some Safari versions ignore keys sent to it directly; then send them system-wide
                // (Safari is frontmost and the field focused, both just verified).
                try await Task.sleep(nanoseconds: 120_000_000)
                if (AX.string(field, kAXValueAttribute) ?? "").isEmpty && !useHID {
                    useHID = true
                    Keys.type(ch, pid: pid, hid: true)
                }
            }
        }
    }

    private func pressReturn(on field: AXUIElement?, app: AXUIElement, pid: pid_t, job: Job) throws {
        if let field { try verify(field, app: app, job: job, secure: false) }
        Keys.returnKey(pid: pid, hid: useHID)
    }

    private func outcome(_ app: AXUIElement, _ job: Job, pid: pid_t, password: AXUIElement) async throws -> (String, String) {
        var typedCode = false
        var codeAsked = false
        let end = Date().addingTimeInterval(20)
        try await Task.sleep(nanoseconds: 1_500_000_000)
        while Date() < end {
            try check(job)
            guard let area = AX.frontWebArea(app) else { break }
            let f = scan(area, job)
            if f.password == nil {
                let codeField = f.others.first(where: AX.looksLikeCode)
                if codeField == nil { return ("signed_in", "safari") }
                // A verification-code step: type the authenticator code if we have one, once.
                if let code = job.totp, !typedCode, let codeField {
                    typedCode = true
                    try await type(code, into: codeField, app: app, pid: pid, job: job, secure: false)
                    try pressReturn(on: codeField, app: app, pid: pid, job: job)
                    try await Task.sleep(nanoseconds: 1_500_000_000)
                    continue
                }
                codeAsked = true
            }
            try await Task.sleep(nanoseconds: 700_000_000)
        }
        if codeAsked {
            return ("login_failed", "needs_a_code_ask_the_user_to_type_it_in_safari")
        }
        // Still on a sign-in form: wrong password, a CAPTCHA, or a step we don't know. Don't leave
        // the password sitting in the field.
        clear(password, app: app, pid: pid, job: job)
        if let area = AX.frontWebArea(app), scan(area, job).password == nil {
            return ("signed_in", "safari_unconfirmed_check_the_page")
        }
        return ("login_failed", "still_on_sign_in_page_check_the_screen_for_an_error_or_captcha")
    }

    private func clear(_ field: AXUIElement, app: AXUIElement, pid: pid_t, job: Job) {
        guard (try? verify(field, app: app, job: job, secure: true)) != nil else { return }
        Keys.selectAllAndDelete(pid: pid, hid: useHID)
    }

    private func check(_ job: Job) throws {
        if cancelled.contains(job.requestId) { throw Stop(status: "cancelled", detail: "cancelled_by_agent") }
    }
}

// MARK: - accessibility helpers

enum AX {
    static func value(_ el: AXUIElement, _ name: String) -> CFTypeRef? {
        var v: CFTypeRef?
        return AXUIElementCopyAttributeValue(el, name as CFString, &v) == .success ? v : nil
    }

    static func string(_ el: AXUIElement, _ name: String) -> String? { value(el, name) as? String }

    static func children(_ el: AXUIElement) -> [AXUIElement] {
        (value(el, kAXChildrenAttribute) as? [AXUIElement]) ?? []
    }

    /// Depth-first in document order.
    static func walk(_ root: AXUIElement, limit: Int, _ visit: (AXUIElement, String, String?) -> Void) {
        var stack = [root], n = 0
        while let el = stack.popLast(), n < limit {
            n += 1
            let role = string(el, kAXRoleAttribute) ?? ""
            visit(el, role, string(el, kAXSubroleAttribute))
            stack.append(contentsOf: children(el).reversed())
        }
    }

    static func frontWebArea(_ app: AXUIElement) -> AXUIElement? {
        guard let win = value(app, kAXFocusedWindowAttribute) else { return nil }
        var found: AXUIElement?
        walk(win as! AXUIElement, limit: 400) { el, role, _ in
            if found == nil && role == "AXWebArea" { found = el }
        }
        return found
    }

    /// The innermost web area (page or frame) holding `el`.
    static func webArea(containing el: AXUIElement) -> AXUIElement? {
        var cur: AXUIElement? = el
        for _ in 0..<200 {
            guard let c = cur else { return nil }
            if string(c, kAXRoleAttribute) == "AXWebArea" { return c }
            cur = value(c, kAXParentAttribute).map { $0 as! AXUIElement }
        }
        return nil
    }

    static func origin(of area: AXUIElement) -> String? {
        guard let url = value(area, "AXURL") as? URL, let scheme = url.scheme?.lowercased(), let host = url.host?.lowercased(),
              scheme == "https" || scheme == "http" else { return nil }
        let defaultPort = scheme == "https" ? 443 : 80
        return "\(scheme)://\(host)" + (url.port.map { $0 == defaultPort ? "" : ":\($0)" } ?? "")
    }

    static func isFocused(_ el: AXUIElement, in app: AXUIElement) -> Bool {
        guard let f = value(app, kAXFocusedUIElementAttribute) else { return false }
        return CFEqual(f, el)
    }

    private static func label(_ el: AXUIElement) -> String {
        [kAXTitleAttribute, kAXDescriptionAttribute, kAXPlaceholderValueAttribute, kAXHelpAttribute, "AXDOMIdentifier"]
            .compactMap { string(el, $0) }.joined(separator: " ").lowercased()
    }

    static func looksLikeUsername(_ el: AXUIElement) -> Bool {
        let l = label(el)
        return ["email", "e-mail", "user", "login", "account", "identifier", "phone"].contains { l.contains($0) }
    }

    static func looksLikeCode(_ el: AXUIElement) -> Bool {
        let l = label(el)
        return ["code", "otp", "verification", "authenticator", "2fa", "token", "digit"].contains { l.contains($0) }
    }
}

enum Keys {
    private static let src = CGEventSource(stateID: .privateState)

    private static func post(_ e: CGEvent, pid: pid_t, hid: Bool) {
        if hid { e.post(tap: .cghidEventTap) } else { e.postToPid(pid) }
    }

    static func type(_ ch: Character, pid: pid_t, hid: Bool) {
        let units = Array(String(ch).utf16)
        for down in [true, false] {
            guard let e = CGEvent(keyboardEventSource: src, virtualKey: 0, keyDown: down) else { continue }
            units.withUnsafeBufferPointer { e.keyboardSetUnicodeString(stringLength: units.count, unicodeString: $0.baseAddress) }
            post(e, pid: pid, hid: hid)
        }
    }

    private static func key(_ code: CGKeyCode, flags: CGEventFlags = [], pid: pid_t, hid: Bool) {
        for down in [true, false] {
            guard let e = CGEvent(keyboardEventSource: src, virtualKey: code, keyDown: down) else { continue }
            e.flags = flags
            post(e, pid: pid, hid: hid)
        }
    }

    static func returnKey(pid: pid_t, hid: Bool) { key(0x24, pid: pid, hid: hid) }

    static func selectAllAndDelete(pid: pid_t, hid: Bool) {
        key(0x00, flags: .maskCommand, pid: pid, hid: hid)   // Cmd-A
        key(0x33, pid: pid, hid: hid)                        // Delete
    }
}

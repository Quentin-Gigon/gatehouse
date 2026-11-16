import Foundation

// What the broker's admin API returns (snake_case keys, decoded with .convertFromSnakeCase).
// Nothing here ever carries a password or TOTP secret: the API does not return them.

struct Account: Codable, Identifiable, Hashable {
    var accountId: String
    var name: String
    var username: String
    var origins: [String]
    var hasTotp: Bool
    var loginUrl: String
    var importedUrl: String
    var preClick: [String]
    var successSelector: String
    var failures: Int
    var id: String { accountId }

    /// "goodreads.com" for "https://www.goodreads.com"
    var host: String {
        let o = origins.first ?? importedUrl
        let h = URL(string: o)?.host ?? o
        return h.hasPrefix("www.") ? String(h.dropFirst(4)) : h
    }
}

struct Agent: Codable, Identifiable, Hashable {
    var id: String
    var name: String
    var createdAt: Double
    var revokedAt: Double?
    var active: Bool { revokedAt == nil }
    var displayName: String { Harness.byAgentName[name]?.title ?? name }
}

struct Grant: Codable, Identifiable, Hashable {
    var id: String
    var agentId: String
    var accountId: String
    var origins: [String]
    var kind: String
    var expiresAt: Double?
    var usedCount: Int
    var state: String
}

struct Approval: Codable, Identifiable, Hashable {
    var id: String
    var agentId: String
    var agent: String
    var accountId: String
    var account: String
    var origin: String
    var createdAt: Double
}

struct HandoffInfo: Codable, Identifiable, Hashable {
    var token: String
    var code: String
    var requestId: String
    var agentId: String
    var accountId: String
    var origin: String
    var createdAt: Double
    var url: String
    var agent: String
    var account: String
    var id: String { token }
}

struct Overview: Codable {
    var accounts: [Account]
    var agents: [Agent]
    var grants: [Grant]
    var approvals: [Approval]
    var handoffs: [HandoffInfo]
    var loginsDisabled: Bool

    static let empty = Overview(accounts: [], agents: [], grants: [], approvals: [], handoffs: [], loginsDisabled: false)

    func activeAgent(named name: String) -> Agent? { agents.first { $0.name == name && $0.active } }

    func activeGrant(agent: String, account: String) -> Grant? {
        grants.last { $0.agentId == agent && $0.accountId == account && $0.state == "active" }
    }
}

struct Attention: Codable, Equatable {
    struct Waiting: Codable, Equatable, Hashable {
        var requestId: String
        var agent: String
        var account: String
        var origin: String
    }
    var running: Bool
    var vaultUnlocked: Bool
    var handoffs: [Waiting]
    var approvals: Int
    var loginsDisabled: Bool

    var count: Int { handoffs.count + approvals }
}

struct ActivityRow: Codable, Identifiable, Hashable {
    var ts: Double
    var action: String
    var agent: String?
    var account: String?
    var origin: String?
    var decision: String?
    var result: String?
    var id: String { "\(ts)-\(action)-\(agent ?? "")-\(account ?? "")" }
}

struct ImportPreview: Codable {
    struct Entry: Codable, Identifiable, Hashable {
        var index: Int
        var name: String
        var username: String
        var url: String
        var totp: String
        var problems: [String]
        var hasPassword: Bool
        var id: Int { index }
    }
    var format: String
    var entries: [Entry]
}

struct ImportResult: Codable {
    var imported: [String]
    var replaced: [String]
    var skipped: [String]
    var notes: [String]
}

/// The agent apps Gatehouse knows how to connect.
struct Harness: Identifiable, Hashable {
    let agentName: String      // the agent identity registered with the broker
    let title: String
    let detail: String
    let symbol: String
    var id: String { agentName }

    static let all: [Harness] = [
        Harness(agentName: "claude-code", title: "Claude Code",
                detail: "Terminal, desktop Code tab, and T3 Code sessions that use it", symbol: "terminal"),
        Harness(agentName: "codex", title: "Codex",
                detail: "Codex CLI and app, and T3 Code sessions that use it", symbol: "chevron.left.forwardslash.chevron.right"),
        Harness(agentName: "claude-desktop", title: "Claude Desktop",
                detail: "Chats in the Claude desktop app", symbol: "bubble.left.and.bubble.right"),
    ]
    static let byAgentName = Dictionary(uniqueKeysWithValues: all.map { ($0.agentName, $0) })
}

enum AccessDuration: String, CaseIterable, Identifiable {
    case forever, session, once
    var id: String { rawValue }
    var label: String {
        switch self {
        case .forever: return "Always"
        case .session: return "Until Gatehouse restarts"
        case .once: return "One sign-in only"
        }
    }
}

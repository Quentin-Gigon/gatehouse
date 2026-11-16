import AppKit
import SwiftUI

@main
struct GatehouseApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) var delegate
    @StateObject private var model = AppModel()

    var body: some Scene {
        MenuBarExtra {
            MenuContent().environmentObject(model)
        } label: {
            Image(systemName: (model.attention?.count ?? 0) > 0 ? "exclamationmark.shield.fill" : "lock.shield")
        }

        Window("Gatehouse", id: "main") {
            MainView()
                .environmentObject(model)
                .frame(minWidth: 820, minHeight: 540)
        }
        .defaultSize(width: 960, height: 640)

        WindowGroup("Finish signing in", id: "handoff", for: String.self) { $token in
            if let token, let h = model.overview.handoffs.first(where: { $0.token == token }) {
                HandoffView(handoff: h).environmentObject(model)
            } else {
                ContentUnavailableView("This sign-in has finished", systemImage: "checkmark.circle",
                                       description: Text("Nothing is waiting for you here any more."))
                    .frame(width: 420, height: 260)
            }
        }
        .defaultSize(width: 1320, height: 980)
    }
}

final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        // First launch, or not installed yet: show the window instead of only a menu-bar icon.
        if !Paths.isInstalled || !UserDefaults.standard.bool(forKey: "launchedBefore") {
            UserDefaults.standard.set(true, forKey: "launchedBefore")
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.3) {
                NSApp.activate(ignoringOtherApps: true)
                for w in NSApp.windows where w.title == "Gatehouse" { w.makeKeyAndOrderFront(nil) }
            }
        }
    }
}

struct MenuContent: View {
    @EnvironmentObject var model: AppModel
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        switch model.service {
        case .notInstalled: Text("Gatehouse is not set up yet")
        case .notRunning: Text("Gatehouse service is not running")
        case .running:
            Text(model.attention?.loginsDisabled == true ? "Sign-ins are paused" : "Gatehouse is running")
        }
        if let a = model.attention {
            if !a.handoffs.isEmpty || a.approvals > 0 { Divider() }
            ForEach(a.handoffs, id: \.self) { h in
                Button("\(Harness.byAgentName[h.agent]?.title ?? h.agent) needs help signing in to \(h.account)…") {
                    show(); model.selection = .needsYou
                }
            }
            if a.approvals > 0 {
                Button("\(a.approvals) access request\(a.approvals == 1 ? "" : "s") waiting…") { show(); model.selection = .needsYou }
            }
        }
        Divider()
        Button("Open Gatehouse…") { show() }.keyboardShortcut("o")
        if model.unlocked { Button("Lock") { model.lock() } }
        Divider()
        Button("Quit Gatehouse") { NSApp.terminate(nil) }.keyboardShortcut("q")
    }

    private func show() {
        openWindow(id: "main")
        NSApp.activate(ignoringOtherApps: true)
    }
}

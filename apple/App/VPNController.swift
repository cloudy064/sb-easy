import Foundation
import NetworkExtension
import Combine

@MainActor final class VPNController: ObservableObject {
    @Published var state = StoreState()
    @Published var status: NEVPNStatus = .invalid
    @Published var live: LiveSnapshot?
    @Published var error: String?
    @Published var busy = false
    @Published var rollback = false
    private var manager: NETunnelProviderManager?
    private var observer: NSObjectProtocol?
    private var poller: Task<Void, Never>?
    private var lastForegroundRefresh = Date.distantPast
    private var lastStateRead = Date.distantPast
    var selected: Profile? { state.profiles.first { $0.id == state.selectedID } }
    var active: Bool { status == .connected || status == .connecting || status == .reasserting || status == .disconnecting }
    var statusText: String {
        switch status {
        case .connected: return "已连接"
        case .connecting: return "连接中"
        case .reasserting: return "正在恢复连接"
        case .disconnecting: return "正在断开"
        case .disconnected: return "未连接"
        default: return "尚未配置 VPN"
        }
    }
    init() {
        observer = NotificationCenter.default.addObserver(forName: .NEVPNStatusDidChange, object: nil, queue: .main) { [weak self] _ in
            Task { @MainActor in self?.status = self?.manager?.connection.status ?? .invalid }
        }
        poller = Task { [weak self] in
            await self?.load()
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: 2_000_000_000)
                guard !Task.isCancelled else { break }
                await self?.poll()
            }
        }
    }
    deinit { if let observer { NotificationCenter.default.removeObserver(observer) }; poller?.cancel() }
    func load() async {
        do {
            state = try await SecureStore.shared.state()
            let managers: [NETunnelProviderManager] = try await withCheckedThrowingContinuation { continuation in
                NETunnelProviderManager.loadAllFromPreferences { values, error in
                    if let error { continuation.resume(throwing: error) } else { continuation.resume(returning: values ?? []) }
                }
            }
            let bundle = Bundle.main.object(forInfoDictionaryKey: "SBTunnelBundle") as? String
            manager = managers.first { ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == bundle }
            status = manager?.connection.status ?? .invalid
        } catch { self.error = "无法加载 VPN 与安全配置" }
    }
    func run(_ operation: @escaping () async throws -> Void) {
        guard !busy else { return }
        busy = true; error = nil
        Task {
            defer { busy = false }
            do { try await operation() }
            catch let error as ClientError { self.error = error.localizedDescription }
            catch { self.error = "操作失败，请检查配置与系统权限" }
            if let updated = try? await SecureStore.shared.state() { state = updated }
        }
    }
    func selectProfile(_ id: String) { guard !active else { return }; run { try await SecureStore.shared.select(id) } }
    func connect() {
        guard let profile = selected, !active else { return }
        run {
            let (current, credentials) = try await SecureStore.shared.profile(profile.id)
            _ = try Core.runtime(current, credentials: credentials)
            let manager = self.manager ?? NETunnelProviderManager()
            guard let bundle = Bundle.main.object(forInfoDictionaryKey: "SBTunnelBundle") as? String else { throw ClientError.storage }
            let configuration = NETunnelProviderProtocol()
            configuration.providerBundleIdentifier = bundle; configuration.serverAddress = "sb-easy"
            configuration.providerConfiguration = ["profileID": profile.id]
            configuration.disconnectOnSleep = false
            manager.protocolConfiguration = configuration; manager.localizedDescription = "sb-easy · " + profile.name
            manager.isEnabled = true; manager.isOnDemandEnabled = false
            try await manager.saveToPreferences()
            try await manager.loadFromPreferences()
            self.manager = manager
            try manager.connection.startVPNTunnel()
            self.status = manager.connection.status
        }
    }
    func disconnect() { manager?.connection.stopVPNTunnel() }
    func refresh() {
        guard let id = selected?.id else { return }
        run {
            try await Repository.shared.refresh(id)
            if self.status == .connected { _ = try await self.message(ProviderRequest(action: "reload")) }
        }
    }
    func removeProfile() {
        guard let id = selected?.id, !active else { return }
        run { try await SecureStore.shared.remove(id) }
    }
    private func message(_ request: ProviderRequest) async throws -> ProviderReply {
        guard let session = manager?.connection as? NETunnelProviderSession, status == .connected else { throw ClientError.unavailable }
        let data = try JSONEncoder().encode(request)
        return try await withCheckedThrowingContinuation { continuation in
            let once = ReplyOnce(continuation)
            do {
                try session.sendProviderMessage(data) { response in
                    guard let response, response.count <= 300 * 1024,
                          let reply = try? JSONDecoder().decode(ProviderReply.self, from: response) else { once.finish(.failure(ClientError.response)); return }
                    if !reply.ok { once.finish(.failure(ClientError.invalid(reply.error ?? "操作失败"))) }
                    else { once.finish(.success(reply)) }
                }
                DispatchQueue.global().asyncAfter(deadline: .now() + 10) { once.finish(.failure(ClientError.unavailable)) }
            } catch { once.finish(.failure(ClientError.unavailable)) }
        }
    }
    private func poll() async {
        status = manager?.connection.status ?? .invalid
        if Date().timeIntervalSince(lastStateRead) >= 30 {
            lastStateRead = Date()
            if let current = try? await SecureStore.shared.state() { state = current }
        }
        guard status == .connected else {
            live = nil; rollback = false
            if !active && !busy, let id = selected?.id, Date().timeIntervalSince(lastForegroundRefresh) >= 60 {
                lastForegroundRefresh = Date()
                try? await Repository.shared.refresh(id, dueOnly: true)
                if let current = try? await SecureStore.shared.state() { state = current }
            }
            return
        }
        if let reply = try? await message(ProviderRequest(action: "state")) { live = reply.snapshot; rollback = reply.rollback ?? false }
        else { live = nil }
    }
    func select(group: String, target: String) {
        run {
            _ = try await self.message(ProviderRequest(action: "select", group: group, target: target))
            // libbox's per-profile cache persists selector choices. The C default
            // setting is only written through the explicit offline preferences UI.
            await self.poll()
        }
    }
    func probe(_ group: String) { run { _ = try await self.message(ProviderRequest(action: "probe", target: group)); await self.poll() } }
}

private final class ReplyOnce {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<ProviderReply, Error>?
    init(_ continuation: CheckedContinuation<ProviderReply, Error>) { self.continuation = continuation }
    func finish(_ result: Result<ProviderReply, Error>) {
        lock.lock(); let current = continuation; continuation = nil; lock.unlock()
        current?.resume(with: result)
    }
}

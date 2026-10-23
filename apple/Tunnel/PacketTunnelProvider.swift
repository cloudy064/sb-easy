import Foundation
import NetworkExtension

final class PacketTunnelProvider: NEPacketTunnelProvider {
    private let work = DispatchQueue(label: "io.sbeasy.tunnel.lifecycle")
    private var engine: SBEngine?
    private let interruptLock = NSLock()
    private var interruptEngine: SBEngine?
    private var profileID: String?
    private var activeRuntime: String?
    private var generation = UUID()
    private var operation: Task<Void, Never>?
    private var timer: DispatchSourceTimer?
    private var refreshing = false
    private var rolledBack = false

    override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        work.async {
            let token = UUID(); self.generation = token
            guard self.engine == nil,
                  let configuration = self.protocolConfiguration as? NETunnelProviderProtocol,
                  let id = configuration.providerConfiguration?["profileID"] as? String,
                  UUID(uuidString: id) != nil else { completionHandler(ClientError.invalid("未选择有效配置")); return }
            self.profileID = id
            self.operation = Task {
                do {
                    let (profile, credentials) = try await SecureStore.shared.profile(id)
                    try Task.checkCancellation()
                    let built = Result { try Core.runtime(profile, credentials: credentials) }
                    let candidate: String
                    let buildFailed: Bool
                    switch built {
                    case .success(let value): candidate = value; buildFailed = false
                    case .failure(let error):
                        guard let fallback = profile.lastGoodRuntime else { throw error }
                        candidate = fallback; buildFailed = true
                    }
                    let directory = try self.runtimeDirectory(id)
                    self.work.async {
                        guard self.generation == token else { completionHandler(CancellationError()); return }
                        let engine = SBEngine(provider: self)
                        self.interruptLock.lock(); self.interruptEngine = engine; self.interruptLock.unlock()
                        do {
                            do {
                                try engine.start(candidate, directory: directory)
                                self.rolledBack = buildFailed; self.activeRuntime = candidate
                            } catch {
                                guard let fallback = profile.lastGoodRuntime else { throw error }
                                try engine.start(fallback, directory: directory)
                                self.rolledBack = true; self.activeRuntime = fallback
                            }
                            self.engine = engine
                            if !self.rolledBack { self.recordGood(profile, runtime: candidate) }
                            self.startTimer()
                            completionHandler(nil)
                            let rollback = self.rolledBack
                            Task { await Repository.shared.report(id, connected: true, rolledBack: rollback) }
                        } catch {
                            engine.stop(); self.engine = nil; self.profileID = nil
                            completionHandler(ClientError.invalid("VPN 启动失败，未应用候选配置"))
                        }
                    }
                } catch {
                    self.work.async { completionHandler(error is CancellationError ? CancellationError() : ClientError.invalid("无法加载 VPN 配置")) }
                }
            }
        }
    }
    private func runtimeDirectory(_ id: String) throws -> URL {
        guard let group = Bundle.main.object(forInfoDictionaryKey: "SBAppGroup") as? String,
              let root = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: group) else { throw ClientError.storage }
        let directory = root.appendingPathComponent("Runtime", isDirectory: true).appendingPathComponent(id, isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        return directory
    }
    private func recordGood(_ profile: Profile, runtime: String) {
        Task {
            var next = profile; next.lastGoodRuntime = runtime; next.lastGoodETag = profile.sourceETag
            try? await SecureStore.shared.update(next, expectedRevision: profile.revision)
        }
    }
    private func startTimer() {
        timer?.cancel()
        let timer = DispatchSource.makeTimerSource(queue: work)
        timer.schedule(deadline: .now() + 60, repeating: 60, leeway: .seconds(5))
        timer.setEventHandler { [weak self] in self?.refresh(fetch: true, reply: nil) }
        self.timer = timer; timer.resume()
    }
    private func refresh(fetch: Bool, reply: ((Data?) -> Void)?) {
        guard let id = profileID, engine != nil, !refreshing else { reply?(encoded(ProviderReply(ok: false, error: "VPN 正忙"))); return }
        refreshing = true
        let token = generation
        Task {
            if fetch { try? await Repository.shared.refresh(id, dueOnly: true) }
            do {
                let (profile, credentials) = try await SecureStore.shared.profile(id)
                let candidate = try Core.runtime(profile, credentials: credentials)
                self.work.async {
                    defer { self.refreshing = false }
                    guard self.generation == token, let engine = self.engine else { reply?(self.encoded(ProviderReply(ok: false, error: "VPN 已停止"))); return }
                    do {
                        if candidate != self.activeRuntime {
                            do { try engine.reload(candidate); self.rolledBack = false }
                            catch {
                                guard let fallback = self.activeRuntime ?? profile.lastGoodRuntime else { throw error }
                                try engine.reload(fallback); self.rolledBack = true
                                reply?(self.encoded(ProviderReply(ok: false, error: "更新失败，已恢复上次配置", rollback: true)))
                                return
                            }
                            self.activeRuntime = candidate; self.recordGood(profile, runtime: candidate)
                        }
                        reply?(self.encoded(ProviderReply(ok: true, rollback: self.rolledBack)))
                        let rollback = self.rolledBack
                        Task { await Repository.shared.report(id, connected: true, rolledBack: rollback) }
                    } catch {
                        reply?(self.encoded(ProviderReply(ok: false, error: "配置更新与恢复均失败")))
                        self.cancelTunnelWithError(ClientError.unavailable)
                    }
                }
            } catch {
                self.work.async { self.refreshing = false; reply?(self.encoded(ProviderReply(ok: false, error: "配置加载失败，保留当前连接"))) }
            }
        }
    }
    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        interruptLock.lock(); let pending = interruptEngine; interruptLock.unlock()
        pending?.interrupt()
        work.async {
            self.generation = UUID(); self.operation?.cancel(); self.operation = nil
            self.timer?.cancel(); self.timer = nil
            let id = self.profileID
            self.engine?.stop(); self.engine = nil;
            self.interruptLock.lock(); self.interruptEngine = nil; self.interruptLock.unlock(); self.profileID = nil; self.activeRuntime = nil; self.refreshing = false
            completionHandler()
            if let id { Task { await Repository.shared.report(id, connected: false, rolledBack: false) } }
        }
    }
    private func encoded(_ reply: ProviderReply) -> Data? { try? JSONEncoder().encode(reply) }
    override func handleAppMessage(_ data: Data, completionHandler: ((Data?) -> Void)? = nil) {
        guard data.count <= 16 * 1024, let request = try? JSONDecoder().decode(ProviderRequest.self, from: data) else {
            completionHandler?(encoded(ProviderReply(ok: false, error: "请求无效"))); return
        }
        work.async {
            guard let engine = self.engine else { completionHandler?(self.encoded(ProviderReply(ok: false, error: "VPN 未连接"))); return }
            do {
                switch request.action {
                case "state":
                    let raw = try engine.snapshot()
                    let state = try JSONDecoder().decode(LiveSnapshot.self, from: Data(raw.utf8))
                    completionHandler?(self.encoded(ProviderReply(ok: true, snapshot: state, rollback: self.rolledBack)))
                case "reload": self.refresh(fetch: false, reply: completionHandler)
                case "select":
                    guard let group = request.group, let target = request.target, group.utf8.count <= 512, target.utf8.count <= 512 else { throw ClientError.response }
                    try engine.select(group, target: target)
                    completionHandler?(self.encoded(ProviderReply(ok: true)))
                case "probe":
                    guard let target = request.target, target.utf8.count <= 512 else { throw ClientError.response }
                    try engine.probe(target)
                    completionHandler?(self.encoded(ProviderReply(ok: true)))
                default: throw ClientError.response
                }
            } catch { completionHandler?(self.encoded(ProviderReply(ok: false, error: "操作失败，请检查当前节点与连接"))) }
        }
    }
    override func sleep(completionHandler: @escaping () -> Void) { work.async { self.engine?.pause(); completionHandler() } }
    override func wake() { work.async { self.engine?.wake() } }
}

import Foundation

final class NoRedirect: NSObject, URLSessionTaskDelegate {
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) { completionHandler(nil) }
}
struct HTTPResult { let status: Int; let data: Data; let headers: HTTPURLResponse }
enum HTTPS {
    static func url(_ raw: String, server: Bool = false) throws -> URL {
        guard raw.utf8.count <= 4096, !raw.contains("\\"), !raw.unicodeScalars.contains(where: { $0.value < 33 || $0.value == 127 }),
              let parts = URLComponents(string: raw), parts.scheme == "https", parts.user == nil, parts.password == nil,
              parts.fragment == nil, let host = parts.host, !host.isEmpty,
              (!server || parts.query == nil), let url = parts.url else { throw ClientError.invalid("请输入有效 HTTPS 地址") }
        return url
    }
    static func request(_ url: URL, method: String = "GET", token: String? = nil, etag: String? = nil,
                        body: Data? = nil, limit: Int = 1024 * 1024) async throws -> HTTPResult {
        let config = URLSessionConfiguration.ephemeral
        config.httpShouldSetCookies = false; config.httpCookieStorage = nil; config.urlCache = nil; config.urlCredentialStorage = nil
        config.timeoutIntervalForRequest = 20; config.timeoutIntervalForResource = 30
        let delegate = NoRedirect()
        let session = URLSession(configuration: config, delegate: delegate, delegateQueue: nil)
        defer { session.invalidateAndCancel() }
        var request = URLRequest(url: url)
        request.httpMethod = method; request.httpBody = body
        request.setValue("sb-easy-apple/1", forHTTPHeaderField: "User-Agent")
        request.setValue("no-store", forHTTPHeaderField: "Cache-Control")
        if body != nil { request.setValue("application/json", forHTTPHeaderField: "Content-Type") }
        if let token { request.setValue("Bearer " + token, forHTTPHeaderField: "Authorization") }
        if let etag { request.setValue(etag, forHTTPHeaderField: "If-None-Match") }
        do {
            let (bytes, response) = try await session.bytes(for: request)
            guard let http = response as? HTTPURLResponse, response.expectedContentLength <= Int64(limit) else { throw ClientError.response }
            var data = Data()
            for try await byte in bytes {
                try Task.checkCancellation()
                guard data.count < limit else { throw ClientError.response }
                data.append(byte)
            }
            return HTTPResult(status: http.statusCode, data: data, headers: http)
        } catch is CancellationError { throw CancellationError() }
        catch let error as ClientError { throw error }
        catch { throw ClientError.network }
    }
    static func endpoint(_ credentials: Credentials, _ path: String) throws -> URL {
        guard let server = credentials.server, let token = credentials.token, !token.isEmpty else { throw ClientError.storage }
        return try url(server.trimmingCharacters(in: CharacterSet(charactersIn: "/")) + path)
    }
}

actor Repository {
    static let shared = Repository()
    private let store: SecureStore
    private var refreshing: Set<String> = []
    init(store: SecureStore = .shared) { self.store = store }
    func enroll(_ raw: String, name: String) async throws {
        guard raw.utf8.count <= 8192, let link = URLComponents(string: raw), link.scheme == "sbeasy", link.host == "enroll",
              link.path.isEmpty, link.port == nil,
              link.user == nil, link.password == nil, link.fragment == nil,
              let query = link.queryItems, query.count == 2,
              query.filter({ $0.name == "server" }).count == 1, query.filter({ $0.name == "code" }).count == 1,
              let server = query.first(where: { $0.name == "server" })?.value,
              let code = query.first(where: { $0.name == "code" })?.value, code.count == 64,
              code.allSatisfy({ $0.isHexDigit && $0.isASCII }) else { throw ClientError.invalid("注册链接无效") }
        let base = try HTTPS.url(server, server: true).absoluteString.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        let body = try JSONSerialization.data(withJSONObject: ["code": code,
            "device": ["hostname": name.isEmpty ? "Apple" : String(name.prefix(80)), "platform": Self.platform, "app_version": Self.appVersion, "core_version": Self.coreVersion, "interactive_client": true, "supports_proxy_selection": true, "supports_local_route_stats": false, "supports_diagnostic_upload": false]])
        let response = try await HTTPS.request(try HTTPS.url(base + "/api/devices/enroll"), method: "POST", body: body, limit: 64 * 1024)
        guard response.status == 200 || response.status == 201,
              let data = try JSONSerialization.jsonObject(with: response.data) as? [String: Any],
              let token = data["agent_token"] as? String, !token.isEmpty, token.utf8.count <= 4096,
              token.utf8.allSatisfy({ $0 > 32 && $0 < 127 }), let host = data["host_id"] as? String, !host.isEmpty, host.utf8.count <= 128,
              let remoteProfile = data["profile"] as? [String: Any] else { throw ClientError.response }
        if let returned = data["server"] as? String {
            guard try HTTPS.url(returned, server: true).absoluteString.trimmingCharacters(in: CharacterSet(charactersIn: "/")) == base else { throw ClientError.response }
        }
        let credentials = Credentials(server: base, hostID: host, token: token)
        var profile = Profile(name: name.isEmpty ? (remoteProfile["name"] as? String ?? "管理配置") : String(name.prefix(80)), mode: .managed)
        // Enrollment consumes a one-time code. Preserve the returned identity
        // before fetching configuration so a transient outage remains recoverable.
        try await store.add(profile, credentials: credentials)
        do {
            try await fetchConfig(&profile, credentials: credentials)
            _ = try Core.runtime(profile, credentials: credentials)
            try await store.update(profile, expectedRevision: profile.revision)
        } catch { throw ClientError.invalid("注册成功，暂未取得可用配置；请稍后刷新") }
    }
    static var appVersion: String { Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "0.1.0" }
    static var coreVersion: String { Bundle.main.object(forInfoDictionaryKey: "SBCoreVersion") as? String ?? "unknown" }
    static var platform: String {
        #if os(iOS)
        return "ios"
        #elseif os(tvOS)
        return "tvos"
        #else
        return "macos"
        #endif
    }
    private func fetchConfig(_ profile: inout Profile, credentials: Credentials) async throws {
        let response = try await HTTPS.request(HTTPS.endpoint(credentials, "/api/agent/config"), token: credentials.token, etag: profile.sourceETag)
        if response.status == 304 && profile.sourceConfig != nil { return }
        guard response.status == 200, !response.data.contains(0), let text = String(data: response.data, encoding: .utf8) else { throw ClientError.response }
        var candidate = profile
        candidate.sourceConfig = text
        if let etag = response.headers.value(forHTTPHeaderField: "ETag"), etag.utf8.count <= 512, etag.utf8.allSatisfy({ $0 >= 32 && $0 != 127 }) { candidate.sourceETag = etag }
        else { candidate.sourceETag = nil }
        _ = try Core.runtime(candidate, credentials: credentials)
        profile = candidate
    }
    func createIndependent(name: String, content: String, remote: Bool) async throws {
        var profile = Profile(name: name.isEmpty ? "独立配置" : String(name.prefix(80)), mode: .independent)
        var credentials = Credentials()
        let sub = try await imported(name: "订阅", content: content, remote: remote)
        profile.subscriptions = [sub]
        if remote { credentials.subscriptionURLs[sub.id] = try HTTPS.url(content).absoluteString }
        _ = try Core.runtime(profile, credentials: credentials)
        try await store.add(profile, credentials: credentials)
    }
    private func imported(name: String, content: String, remote: Bool) async throws -> Subscription {
        let data: Data, header: String?
        if remote {
            let response = try await HTTPS.request(HTTPS.url(content), limit: 512 * 1024)
            guard response.status == 200 else { throw ClientError.response }
            data = response.data; header = response.headers.value(forHTTPHeaderField: "Subscription-Userinfo")
        } else { data = Data(content.utf8); header = nil }
        let (nodes, report) = try Core.imported(data)
        return Subscription(name: name.isEmpty ? "订阅" : String(name.prefix(80)), nodesJSON: nodes, report: report,
            metadata: try Core.metadata(header), remote: remote, refreshMinutes: remote ? 360 : 0,
            lastAttempt: Date(), lastSuccess: Date(), nextRefresh: remote ? Date().addingTimeInterval(21600) : nil)
    }
    func addSubscription(profileID: String, name: String, content: String, remote: Bool) async throws {
        var (profile, credentials) = try await store.profile(profileID)
        guard profile.subscriptions.count < 32 else { throw ClientError.invalid("订阅数量已达上限") }
        let sub = try await imported(name: name, content: content, remote: remote)
        profile.subscriptions.append(sub)
        if remote { credentials.subscriptionURLs[sub.id] = try HTTPS.url(content).absoluteString }
        _ = try Core.runtime(profile, credentials: credentials)
        try await store.update(profile, expectedRevision: profile.revision, credentials: credentials)
    }
    func refresh(_ id: String, dueOnly: Bool = false) async throws {
        guard refreshing.insert(id).inserted else { throw ClientError.invalid("正在刷新此配置，请稍后重试") }
        defer { refreshing.remove(id) }
        var (profile, credentials) = try await store.profile(id)
        let revision = profile.revision
        var failed = false
        if profile.mode == .managed { try await fetchConfig(&profile, credentials: credentials) }
        for index in profile.subscriptions.indices {
            let old = profile.subscriptions[index]
            guard old.remote, let url = credentials.subscriptionURLs[old.id],
                  !dueOnly || (old.refreshMinutes > 0 && (old.nextRefresh ?? .distantPast) <= Date()) else { continue }
            do {
                var next = try await imported(name: old.name, content: url, remote: true)
                next.id = old.id; next.refreshMinutes = old.refreshMinutes
                next.nextRefresh = old.refreshMinutes > 0 ? Date().addingTimeInterval(Double(old.refreshMinutes * 60)) : nil
                var candidate = profile; candidate.subscriptions[index] = next
                _ = try Core.runtime(candidate, credentials: credentials)
                profile = candidate
            } catch is CancellationError { throw CancellationError() }
            catch {
                failed = true
                profile.subscriptions[index].lastAttempt = Date()
                profile.subscriptions[index].lastError = "刷新失败；保留上次可用节点"
                profile.subscriptions[index].failures = min(old.failures + 1, 7)
                profile.subscriptions[index].nextRefresh = Date().addingTimeInterval(min(3600, 60 * pow(2, Double(min(old.failures, 6)))))
            }
        }
        _ = try Core.runtime(profile, credentials: credentials)
        try await store.update(profile, expectedRevision: revision)
        if failed && !dueOnly { throw ClientError.invalid("部分订阅刷新失败，已保留原配置") }
    }
    func refreshInterval(profileID: String, subscriptionID: String, minutes: Int) async throws {
        guard minutes == 0 || (15...10080).contains(minutes) else { throw ClientError.invalid("刷新间隔须为 15 分钟到 7 天，或关闭自动刷新") }
        var (profile, _) = try await store.profile(profileID)
        guard let index = profile.subscriptions.firstIndex(where: { $0.id == subscriptionID }), profile.subscriptions[index].remote else { throw ClientError.stale }
        profile.subscriptions[index].refreshMinutes = minutes
        profile.subscriptions[index].nextRefresh = minutes > 0 ? Date().addingTimeInterval(Double(minutes * 60)) : nil
        try await store.update(profile, expectedRevision: profile.revision)
    }
    func removeSubscription(profileID: String, subscriptionID: String) async throws {
        var (profile, credentials) = try await store.profile(profileID)
        profile.subscriptions.removeAll { $0.id == subscriptionID }
        credentials.subscriptionURLs.removeValue(forKey: subscriptionID)
        _ = try Core.runtime(profile, credentials: credentials)
        try await store.update(profile, expectedRevision: profile.revision, credentials: credentials)
    }
    func preferences(_ value: Preferences, profileID: String) async throws {
        try Core.validate(value)
        var (profile, credentials) = try await store.profile(profileID)
        profile.preferences = value
        _ = try Core.runtime(profile, credentials: credentials)
        try await store.update(profile, expectedRevision: profile.revision)
    }
    func report(_ id: String, connected: Bool, rolledBack: Bool) async {
        guard let (profile, credentials) = try? await store.profile(id), profile.mode == .managed else { return }
        do {
            let body = try JSONSerialization.data(withJSONObject: ["singbox_running": connected, "singbox_version": Self.coreVersion, "app_version": Self.appVersion,
                "config_etag": profile.lastGoodETag ?? "", "last_error": rolledBack ? "Candidate rejected; last successful configuration restored" : ""])
            _ = try await HTTPS.request(HTTPS.endpoint(credentials, "/api/agent/status"), method: "POST", token: credentials.token, body: body, limit: 64 * 1024)
        } catch { /* A control-plane outage must not replace a working tunnel. */ }
    }
}

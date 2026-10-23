import Foundation
import SBEasyCore

enum ClientError: LocalizedError {
    case invalid(String), unavailable, stale, storage, network, response
    var errorDescription: String? {
        switch self {
        case .invalid(let message): return message
        case .unavailable: return "服务暂不可用"
        case .stale: return "配置已更新，请重试"
        case .storage: return "无法读取安全存储；请检查设备解锁状态与应用权限"
        case .network: return "网络请求失败，请检查 HTTPS 服务与网络连接"
        case .response: return "服务响应无效"
        }
    }
}

enum ProfileMode: String, Codable { case managed, independent }
struct LocalGroup: Codable, Identifiable {
    var id = UUID().uuidString.lowercased()
    var name: String
    var domains: [String]
    var outbound: String
}
struct Preferences: Codable {
    var selected_tag: String?
    var local_groups: [LocalGroup] = []
}
struct ImportReport: Codable { var imported: Int; var skipped: Int; var notice: String; var warnings: [String]? }
struct Quota: Codable {
    var available: Bool
    var used_bytes: Double?
    var total_bytes: Double?
    var remaining_bytes: Double?
    var expires_at: Double?
    var expired: Bool?
    var quota_exhausted: Bool?
}
struct Subscription: Codable, Identifiable {
    var id = UUID().uuidString.lowercased()
    var name: String
    var nodesJSON: String
    var report: ImportReport
    var metadata: Quota
    var remote: Bool
    var refreshMinutes: Int = 360
    var lastAttempt: Date?
    var lastSuccess: Date?
    var nextRefresh: Date?
    var lastError: String?
    var failures = 0
}
struct Profile: Codable, Identifiable {
    var id = UUID().uuidString.lowercased()
    var name: String
    var mode: ProfileMode
    var credentialRef = UUID().uuidString.lowercased()
    var sourceConfig: String?
    var sourceETag: String?
    var subscriptions: [Subscription] = []
    var preferences = Preferences()
    var lastGoodRuntime: String?
    var lastGoodETag: String?
    var revision = 0
    var updatedAt = Date()
}
struct Credentials: Codable {
    var server: String?
    var hostID: String?
    var token: String?
    var subscriptionURLs: [String: String] = [:]
}
struct StoreState: Codable {
    var version = 1
    var profiles: [Profile] = []
    var selectedID: String?
}
struct LiveItem: Codable, Identifiable {
    var tag: String; var type: String; var delay_ms: Int?; var checked_at: Int64?
    var id: String { tag }
}
struct LiveGroup: Codable, Identifiable {
    var tag: String; var type: String; var selected: String; var selectable: Bool; var items: [LiveItem]
    var id: String { tag }
}
struct LiveSnapshot: Codable {
    var traffic_available: Bool
    var upload_total: Int64
    var download_total: Int64
    var connections: Int64
    var memory_bytes: Int64
    var groups: [LiveGroup]
}
struct ProviderRequest: Codable { var action: String; var group: String?; var target: String? }
struct ProviderReply: Codable { var ok: Bool; var error: String?; var snapshot: LiveSnapshot?; var rollback: Bool? }

enum Core {
    static func string(_ operation: (UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>) -> UnsafeMutablePointer<CChar>?) throws -> String {
        var failure: UnsafeMutablePointer<CChar>?
        let result = operation(&failure)
        defer { if let result { sba_free(result) }; if let failure { sba_free(failure) } }
        guard let result else { throw ClientError.invalid(failure.map { String(cString: $0) } ?? "配置无效") }
        return String(cString: result)
    }
    static func json<T: Encodable>(_ value: T) throws -> String {
        String(decoding: try JSONEncoder().encode(value), as: UTF8.self)
    }
    static func imported(_ body: Data) throws -> (String, ImportReport) {
        let result = try body.withUnsafeBytes { bytes in
            try string { sba_import_subscription(bytes.bindMemory(to: CChar.self).baseAddress, body.count, $0) }
        }
        guard let data = result.data(using: .utf8), let object = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let nodes = object["nodes"], let report = object["report"] else { throw ClientError.response }
        let nodesData = try JSONSerialization.data(withJSONObject: nodes, options: [.sortedKeys])
        let reportData = try JSONSerialization.data(withJSONObject: report)
        return (String(decoding: nodesData, as: UTF8.self), try JSONDecoder().decode(ImportReport.self, from: reportData))
    }
    static func metadata(_ header: String?) throws -> Quota {
        guard let raw = sba_subscription_metadata(header ?? "", Int64(Date().timeIntervalSince1970)) else { throw ClientError.response }
        defer { sba_free(raw) }
        return try JSONDecoder().decode(Quota.self, from: Data(String(cString: raw).utf8))
    }
    static func validate(_ preferences: Preferences) throws {
        let value = try json(preferences)
        _ = try string { sba_validate_settings(value, $0) }
    }
    static func runtime(_ profile: Profile, credentials: Credentials) throws -> String {
        let subscriptions = try profile.subscriptions.map { sub -> [String: Any] in
            ["id": sub.id, "nodes": try JSONSerialization.jsonObject(with: Data(sub.nodesJSON.utf8))]
        }
        let subs = String(decoding: try JSONSerialization.data(withJSONObject: subscriptions), as: UTF8.self)
        let settings = try json(profile.preferences)
        let host = (credentials.server.flatMap { URLComponents(string: $0)?.host } ?? "").trimmingCharacters(in: CharacterSet(charactersIn: "[]")).lowercased()
        return try string { error in
            if let source = profile.sourceConfig, profile.mode == .managed {
                return sba_build_runtime(source, subs, settings, host, error)
            }
            if profile.mode == .managed { return nil }
            return sba_build_runtime(nil, subs, settings, "", error)
        }
    }
    static func outboundTags(_ runtime: String) throws -> [String] {
        let root = try JSONSerialization.jsonObject(with: Data(runtime.utf8)) as? [String: Any]
        return (root?["outbounds"] as? [[String: Any]] ?? []).compactMap { node in
            guard let type = node["type"] as? String, type != "selector", type != "urltest" else { return nil }
            return node["tag"] as? String
        }
    }
}

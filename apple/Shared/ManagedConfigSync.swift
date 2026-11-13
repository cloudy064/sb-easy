import Foundation
import CoreFoundation

// Encrypted cache and durable outbox. Versions always come from the server.
struct ManagedConfigSync: Codable {
    var remote: String?
    var pendingPolicy: String?
    var expectedBase: Int64?
    var expectedPatch: Int64?
    var conflict = false

    static func object(_ text: String) throws -> [String: Any] {
        guard text.utf8.count <= 8 * 1024 * 1024,
              let object = try JSONSerialization.jsonObject(with: Data(text.utf8)) as? [String: Any] else { throw ClientError.response }
        return object
    }
    static func encoded(_ value: [String: Any]) throws -> String {
        String(decoding: try JSONSerialization.data(withJSONObject: value, options: [.sortedKeys]), as: UTF8.self)
    }
    static func version(_ state: [String: Any], _ key: String) throws -> Int64 {
        guard let value = state[key] as? NSNumber, CFGetTypeID(value) != CFBooleanGetTypeID(),
              value.doubleValue >= 0, value.doubleValue <= 9_007_199_254_740_991,
              value.doubleValue == Double(value.int64Value) else { throw ClientError.response }
        return value.int64Value
    }
    static func validated(_ text: String) throws -> [String: Any] {
        let value = try object(text)
        guard try version(value, "base_version") > 0,
              value["base"] is [String: Any], value["config"] is [String: Any],
              value["patch"] is [String: Any], value["agent_settings"] is [String: Any] else { throw ClientError.response }
        _ = try version(value, "patch_version")
        return value
    }
    static func policy(in state: [String: Any]) throws -> String {
        let settings = state["agent_settings"] as? [String: Any] ?? [:]
        guard settings["apple"] == nil || settings["apple"] is [String: Any] else { throw ClientError.response }
        return try encoded(settings["apple"] as? [String: Any] ?? [:])
    }
    mutating func queue(_ policy: String) throws {
        let policy = try Self.encoded(Self.object(policy))
        if pendingPolicy == nil, let remote, try Self.policy(in: Self.validated(remote)) == policy {
            pendingPolicy = nil; expectedBase = nil; expectedPatch = nil; conflict = false
            return
        }
        if pendingPolicy == nil, let remote {
            let state = try Self.validated(remote)
            expectedBase = try Self.version(state, "base_version")
            expectedPatch = try Self.version(state, "patch_version")
        }
        pendingPolicy = policy
    }
    mutating func observe(_ text: String) throws {
        let state = try Self.validated(text)
        let base = try Self.version(state, "base_version"), patch = try Self.version(state, "patch_version")
        if let pendingPolicy {
            if try Self.policy(in: state) == pendingPolicy {
                self.pendingPolicy = nil; expectedBase = nil; expectedPatch = nil; conflict = false
            } else if expectedBase == nil {
                expectedBase = base; expectedPatch = patch
                let serverPolicy = try Self.policy(in: state)
                conflict = (state["agent_settings_initialized"] as? Bool == true) || serverPolicy != "{}"
            } else { conflict = expectedBase != base || expectedPatch != patch }
        }
        remote = try Self.encoded(state)
    }
    func request() throws -> Data? {
        guard let remote, let pendingPolicy, !conflict, let expectedBase, let expectedPatch else { return nil }
        let state = try Self.validated(remote)
        var settings = state["agent_settings"] as? [String: Any] ?? [:]
        let policy = try Self.object(pendingPolicy)
        if policy.isEmpty { settings.removeValue(forKey: "apple") } else { settings["apple"] = policy }
        return try JSONSerialization.data(withJSONObject: ["base_version": expectedBase, "patch_version": expectedPatch,
            "patch": state["patch"] ?? [:], "agent_settings": settings])
    }
    mutating func resolve(keepLocal: Bool) throws {
        guard let remote else { throw ClientError.stale }
        let state = try Self.validated(remote)
        if keepLocal {
            expectedBase = try Self.version(state, "base_version")
            expectedPatch = try Self.version(state, "patch_version")
        } else if pendingPolicy != nil {
            // Keep an explicit undo until the previous network cycle finishes.
            pendingPolicy = try Self.policy(in: state)
            expectedBase = try Self.version(state, "base_version")
            expectedPatch = try Self.version(state, "patch_version")
        } else { expectedBase = nil; expectedPatch = nil }
        conflict = false
    }
}

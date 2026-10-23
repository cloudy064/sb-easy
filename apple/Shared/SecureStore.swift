import Foundation
import Security
import CryptoKit
import Darwin

protocol SecretStore {
    func get(_ account: String) throws -> Data?
    func insert(_ account: String, data: Data) throws
    func remove(_ account: String) throws
}

final class Keychain: SecretStore {
    private let group: String?
    init(group: String? = Bundle.main.object(forInfoDictionaryKey: "SBKeychainGroup") as? String) { self.group = group }
    private func query(_ account: String) -> [String: Any] {
        var query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "io.sbeasy.client.v1", kSecAttrAccount as String: account,
            kSecAttrSynchronizable as String: false]
        if let group, !group.isEmpty { query[kSecAttrAccessGroup as String] = group }
        return query
    }
    func get(_ account: String) throws -> Data? {
        var query = query(account)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var value: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &value)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = value as? Data else { throw ClientError.storage }
        return data
    }
    func insert(_ account: String, data: Data) throws {
        var query = query(account)
        query[kSecValueData as String] = data
        query[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        guard SecItemAdd(query as CFDictionary, nil) == errSecSuccess else { throw ClientError.storage }
    }
    func remove(_ account: String) throws {
        let status = SecItemDelete(query(account) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else { throw ClientError.storage }
    }
}

actor SecureStore {
    static let shared = SecureStore()
    private let keychain: any SecretStore
    private let directory: URL?
    init(directory: URL? = nil, keychain: any SecretStore = Keychain()) {
        self.keychain = keychain
        if let directory { self.directory = directory }
        else if let group = Bundle.main.object(forInfoDictionaryKey: "SBAppGroup") as? String {
            self.directory = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: group)?.appendingPathComponent("Vault", isDirectory: true)
        } else { self.directory = nil }
    }
    private func locked<T>(_ body: (URL, SymmetricKey) throws -> T) throws -> T {
        guard let directory else { throw ClientError.storage }
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let lock = directory.appendingPathComponent("state.lock")
        let fd = open(lock.path, O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0o600)
        guard fd >= 0 else { throw ClientError.storage }
        defer { flock(fd, LOCK_UN); close(fd) }
        guard flock(fd, LOCK_EX) == 0 else { throw ClientError.storage }
        let keyData: Data
        if let saved = try keychain.get("vault-key") { keyData = saved }
        else {
            var bytes = Data(count: 32)
            let ok = bytes.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, $0.count, $0.baseAddress!) }
            guard ok == errSecSuccess else { throw ClientError.storage }
            try keychain.insert("vault-key", data: bytes)
            keyData = bytes
        }
        guard keyData.count == 32 else { throw ClientError.storage }
        return try body(directory.appendingPathComponent("profiles.sealed"), SymmetricKey(data: keyData))
    }
    private func read(_ file: URL, _ key: SymmetricKey) throws -> StoreState {
        guard FileManager.default.fileExists(atPath: file.path) else { return StoreState() }
        let values = try file.resourceValues(forKeys: [.fileSizeKey, .isSymbolicLinkKey])
        guard values.isSymbolicLink != true, (values.fileSize ?? Int.max) <= 16 * 1024 * 1024 else { throw ClientError.storage }
        let box = try AES.GCM.SealedBox(combined: Data(contentsOf: file))
        let plain = try AES.GCM.open(box, using: key, authenticating: Data("sb-easy.apple.v1".utf8))
        let state = try JSONDecoder().decode(StoreState.self, from: plain)
        guard state.version == 1, state.profiles.count <= 32 else { throw ClientError.storage }
        return state
    }
    private func write(_ state: StoreState, _ file: URL, _ key: SymmetricKey) throws {
        let plain = try JSONEncoder().encode(state)
        guard plain.count <= 16 * 1024 * 1024 else { throw ClientError.storage }
        guard let sealed = try AES.GCM.seal(plain, using: key, authenticating: Data("sb-easy.apple.v1".utf8)).combined else { throw ClientError.storage }
        #if os(macOS)
        try sealed.write(to: file, options: [.atomic])
        #else
        try sealed.write(to: file, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
        #endif
        guard chmod(file.path, 0o600) == 0 else { throw ClientError.storage }
    }
    func state() throws -> StoreState { try locked { try read($0, $1) } }
    func profile(_ id: String) throws -> (Profile, Credentials) {
        try locked { file, key in
            guard let profile = try read(file, key).profiles.first(where: { $0.id == id }),
                  let data = try keychain.get("credential:" + profile.credentialRef) else { throw ClientError.storage }
            return (profile, try JSONDecoder().decode(Credentials.self, from: data))
        }
    }
    func add(_ profile: Profile, credentials: Credentials) throws {
        try locked { file, key in
            var state = try read(file, key)
            guard state.profiles.count < 32, !state.profiles.contains(where: { $0.id == profile.id }) else { throw ClientError.invalid("配置数量已达上限") }
            try keychain.insert("credential:" + profile.credentialRef, data: JSONEncoder().encode(credentials))
            do { state.profiles.append(profile); state.selectedID = profile.id; try write(state, file, key) }
            catch { try? keychain.remove("credential:" + profile.credentialRef); throw error }
        }
    }
    func update(_ profile: Profile, expectedRevision: Int, credentials: Credentials? = nil) throws {
        try locked { file, key in
            var state = try read(file, key)
            guard let index = state.profiles.firstIndex(where: { $0.id == profile.id }), state.profiles[index].revision == expectedRevision else { throw ClientError.stale }
            var next = profile
            next.revision = expectedRevision + 1; next.updatedAt = Date()
            let oldRef = state.profiles[index].credentialRef
            if let credentials {
                next.credentialRef = UUID().uuidString.lowercased()
                try keychain.insert("credential:" + next.credentialRef, data: JSONEncoder().encode(credentials))
            } else { next.credentialRef = oldRef }
            do { state.profiles[index] = next; try write(state, file, key) }
            catch { if credentials != nil { try? keychain.remove("credential:" + next.credentialRef) }; throw error }
            if credentials != nil { try? keychain.remove("credential:" + oldRef) }
        }
    }
    func select(_ id: String) throws {
        try locked { file, key in
            var state = try read(file, key)
            guard state.profiles.contains(where: { $0.id == id }) else { throw ClientError.stale }
            state.selectedID = id; try write(state, file, key)
        }
    }
    func remove(_ id: String) throws {
        try locked { file, key in
            var state = try read(file, key)
            guard let profile = state.profiles.first(where: { $0.id == id }) else { return }
            state.profiles.removeAll { $0.id == id }
            if state.selectedID == id { state.selectedID = state.profiles.first?.id }
            try write(state, file, key)
            try? keychain.remove("credential:" + profile.credentialRef)
        }
    }
}

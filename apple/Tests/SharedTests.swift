import XCTest
import Foundation

final class MemorySecrets: SecretStore {
    private let lock = NSLock()
    private var items: [String: Data] = [:]
    func get(_ account: String) throws -> Data? { lock.lock(); defer { lock.unlock() }; return items[account] }
    func insert(_ account: String, data: Data) throws {
        lock.lock(); defer { lock.unlock() }
        guard items[account] == nil else { throw ClientError.storage }
        items[account] = data
    }
    func remove(_ account: String) throws { lock.lock(); defer { lock.unlock() }; items.removeValue(forKey: account) }
}
final class SharedTests: XCTestCase {
    private let fixture = "trojan://fixture-secret@proxy.example:443?security=tls#fixture"
    func testHTTPSAuthorityAndRedirectBoundary() throws {
        XCTAssertEqual(try HTTPS.url("https://control.example/prefix", server: true).host, "control.example")
        for value in ["http://control.example", "https://user:secret@control.example", "https://control.example/#token", "https://control.example/\\bad", "https://control.example/\n"] {
            XCTAssertThrowsError(try HTTPS.url(value))
        }
        XCTAssertThrowsError(try HTTPS.url("https://control.example/?token=hidden", server: true))
    }
    func testImportRuntimeAndSettings() throws {
        let (nodes, report) = try Core.imported(Data(fixture.utf8))
        XCTAssertEqual(report.imported, 1)
        var profile = Profile(name: "Fixture", mode: .independent)
        profile.subscriptions = [Subscription(name: "Fixture", nodesJSON: nodes, report: report, metadata: Quota(available: false), remote: false)]
        let runtime = try Core.runtime(profile, credentials: Credentials())
        XCTAssertTrue(runtime.contains("sb-easy-apple-default"))
        profile.preferences.selected_tag = "removed-node"
        XCTAssertThrowsError(try Core.runtime(profile, credentials: Credentials()))
        XCTAssertThrowsError(try Core.validate(Preferences(local_groups: [LocalGroup(name: "Overlap", domains: ["example.org", "sub.example.org"], outbound: "fixture")])))
    }
    func testEncryptedVaultRevisionAndTamper() async throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: directory) }
        let secrets = MemorySecrets()
        let store = SecureStore(directory: directory, keychain: secrets)
        let profile = Profile(name: "Private Fixture", mode: .managed)
        try await store.add(profile, credentials: Credentials(server: "https://control.example", hostID: "fixture", token: "credential-secret"))
        let disk = try Data(contentsOf: directory.appendingPathComponent("profiles.sealed"))
        XCTAssertNil(disk.range(of: Data("Private Fixture".utf8)))
        XCTAssertNil(disk.range(of: Data("credential-secret".utf8)))
        let (saved, credentials) = try await store.profile(profile.id)
        XCTAssertEqual(credentials.token, "credential-secret")
        var changed = saved; changed.name = "Updated"
        try await store.update(changed, expectedRevision: 0)
        do { try await store.update(saved, expectedRevision: 0); XCTFail("stale write accepted") } catch ClientError.stale {} catch { XCTFail("unexpected error") }
        var corrupt = try Data(contentsOf: directory.appendingPathComponent("profiles.sealed"))
        corrupt[corrupt.count - 1] ^= 1
        try corrupt.write(to: directory.appendingPathComponent("profiles.sealed"))
        do { _ = try await store.state(); XCTFail("tampered ciphertext accepted") } catch {}
    }
    func testCrossStoreUpdatesAndModeIsolation() async throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: directory) }
        let secrets = MemorySecrets()
        let first = SecureStore(directory: directory, keychain: secrets)
        let second = SecureStore(directory: directory, keychain: secrets)
        let managed = Profile(name: "Managed", mode: .managed)
        let independent = Profile(name: "Independent", mode: .independent)
        try await first.add(managed, credentials: Credentials(server: "https://control.example", token: "managed-token"))
        try await second.add(independent, credentials: Credentials(subscriptionURLs: ["fixture": "https://subscription.example/private"]))
        let (local, credentials) = try await first.profile(independent.id)
        XCTAssertEqual(local.mode, .independent); XCTAssertNil(credentials.token); XCTAssertNil(credentials.server)
        let count = try await first.state().profiles.count
        XCTAssertEqual(count, 2)
        try await second.remove(managed.id)
        do { _ = try await first.profile(managed.id); XCTFail("deleted profile readable") } catch {}
        let remaining = try await first.profile(independent.id)
        XCTAssertEqual(remaining.0.id, independent.id)
    }
}

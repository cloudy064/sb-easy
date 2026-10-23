package io.sbeasy.android.core

import org.json.JSONObject

/** Persistence and network boundaries let failure recovery be verified without an Android process. */
interface EnrollmentStorage {
    fun load(): Enrollment?
    fun save(enrollment: Enrollment)
    fun clear()
}
interface ConfigurationStorage {
    fun active(): ManagedConfig?
    fun candidate(): ManagedConfig?
    fun saveCandidate(config: ManagedConfig)
    fun promoteCandidate(): ManagedConfig
    fun rollback(): ManagedConfig?
    fun clear()
}
interface RoutingStorage {
    fun load(): LocalRoutingPolicy?
    fun save(policy: LocalRoutingPolicy)
    fun clear()
}
interface SubscriptionStorage {
    fun mode(): ClientMode
    fun setMode(mode: ClientMode)
    fun load(): List<LocalSubscription>
    fun save(subscriptions: List<LocalSubscription>)
}
interface AgentControlPlane {
    fun enroll(rawUri: String, device: JSONObject, allowInsecureLocalHttp: Boolean = false): Enrollment
    fun fetchConfig(enrollment: Enrollment, etag: String?, force: Boolean): ConfigFetchResult
    fun reportStatus(enrollment: Enrollment, body: JSONObject)
    fun commands(enrollment: Enrollment): List<AgentCommand>
    fun acknowledge(enrollment: Enrollment, command: AgentCommand, success: Boolean, result: String)
    fun reportTelemetry(enrollment: Enrollment, body: JSONObject)
    fun networkSnapshot(): JSONObject
    fun uploadDiagnostics(enrollment: Enrollment, body: JSONObject): String
    fun uploadCapture(enrollment: Enrollment, digest: String, data: ByteArray, wifiOnly: Boolean)
    fun reportLatencies(enrollment: Enrollment, values: Map<String, Int?>)
}
fun interface SubscriptionSource {
    fun fetch(source: String, allowInsecure: Boolean): SubscriptionFetcher.Download
}

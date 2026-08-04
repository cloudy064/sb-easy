package io.sbeasy.android.core

import android.content.Context
import android.util.AtomicFile
import java.io.File
import org.json.JSONObject

class AtomicConfigStore(context: Context) {
    private val directory = File(context.filesDir, "managed-config").apply { mkdirs() }

    @Synchronized
    fun active(): ManagedConfig? = read("active")

    @Synchronized
    fun candidate(): ManagedConfig? = read("candidate")

    @Synchronized
    fun saveCandidate(config: ManagedConfig) = write("candidate", config)

    @Synchronized
    fun promoteCandidate(): ManagedConfig {
        val candidate = requireNotNull(candidate()) { "No candidate configuration" }
        active()?.let { write("rollback", it) }
        write("active", candidate)
        delete("candidate")
        return candidate
    }

    @Synchronized
    fun rollback(): ManagedConfig? {
        val rollback = read("rollback") ?: return null
        write("active", rollback)
        return rollback
    }

    @Synchronized
    fun clear() {
        listOf("active", "candidate", "rollback").forEach(::delete)
    }

    private fun write(name: String, config: ManagedConfig) {
        writeAtomic(
            File(directory, "$name.snapshot.json"),
            JSONObject()
                .put("content", config.content)
                .put("etag", config.etag)
                .put("rule_source", config.ruleSource)
                .put("profile_id", config.profileId)
                .put("profile_name", config.profileName)
                .put("synced_at", config.syncedAtMillis)
                .toString(),
        )
    }

    private fun read(name: String): ManagedConfig? = runCatching {
        val snapshotFile = File(directory, "$name.snapshot.json")
        val legacyContent = File(directory, "$name.json")
        val legacyMetadata = File(directory, "$name.meta.json")
        if (!snapshotFile.isFile && (!legacyContent.isFile || !legacyMetadata.isFile)) return null
        val metadata = JSONObject(
            if (snapshotFile.isFile) snapshotFile.readText() else legacyMetadata.readText(),
        )
        ManagedConfig(
            content = if (snapshotFile.isFile) metadata.getString("content") else legacyContent.readText(),
            etag = metadata.getString("etag"),
            ruleSource = metadata.optString("rule_source", "profile"),
            profileId = metadata.optString("profile_id", "default"),
            profileName = metadata.optString("profile_name", "Default"),
            syncedAtMillis = metadata.optLong("synced_at", 0L),
        )
    }.getOrNull()

    private fun delete(name: String) {
        File(directory, "$name.snapshot.json").delete()
        // Remove the pre-1.0 split representation if it exists.
        File(directory, "$name.json").delete()
        File(directory, "$name.meta.json").delete()
    }

    private fun writeAtomic(target: File, content: String) {
        val atomic = AtomicFile(target)
        val output = atomic.startWrite()
        try {
            output.write(content.toByteArray(Charsets.UTF_8))
            atomic.finishWrite(output)
        } catch (error: Throwable) {
            atomic.failWrite(output)
            throw error
        }
    }
}

package io.sbeasy.android.core

import android.content.Context
import android.util.AtomicFile
import java.io.File

class LocalRoutingStore(context: Context) {
    private val file = AtomicFile(File(context.filesDir, "local-routing.json"))

    @Synchronized
    fun load(): LocalRoutingPolicy? {
        if (!file.baseFile.isFile) return null
        // Never silently discard a user's policy if storage is corrupt.
        return LocalRouting.decode(file.openRead().bufferedReader().use { it.readText() })
    }

    @Synchronized
    fun save(policy: LocalRoutingPolicy) {
        LocalRouting.validate(policy)
        val output = file.startWrite()
        try {
            output.write(LocalRouting.encode(policy).toByteArray(Charsets.UTF_8))
            file.finishWrite(output)
        } catch (error: Throwable) {
            file.failWrite(output)
            throw error
        }
    }

    @Synchronized
    fun clear() = file.delete()
}

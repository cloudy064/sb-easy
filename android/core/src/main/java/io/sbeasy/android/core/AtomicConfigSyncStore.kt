package io.sbeasy.android.core

import android.content.Context
import android.util.AtomicFile
import java.io.File
import org.json.JSONObject

class AtomicConfigSyncStore(context: Context) : ConfigSyncStorage {
    private val file = AtomicFile(File(context.filesDir, "managed-config-sync.json"))
    @Synchronized override fun load(): JSONObject? = if (!file.baseFile.isFile) null else
        JSONObject(file.openRead().bufferedReader().use { it.readText() })
    @Synchronized override fun save(value: JSONObject) {
        val output = file.startWrite()
        try { output.write(value.toString().toByteArray(Charsets.UTF_8)); file.finishWrite(output) }
        catch (error: Throwable) { file.failWrite(output); throw error }
    }
    @Synchronized override fun clear() = file.delete()
}

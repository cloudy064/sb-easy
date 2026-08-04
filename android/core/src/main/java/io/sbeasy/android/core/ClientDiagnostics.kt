package io.sbeasy.android.core

import android.content.Context
import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * App-private, bounded diagnostic log used when Android's system log is not
 * available to the user. Entries are redacted before touching memory or disk.
 */
object ClientDiagnostics {
    private val lock = Any()
    private val mutableEntries = MutableStateFlow<List<RuntimeLog>>(emptyList())
    private val additionalLogs = linkedMapOf<String, File>()
    private var libboxEntries = emptyList<RuntimeLog>()
    private var initialized = false
    private var logFile: File? = null
    private var libboxLogFile: File? = null

    val entries: StateFlow<List<RuntimeLog>> = mutableEntries.asStateFlow()

    fun initialize(context: Context): Unit = synchronized(lock) {
        if (initialized) return
        val directory = File(context.filesDir, "diagnostics").apply { mkdirs() }
        logFile = File(directory, "client.log")
        libboxLogFile = File(directory, "libbox.log")
        val legacy = runCatching {
            logFile?.takeIf(File::isFile)?.readLines().orEmpty().takeLast(MAX_ENTRIES)
        }.getOrDefault(emptyList())
        val restoredLibbox = runCatching {
            libboxLogFile?.takeIf(File::isFile)?.readLines().orEmpty()
        }.getOrDefault(emptyList())
        mutableEntries.value = legacy.filterNot(::isLibboxLine).map { line ->
            RuntimeLog(levelFromLine(line), line, 0L)
        }
        libboxEntries = (legacy.filter(::isLibboxLine) + restoredLibbox)
            .takeLast(MAX_LIBBOX_ENTRIES)
            .map { line -> RuntimeLog(levelFromLine(line), line, 0L) }
        initialized = true
        appendLocked(listOf(newEntry(INFO, "diagnostics", "local diagnostic log initialized")))
    }

    fun registerAdditionalLog(name: String, file: File) = synchronized(lock) {
        additionalLogs[name.take(40)] = file
    }

    fun info(source: String, message: String) = record(INFO, source, message)

    fun warn(source: String, message: String) = record(WARN, source, message)

    fun error(source: String, message: String, error: Throwable? = null) {
        val detail = buildString {
            append(message)
            if (error != null) {
                append(": ")
                append(error.message ?: error.javaClass.simpleName)
                append('\n')
                append(error.stackTraceToString().take(MAX_MESSAGE_LENGTH))
            }
        }
        record(ERROR, source, detail)
    }

    fun appendLibbox(values: List<RuntimeLog>): Unit = synchronized(lock) {
        if (!initialized || values.isEmpty()) return
        val safeValues = values.map { value ->
            newEntry(value.level, "libbox", value.message)
        }
        libboxEntries = (libboxEntries + safeValues).takeLast(MAX_LIBBOX_ENTRIES)
        appendFileLocked(libboxLogFile, safeValues, libboxEntries, ROTATED_LIBBOX_ENTRIES)
    }

    fun snapshotLines(maxLines: Int = 1_200): List<String> = synchronized(lock) {
        val external = additionalLogs.flatMap { (name, file) ->
            tailLines(file, EXTERNAL_LOG_LINES_PER_FILE).map { line ->
                "[external:$name] ${redactDiagnosticText(line)}"
            }
        }
        mergeDiagnosticLines(
            app = mutableEntries.value.map(RuntimeLog::message),
            libbox = libboxEntries.map(RuntimeLog::message),
            external = external,
            maxLines = maxLines,
        )
    }

    fun clear() = synchronized(lock) {
        mutableEntries.value = emptyList()
        libboxEntries = emptyList()
        runCatching { logFile?.writeText("") }
        runCatching { libboxLogFile?.writeText("") }
        if (initialized) appendLocked(listOf(newEntry(INFO, "diagnostics", "local diagnostic log cleared")))
    }

    private fun record(level: Int, source: String, message: String): Unit = synchronized(lock) {
        if (!initialized) return
        appendLocked(listOf(newEntry(level, source, message)))
    }

    private fun newEntry(level: Int, source: String, message: String): RuntimeLog {
        val now = System.currentTimeMillis()
        val timestamp = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSXXX", Locale.US).format(Date(now))
        val levelName = when {
            level >= ERROR -> "ERROR"
            level >= WARN -> "WARN"
            else -> "INFO"
        }
        val safeSource = source.replace(Regex("[^A-Za-z0-9_.-]"), "_").take(40)
        val safeMessage = redactDiagnosticText(message)
            .replace('\r', ' ')
            .replace("\n", " ↩ ")
            .take(MAX_MESSAGE_LENGTH)
        return RuntimeLog(level, "$timestamp $levelName [$safeSource] $safeMessage", now)
    }

    private fun appendLocked(values: List<RuntimeLog>) {
        if (values.isEmpty()) return
        mutableEntries.value = (mutableEntries.value + values).takeLast(MAX_ENTRIES)
        appendFileLocked(logFile, values, mutableEntries.value, ROTATED_ENTRIES)
    }

    private fun appendFileLocked(
        target: File?,
        values: List<RuntimeLog>,
        retained: List<RuntimeLog>,
        rotatedEntries: Int,
    ) {
        val file = target ?: return
        runCatching {
            val payload = values.joinToString(separator = "\n", postfix = "\n", transform = RuntimeLog::message)
            if (file.length() + payload.toByteArray().size > MAX_FILE_BYTES) {
                file.writeText(retained.takeLast(rotatedEntries).joinToString("\n", postfix = "\n") { it.message })
            } else {
                file.appendText(payload)
            }
        }
    }

    private fun tailLines(file: File, maxLines: Int): List<String> = runCatching {
        if (!file.isFile) {
            emptyList()
        } else {
            file.inputStream().use { input ->
                val offset = (file.length() - MAX_EXTERNAL_LOG_BYTES).coerceAtLeast(0L)
                var remaining = offset
                while (remaining > 0L) {
                    val skipped = input.skip(remaining)
                    if (skipped <= 0L) break
                    remaining -= skipped
                }
                BufferedReader(InputStreamReader(input)).use { reader ->
                    val lines = reader.readLines()
                    // A byte-range seek may begin in the middle of a line.
                    lines.drop(if (offset > 0L && lines.isNotEmpty()) 1 else 0).takeLast(maxLines)
                }
            }
        }
    }.getOrDefault(emptyList())

    private fun levelFromLine(line: String): Int = when {
        " ERROR [" in line -> ERROR
        " WARN [" in line -> WARN
        else -> INFO
    }

    private fun isLibboxLine(line: String): Boolean =
        " [libbox] " in line || " [libbox-debug] " in line

    const val INFO = 3
    const val WARN = 4
    const val ERROR = 5
    private const val MAX_ENTRIES = 1_500
    private const val MAX_LIBBOX_ENTRIES = 1_000
    private const val ROTATED_ENTRIES = 900
    private const val ROTATED_LIBBOX_ENTRIES = 700
    private const val MAX_FILE_BYTES = 2 * 1_024 * 1_024L
    private const val MAX_MESSAGE_LENGTH = 4_000
    private const val EXTERNAL_LOG_LINES_PER_FILE = 200
    private const val MAX_EXTERNAL_LOG_BYTES = 256 * 1_024L
}

internal fun mergeDiagnosticLines(
    app: List<String>,
    libbox: List<String>,
    external: List<String>,
    maxLines: Int,
): List<String> {
    if (maxLines <= 0) return emptyList()
    val externalLines = external.takeLast((maxLines / 6).coerceAtLeast(1))
    val libboxLines = libbox.takeLast((maxLines / 2).coerceAtLeast(1))
    val appLines = app.takeLast((maxLines - externalLines.size - libboxLines.size).coerceAtLeast(0))
    return appLines + libboxLines + externalLines
}

internal fun redactDiagnosticText(raw: String): String {
    var value = raw
    value = JSON_SECRET.replace(value) { match -> "${match.groupValues[1]}***${match.groupValues[2]}" }
    value = AUTHORIZATION.replace(value) { match -> "${match.groupValues[1]}***" }
    value = QUERY_SECRET.replace(value) { match -> "${match.groupValues[1]}***" }
    value = URI_USER_INFO.replace(value) { match -> "${match.groupValues[1]}***@" }
    value = WIREGUARD_PRIVATE_KEY.replace(value) { match -> "${match.groupValues[1]}***" }
    return value
}

private val JSON_SECRET = Regex(
    "(?i)(\\\"(?:agent_token|token|password|secret|private_key|preshared_key|uuid)\\\"\\s*:\\s*\\\")[^\\\"]*(\\\")",
)
private val AUTHORIZATION = Regex("(?i)(authorization\\s*[:=]\\s*bearer\\s+)[^\\s,;]+")
private val QUERY_SECRET = Regex("(?i)([?&](?:code|token|secret)=)[^&#\\s]+")
private val URI_USER_INFO = Regex("([a-zA-Z][a-zA-Z0-9+.-]*://)[^/@\\s]+@")
private val WIREGUARD_PRIVATE_KEY = Regex("(?i)((?:private|preshared)[ _-]?key\\s*[:=]\\s*)[A-Za-z0-9+/]{32,}={0,2}")

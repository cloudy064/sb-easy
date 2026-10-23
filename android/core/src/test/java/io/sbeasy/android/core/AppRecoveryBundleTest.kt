package io.sbeasy.android.core

import java.io.ByteArrayOutputStream
import java.io.File
import java.io.IOException
import java.io.OutputStream
import java.util.zip.ZipInputStream
import org.junit.Assert.*
import org.junit.Test

class AppRecoveryBundleTest {
    @Test fun externalArchiveContainsExactApkReceiptAndDecryptablePreferencesWithoutPlaintextSecrets() {
        val folder = kotlin.io.path.createTempDirectory("sb-rescue-").toFile()
        val apk = File(folder, "old.apk").apply { writeBytes(ByteArray(4096) { (it * 17).toByte() }) }
        val release = AppCatalogTest.release().copy(build = 28, version = "1.3.4", bytes = apk.length(), sha256 = HttpDebugPackagePolicy.digest(apk))
        val secret = "recovery-passphrase-2026".toCharArray()
        val payload = "{\"subscription\":\"https://example.test/private-subscription-secret\"}"
        val envelope = PreferencesEnvelope.encrypt(payload, secret)
        try {
            val output = ByteArrayOutputStream()
            val hash = AppRecoveryBundle.write(apk, release, "{\"signed\":\"receipt-fixture\"}", envelope, 28, 29, output)
            val bytes = output.toByteArray(); AppRecoveryBundle.verify(bytes.inputStream(), hash)
            val entries = linkedMapOf<String, ByteArray>()
            ZipInputStream(bytes.inputStream()).use { zip -> while (true) { val entry = zip.nextEntry ?: break; entries[entry.name] = zip.readBytes() } }
            assertEquals(setOf("sb-easy-1.3.4-28.apk", "signed-catalog.json", "preferences.sbp", "RECOVERY.txt"), entries.keys)
            assertArrayEquals(apk.readBytes(), entries.getValue("sb-easy-1.3.4-28.apk"))
            assertEquals("{\"signed\":\"receipt-fixture\"}", String(entries.getValue("signed-catalog.json")))
            assertEquals(payload, PreferencesEnvelope.decrypt(String(entries.getValue("preferences.sbp")), secret))
            assertFalse(entries.values.any { String(it).contains("private-subscription-secret") })
            assertTrue(String(entries.getValue("RECOVERY.txt")).contains("system file manager"))
            assertThrows(IllegalArgumentException::class.java) { AppRecoveryBundle.verify(bytes.dropLast(1).toByteArray().inputStream(), hash) }
            val changed = bytes.copyOf().apply { this[20] = (this[20].toInt() xor 1).toByte() }
            assertThrows(IllegalArgumentException::class.java) { AppRecoveryBundle.verify(changed.inputStream(), hash) }
        } finally { secret.fill('\u0000'); folder.deleteRecursively() }
    }

    @Test fun plaintextPreferencesChangedApkAndDocumentWriteFailureCannotProduceARescueConfirmation() {
        val folder = kotlin.io.path.createTempDirectory("sb-rescue-failure-").toFile()
        val apk = File(folder, "old.apk").apply { writeText("signed fixture bytes") }
        val release = AppCatalogTest.release().copy(bytes = apk.length(), sha256 = HttpDebugPackagePolicy.digest(apk))
        val envelope = org.json.JSONObject(File(System.getProperty("sb.testdata"), "preferences-v1.json").readText()).getJSONObject("envelope").toString()
        try {
            assertThrows(IllegalArgumentException::class.java) { AppRecoveryBundle.write(apk, release, "{}", "{\"secret\":\"plaintext\"}", 29, 30, ByteArrayOutputStream()) }
            val broken = object : OutputStream() { override fun write(value: Int) { throw IOException("document provider write failed") } }
            assertThrows(IOException::class.java) { AppRecoveryBundle.write(apk, release, "{}", envelope, 29, 30, broken) }
            apk.appendText("tampered")
            val unchanged = ByteArrayOutputStream()
            assertThrows(IllegalArgumentException::class.java) { AppRecoveryBundle.write(apk, release, "{}", envelope, 29, 30, unchanged) }
            assertEquals(0, unchanged.size())
        } finally { folder.deleteRecursively() }
    }
}

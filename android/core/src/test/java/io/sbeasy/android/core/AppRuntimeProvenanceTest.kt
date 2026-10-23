package io.sbeasy.android.core

import java.io.File
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

class AppRuntimeProvenanceTest {
    private val library = "test-only non-executable native fixture".toByteArray()
    private fun provenance() = JSONObject().put("format", "sb-easy.libbox-provenance").put("version", 1).put("source_kind", "local-pinned-build")
        .put("core_version", "1.14.3").put("source_revision", "c".repeat(40)).put("overlay_sha256", "1".repeat(64))
        .put("source_changes_sha256", "2".repeat(64)).put("aar_sha256", "3".repeat(64))
        .put("toolchain", JSONObject().put("go", "go1.26.2").put("gomobile", "v0.1.12").put("ndk", "28.0.13004108"))
        .put("native_sha256", JSONObject(AppCatalog.ABIS.associateWith { PluginCatalog.sha256(library) }))
    private fun apk(raw: ByteArray, bytes: ByteArray = library, abi: String = "arm64-v8a"): File = File.createTempFile("sb-app-provenance-", ".apk").apply {
        ZipOutputStream(outputStream()).use { zip ->
            zip.putNextEntry(ZipEntry("assets/libbox-provenance.json")); zip.write(raw); zip.closeEntry()
            zip.putNextEntry(ZipEntry("lib/$abi/libbox.so")); zip.write(bytes); zip.closeEntry()
        }
    }
    @Test fun bundledNativeLibraryMustMatchSignedProvenanceAndArchitecture() {
        val raw = provenance().toString().toByteArray()
        val release = AppCatalogTest.release().copy(provenanceSha256 = PluginCatalog.sha256(raw))
        val good = apk(raw); try { assertEquals(setOf("arm64-v8a"), AppRuntimeProvenance.verify(good, release)) } finally { good.delete() }
        for (bad in listOf(apk(raw, "modified library".toByteArray()), apk(raw, abi = "x86_64"), apk(provenance().put("extra", true).toString().toByteArray()))) {
            try { assertTrue(runCatching { AppRuntimeProvenance.verify(bad, release) }.isFailure) } finally { bad.delete() }
        }
    }
    @Test fun matchingHumanVersionCannotHideWrongRevisionOrUnknownBuildOrigin() {
        for ((field, value) in listOf("source_revision" to "e".repeat(40), "core_version" to "1.14.2", "source_kind" to "downloaded-release", "aar_sha256" to "invalid")) {
            val raw = provenance().put(field, value).toString().toByteArray(); val file = apk(raw)
            val release = AppCatalogTest.release().copy(provenanceSha256 = PluginCatalog.sha256(raw))
            try { assertTrue(field, runCatching { AppRuntimeProvenance.verify(file, release) }.isFailure) } finally { file.delete() }
        }
    }
}

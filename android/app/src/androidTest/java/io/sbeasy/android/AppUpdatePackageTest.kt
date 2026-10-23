package io.sbeasy.android

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.sbeasy.android.core.*
import java.io.File
import java.util.zip.ZipFile
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

/** Runs only on an actual Android device/emulator; does not install or replace the application. */
@RunWith(AndroidJUnit4::class)
class AppUpdatePackageTest {
    @Test fun installedApkHasConsistentCertificateManifestAndBundledRuntimeProvenance() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        assertTrue("Test requires the single-APK distribution", context.applicationInfo.splitSourceDirs.isNullOrEmpty())
        val apk = File(context.applicationInfo.sourceDir)
        val raw = context.assets.open("libbox-provenance.json").use { it.readBytes() }
        val provenance = JSONObject(String(raw, Charsets.UTF_8))
        val abis = ZipFile(apk).use { zip -> zip.entries().asSequence().map { it.name }.filter { it.startsWith("lib/") && it.endsWith(".so") }.map { it.split('/')[1] }.toSet() }
        val release = AppRelease(BuildConfig.VERSION_NAME, AppPackagePolicy.currentBuild(context), context.applicationInfo.minSdkVersion, abis,
            context.packageName, AppPackagePolicy.currentSigner(context), "https://example.invalid/app.apk", HttpDebugPackagePolicy.digest(apk), apk.length(),
            provenance.getString("core_version"), provenance.getString("source_revision"), PluginCatalog.sha256(raw))
        AppPackagePolicy.inspect(context, apk, release)
        for (invalid in listOf(release.copy(build = release.build + 1), release.copy(signer = "0".repeat(64)), release.copy(minOs = release.minOs + 1),
            release.copy(sourceRevision = "0".repeat(40)), release.copy(coreVersion = "0.0.0"), release.copy(provenanceSha256 = "0".repeat(64)))) {
            assertTrue(runCatching { AppPackagePolicy.inspect(context, apk, invalid) }.isFailure)
        }
    }
}

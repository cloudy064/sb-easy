import java.util.Base64
import groovy.json.JsonSlurper

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

val clientManifest = JsonSlurper().parseText(providers.fileContents(
    rootProject.layout.projectDirectory.file("../config/client-releases.json")
).asText.get()) as Map<*, *>
val androidVersion = (clientManifest["development"] as Map<*, *>)["android"] as Map<*, *>

android {
    namespace = "io.sbeasy.android"
    compileSdk = 36

    defaultConfig {
        applicationId = "io.sbeasy.android"
        minSdk = 24
        targetSdk = 36
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        versionCode = (androidVersion["version_code"] as Number).toInt()
        versionName = androidVersion["version"] as String
        val trustFile = providers.gradleProperty("sbPluginCatalogKeys").orNull?.let(::file)
            ?: rootProject.file("../config/plugin-catalog-keys.json")
        require(trustFile.length() <= 65536) { "Plugin trust config exceeds 64 KiB" }
        buildConfigField("String", "PLUGIN_CATALOG_KEYS_BASE64", "\"" + Base64.getEncoder().encodeToString(trustFile.readBytes()) + "\"")
    }

    defaultConfig {
        val appTrustFile = providers.gradleProperty("sbAppCatalogKeys").orNull?.let(::file)
            ?: rootProject.file("../config/app-catalog-keys.json")
        require(appTrustFile.length() <= 65536) { "Application trust config exceeds 64 KiB" }
        buildConfigField("String", "APP_CATALOG_KEYS_BASE64", "\"" + Base64.getEncoder().encodeToString(appTrustFile.readBytes()) + "\"")
    }

    sourceSets.getByName("main").assets.srcDir(layout.buildDirectory.dir("generated/runtime-provenance").get().asFile)

    buildTypes {
        release {
            isMinifyEnabled = false
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }

    packaging {
        jniLibs.useLegacyPackaging = true
        jniLibs.keepDebugSymbols += "**/libbox.so"
    }

    splits {
        abi {
            isEnable = true
            reset()
            include("arm64-v8a", "armeabi-v7a", "x86", "x86_64")
            isUniversalApk = true
        }
    }
}

apply(from = rootProject.file("signing.gradle"))

dependencies {
    implementation(project(":core"))
    implementation(project(":libbox-bridge"))

    val composeBom = platform("androidx.compose:compose-bom:2026.06.01")
    implementation(composeBom)
    androidTestImplementation(composeBom)
    androidTestImplementation("androidx.test:runner:1.7.0")
    androidTestImplementation("androidx.test.espresso:espresso-core:3.7.0")
    androidTestImplementation("androidx.test.ext:junit:1.3.0")
    androidTestImplementation("androidx.compose.ui:ui-test-junit4")
    debugImplementation("androidx.compose.ui:ui-test-manifest")

    implementation("androidx.activity:activity-compose:1.13.0")
    implementation("androidx.core:core-ktx:1.17.0")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.10.0")
    implementation("androidx.fragment:fragment-ktx:1.8.9")
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.compose.material3:material3")
    implementation("com.journeyapps:zxing-android-embedded:4.3.0")
    implementation("com.google.zxing:core:3.5.4")
    testImplementation("junit:junit:4.13.2")
    debugImplementation("androidx.compose.ui:ui-tooling")
}

// A downloaded same-version AAR cannot inherit a source-build label: bind the asset to its exact bytes.
val prepareRuntimeProvenance by tasks.registering {
    val aar = rootProject.file("libbox-bridge/libs/libbox.aar")
    val provenance = rootProject.file("libbox-bridge/libs/libbox-provenance.json")
    val destination = layout.buildDirectory.dir("generated/runtime-provenance")
    inputs.files(aar, provenance, rootProject.file("../config/runtime-versions.json"), rootProject.file("scripts/libbox-provenance.py"))
    inputs.files(rootProject.fileTree("libbox-overlay") { include("**/*.go") }, rootProject.fileTree("scripts") { include("*capture*", "build-libbox.sh") }, rootProject.file("third_party/libpcap-1.10.6.tar.xz"))
    outputs.dir(destination)
    doLast {
        require(provenance.isFile) { "Missing libbox build provenance; run android/scripts/build-libbox.sh" }
        val result = ProcessBuilder("python3", rootProject.file("scripts/libbox-provenance.py").path,
            "verify", "--aar", aar.path, "--output", provenance.path).inheritIO().start().waitFor()
        check(result == 0) { "libbox provenance does not match the bundled AAR" }
        val directory = destination.get().asFile.apply { mkdirs() }
        provenance.copyTo(directory.resolve("libbox-provenance.json"), overwrite = true)
    }
}
tasks.named("preBuild").configure { dependsOn(prepareRuntimeProvenance) }

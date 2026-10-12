package io.sbeasy.android

import org.junit.Assert.*
import org.junit.Test

class HttpDebugStoreTest {
    @Test fun prefersNativeAbiOverTranslatedArmSupport() {
        assertTrue(HttpDebugStore.artifact(listOf("x86_64", "arm64-v8a")).url.contains("x86_64"))
        assertTrue(HttpDebugStore.artifact(listOf("arm64-v8a", "armeabi-v7a")).url.contains("arm64-v8a"))
        assertThrows(IllegalStateException::class.java) { HttpDebugStore.artifact(listOf("armeabi-v7a")) }
    }
}

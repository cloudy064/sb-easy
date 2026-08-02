package io.sbeasy.android.core

import android.content.Context
import android.util.Base64
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import org.json.JSONObject

class SecureEnrollmentStore(context: Context) {
    private val preferences = context.getSharedPreferences("secure_enrollment", Context.MODE_PRIVATE)

    fun load(): Enrollment? {
        val encoded = preferences.getString(KEY_PAYLOAD, null) ?: return null
        return runCatching {
            val parts = encoded.split(':', limit = 2)
            require(parts.size == 2)
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(
                Cipher.DECRYPT_MODE,
                encryptionKey(),
                GCMParameterSpec(128, Base64.decode(parts[0], Base64.NO_WRAP)),
            )
            val json = JSONObject(
                String(cipher.doFinal(Base64.decode(parts[1], Base64.NO_WRAP)), Charsets.UTF_8),
            )
            Enrollment(
                server = json.getString("server"),
                hostId = json.getString("host_id"),
                hostName = json.getString("host_name"),
                agentToken = json.getString("agent_token"),
                profileId = json.getString("profile_id"),
                profileName = json.getString("profile_name"),
            )
        }.getOrNull()
    }

    fun save(enrollment: Enrollment) {
        val json = JSONObject()
            .put("server", enrollment.server)
            .put("host_id", enrollment.hostId)
            .put("host_name", enrollment.hostName)
            .put("agent_token", enrollment.agentToken)
            .put("profile_id", enrollment.profileId)
            .put("profile_name", enrollment.profileName)
            .toString()
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, encryptionKey())
        val payload = Base64.encodeToString(cipher.iv, Base64.NO_WRAP) + ":" +
            Base64.encodeToString(cipher.doFinal(json.toByteArray(Charsets.UTF_8)), Base64.NO_WRAP)
        check(preferences.edit().putString(KEY_PAYLOAD, payload).commit())
    }

    fun clear() {
        preferences.edit().remove(KEY_PAYLOAD).apply()
    }

    private fun encryptionKey(): SecretKey {
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (keyStore.getKey(KEY_ALIAS, null) as? SecretKey)?.let { return it }
        return KeyGenerator.getInstance("AES", "AndroidKeyStore").run {
            init(
                android.security.keystore.KeyGenParameterSpec.Builder(
                    KEY_ALIAS,
                    android.security.keystore.KeyProperties.PURPOSE_ENCRYPT or
                        android.security.keystore.KeyProperties.PURPOSE_DECRYPT,
                )
                    .setBlockModes(android.security.keystore.KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(android.security.keystore.KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setKeySize(256)
                    .build(),
            )
            generateKey()
        }
    }

    companion object {
        private const val KEY_ALIAS = "sb_easy_agent_token_v1"
        private const val KEY_PAYLOAD = "payload"
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
    }
}

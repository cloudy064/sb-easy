package io.sbeasy.android.core

import java.nio.ByteBuffer
import java.nio.CharBuffer
import java.nio.charset.CodingErrorAction
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import okio.ByteString.Companion.decodeBase64
import okio.ByteString.Companion.toByteString
import org.json.JSONObject

/** The same password envelope is used by the native desktop client and the opaque sync API. */
object PreferencesEnvelope {
    const val MAX_BYTES = 1024 * 1024
    const val ITERATIONS = 600_000
    private val aad = "sb-easy/preferences/v1".toByteArray(Charsets.UTF_8)
    private val fields = setOf("format", "version", "kdf", "iterations", "salt", "nonce", "ciphertext")

    fun encrypt(payload: String, password: CharArray): String = encrypt(payload, password,
        ByteArray(16).also(SecureRandom()::nextBytes), ByteArray(12).also(SecureRandom()::nextBytes))

    internal fun encrypt(payload: String, password: CharArray, salt: ByteArray, nonce: ByteArray): String {
        require(salt.size == 16 && nonce.size == 12)
        val plain = payload.toByteArray(Charsets.UTF_8)
        require(plain.size <= MAX_BYTES) { "偏好数据超过 1 MiB" }
        val key = derive(password, salt)
        try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
            cipher.updateAAD(aad)
            return JSONObject().put("format", "sb-easy.preferences").put("version", 1)
                .put("kdf", "pbkdf2-sha256").put("iterations", ITERATIONS)
                .put("salt", salt.toByteString().base64()).put("nonce", nonce.toByteString().base64())
                .put("ciphertext", cipher.doFinal(plain).toByteString().base64()).toString().also {
                    require(it.toByteArray(Charsets.UTF_8).size <= MAX_BYTES) { "加密文件超过 1 MiB，请减少订阅内容后重试" }
                }
        } finally { key.fill(0); plain.fill(0) }
    }

    fun decrypt(envelope: String, password: CharArray): String {
        val parsed = inspect(envelope)
        val key = derive(password, decode(parsed, "salt", 16))
        try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, decode(parsed, "nonce", 12)))
            cipher.updateAAD(aad)
            val plaintext = try { cipher.doFinal(decode(parsed, "ciphertext")) }
            catch (_: Exception) { throw IllegalArgumentException("口令错误或文件已损坏，未导入任何内容") }
            try { return utf8(plaintext) } finally { plaintext.fill(0) }
        } finally { key.fill(0) }
    }

    fun inspect(envelope: String): JSONObject {
        require(envelope.toByteArray(Charsets.UTF_8).size in 1..MAX_BYTES) { "加密文件为空或超过 1 MiB" }
        val root = try { JSONObject(envelope) } catch (_: Exception) { throw IllegalArgumentException("不是有效的偏好加密文件") }
        require(root.keys().asSequence().toSet() == fields && root.opt("format") == "sb-easy.preferences" &&
            root.opt("version") == 1 && root.opt("kdf") == "pbkdf2-sha256" && root.opt("iterations") == ITERATIONS) {
            "不支持的偏好加密格式或参数"
        }
        decode(root, "salt", 16); decode(root, "nonce", 12)
        require(decode(root, "ciphertext").size >= 16) { "加密内容不完整" }
        return root
    }

    fun utf8(bytes: ByteArray): String = try {
        Charsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT)
            .decode(ByteBuffer.wrap(bytes)).toString()
    } catch (_: Exception) { throw IllegalArgumentException("文件不是有效的 UTF-8") }

    private fun decode(json: JSONObject, name: String, size: Int? = null): ByteArray {
        val text = json.opt(name) as? String ?: throw IllegalArgumentException("无效的加密参数")
        val bytes = text.decodeBase64()?.toByteArray() ?: throw IllegalArgumentException("无效的 Base64 加密参数")
        require(bytes.toByteString().base64() == text && (size == null || bytes.size == size)) { "无效的加密参数长度或编码" }
        return bytes
    }

    private fun derive(password: CharArray, salt: ByteArray): ByteArray {
        val encoded = try { Charsets.UTF_8.newEncoder().onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT).encode(CharBuffer.wrap(password)) }
        catch (_: Exception) { throw IllegalArgumentException("口令包含无效字符") }
        val secret = ByteArray(encoded.remaining()).also(encoded::get)
        if (encoded.hasArray()) encoded.array().fill(0)
        try {
            require(secret.size in 12..4096) { "加密口令须为 12–4096 个 UTF-8 字节" }
            // JCE's PBKDF2WithHmacSHA256 is unavailable on API 24/25. This equivalent
            // one-block PBKDF2 uses HmacSHA256, available on every supported Android.
            val mac = Mac.getInstance("HmacSHA256").apply { init(SecretKeySpec(secret, "HmacSHA256")) }
            var previous = mac.doFinal(salt + byteArrayOf(0, 0, 0, 1))
            val result = previous.copyOf()
            repeat(ITERATIONS - 1) {
                val next = mac.doFinal(previous)
                previous.fill(0); previous = next
                for (index in result.indices) result[index] = (result[index].toInt() xor next[index].toInt()).toByte()
            }
            previous.fill(0)
            return result
        } finally { secret.fill(0) }
    }
}

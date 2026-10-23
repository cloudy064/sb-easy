package io.sbeasy.android.core

import org.json.JSONArray
import org.json.JSONObject

/** Android's JSONObject parser accepts duplicate keys and trailing data. Signed input must not. */
internal object StrictJson {
    fun objectValue(text: String): JSONObject = Reader(text).read() as? JSONObject ?: error("JSON 顶层必须为对象")
    private class Reader(private val text: String) {
        private var offset = 0
        private var values = 0
        fun read(): Any {
            val result = value(0); space(); require(offset == text.length) { "JSON 含多余内容" }; return result
        }
        private fun space() { while (offset < text.length && text[offset] in " \n\r\t") offset++ }
        private fun value(depth: Int): Any {
            require(depth <= 24 && ++values <= 20000) { "JSON 内容过于复杂" }; space()
            require(offset < text.length) { "JSON 内容不完整" }
            return when (text[offset]) {
                '{' -> {
                    offset++; space(); val result = JSONObject(); val seen = hashSetOf<String>()
                    if (!take('}')) {
                        do {
                            space(); val name = string(); require(seen.add(name)) { "JSON 字段重复" }
                            space(); expect(':'); result.put(name, value(depth + 1)); space()
                        } while (take(','))
                        expect('}')
                    }; result
                }
                '[' -> {
                    offset++; space(); val result = JSONArray()
                    if (!take(']')) { do { result.put(value(depth + 1)); space() } while (take(',')); expect(']') }; result
                }
                '"' -> string()
                't' -> literal("true", true)
                'f' -> literal("false", false)
                'n' -> literal("null", JSONObject.NULL)
                else -> {
                    val match = number.find(text, offset)
                    require(match != null && match.range.first == offset) { "JSON 数字无效" }
                    offset = match.range.last + 1
                    if (match.value.any { it in ".eE" }) match.value.toDouble().also { require(it.isFinite()) { "JSON 数字无效" } }
                    else match.value.toLongOrNull() ?: error("JSON 整数超出范围")
                }
            }
        }
        private fun string(): String {
            expect('"'); val result = StringBuilder()
            while (offset < text.length) {
                val next = text[offset++]
                if (next == '"') {
                    val value = result.toString()
                    var index = 0
                    while (index < value.length) {
                        if (value[index].isHighSurrogate()) { require(index + 1 < value.length && value[index + 1].isLowSurrogate()) { "JSON Unicode 无效" }; index++ }
                        else require(!value[index].isLowSurrogate()) { "JSON Unicode 无效" }
                        index++
                    }
                    return value
                }
                require(next.code >= 32) { "JSON 字符串含控制字符" }
                if (next != '\\') { result.append(next); continue }
                require(offset < text.length) { "JSON 转义不完整" }
                when (val escaped = text[offset++]) {
                    '"', '\\', '/' -> result.append(escaped)
                    'b' -> result.append('\b'); 'f' -> result.append('\u000c'); 'n' -> result.append('\n'); 'r' -> result.append('\r'); 't' -> result.append('\t')
                    'u' -> {
                        require(offset + 4 <= text.length) { "JSON Unicode 不完整" }
                        val hex = text.substring(offset, offset + 4)
                        require(hex.all { it in "0123456789abcdefABCDEF" }) { "JSON Unicode 无效" }
                        val code = hex.toInt(16)
                        offset += 4; result.append(code.toChar())
                    }
                    else -> error("JSON 转义无效")
                }
            }; error("JSON 字符串不完整")
        }
        private fun literal(word: String, value: Any): Any {
            require(text.startsWith(word, offset)) { "JSON 字面值无效" }; offset += word.length; return value
        }
        private fun take(char: Char): Boolean = (offset < text.length && text[offset] == char).also { if (it) offset++ }
        private fun expect(char: Char) { require(take(char)) { "JSON 结构无效" } }
        companion object { private val number = Regex("-?(?:0|[1-9][0-9]*)(?:\\.[0-9]+)?(?:[eE][+-]?[0-9]+)?") }
    }
}

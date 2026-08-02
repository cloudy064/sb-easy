package io.sbeasy.android

import com.google.zxing.BarcodeFormat
import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.MultiFormatReader
import com.google.zxing.RGBLuminanceSource
import com.google.zxing.common.GlobalHistogramBinarizer
import com.google.zxing.common.HybridBinarizer
import java.util.EnumMap

internal object QrCodeDecoder {
    fun decode(width: Int, height: Int, pixels: IntArray): String {
        require(width > 0 && height > 0 && pixels.size == width * height) {
            "二维码图片尺寸无效"
        }
        val source = RGBLuminanceSource(width, height, pixels)
        val hints = EnumMap<DecodeHintType, Any>(DecodeHintType::class.java).apply {
            put(DecodeHintType.POSSIBLE_FORMATS, listOf(BarcodeFormat.QR_CODE))
            put(DecodeHintType.TRY_HARDER, true)
            put(DecodeHintType.CHARACTER_SET, "UTF-8")
        }
        val reader = MultiFormatReader()
        val candidates = listOf(
            BinaryBitmap(HybridBinarizer(source)),
            BinaryBitmap(GlobalHistogramBinarizer(source)),
            BinaryBitmap(HybridBinarizer(source.invert())),
        )
        candidates.forEach { candidate ->
            runCatching { reader.decode(candidate, hints).text }
                .onSuccess { return it }
            reader.reset()
        }
        error("图片中未识别到注册二维码，请选择清晰的原图或截图")
    }
}

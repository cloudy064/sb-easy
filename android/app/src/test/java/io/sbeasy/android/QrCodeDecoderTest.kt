package io.sbeasy.android

import com.google.zxing.BarcodeFormat
import com.google.zxing.qrcode.QRCodeWriter
import org.junit.Assert.assertEquals
import org.junit.Test

class QrCodeDecoderTest {
    @Test
    fun decodesEnrollmentQrPixels() {
        val uri = "sbeasy://enroll?server=http%3A%2F%2F39.108.98.208%3A51821&code=${"ab".repeat(32)}"
        val matrix = QRCodeWriter().encode(uri, BarcodeFormat.QR_CODE, 512, 512)
        val pixels = IntArray(matrix.width * matrix.height) { index ->
            val x = index % matrix.width
            val y = index / matrix.width
            if (matrix[x, y]) 0xff000000.toInt() else 0xffffffff.toInt()
        }

        assertEquals(uri, QrCodeDecoder.decode(matrix.width, matrix.height, pixels))
    }
}

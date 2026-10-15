package com.linecorp.webauthn.model

import com.google.common.truth.Truth.assertThat
import org.junit.jupiter.api.Test

class EC2COSEKeyTest {
    @Test
    fun `normalizes p256 coordinates to 32 bytes`() {
        val x = ByteArray(32) { 0x11.toByte() }
        val y = ByteArray(33) { 0x22.toByte() }.also { it[0] = 0x00 }

        val key = EC2COSEKey(
            kty = 2,
            alg = -7,
            crv = 1,
            x = x,
            y = y,
        )

        assertThat(key.x.size).isEqualTo(32)
        assertThat(key.y.size).isEqualTo(32)
        assertThat(key.y[0]).isEqualTo(0x22.toByte())
    }
}

/*
 * Copyright 2024 LY Corporation
 *
 * LY Corporation licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

package com.linecorp.webauthn.model

import co.nstant.`in`.cbor.CborDecoder
import co.nstant.`in`.cbor.model.ByteString
import co.nstant.`in`.cbor.model.DataItem
import co.nstant.`in`.cbor.model.UnicodeString
import com.google.common.truth.Truth.assertThat
import com.linecorp.webauthn.authenticator.keygenerator.BiometricKeyGenerator
import com.linecorp.webauthn.authenticator.objectgenerator.AndroidKeyObjectGenerator
import com.linecorp.webauthn.authenticator.objectgenerator.Fido2ObjectGenerator
import com.linecorp.webauthn.authenticator.objectgenerator.NoneObjectGenerator
import com.linecorp.webauthn.util.Fido2Util
import com.linecorp.webauthn.util.TestAuthenticatorFactory
import com.linecorp.webauthn.util.toBase64url
import java.nio.ByteBuffer
import java.security.KeyPair
import java.security.KeyStore
import java.security.MessageDigest
import java.security.Signature
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Test
import co.nstant.`in`.cbor.model.Map as CborMap
import co.nstant.`in`.cbor.model.Number as CborNumber

/**
 * Verifies the bytes of an attestation object built from a **real** AndroidKeyStore key.
 *
 * `com.linecorp.webauthn.model.CborEncodingTest` pins the same encoding rules on the JVM, but it does so
 * over a synthetic `authData = byteArrayOf(1, 2)` and hand-written statements, so it cannot see what a
 * relying party actually receives: the attested credential data, and the COSE credential public key
 * inside it, only exist once a device has generated a key. The 32-byte coordinate requirement is exactly
 * the property that a synthetic fixture cannot check.
 *
 * Keys differ on every run, so nothing here compares against a fixed hex string. The assertions are the
 * raw CBOR framing bytes plus a structural parse of the fixed-layout authenticator data.
 */
class AttestationObjectWireFormatTest {

    private val keyStore: KeyStore = KeyStore.getInstance("AndroidKeyStore").also { it.load(null) }
    private val generatedAliases = mutableListOf<String>()

    private val rpId = "example.com"
    private val clientDataHash = ByteArray(32) { 3 }
    private val aaguid = AuthenticatorType.BiometricNone.aaguidBytes()

    @AfterEach
    fun tearDown() {
        // A failed assertion must not leave a hardware-backed key on a shared device.
        TestAuthenticatorFactory.deleteAliases(keyStore, generatedAliases)
        generatedAliases.clear()
    }

    @Test
    fun aNoneAttestationObjectFromARealKeyIsCanonicalCbor() {
        val credId = newCredentialId()
        generateKey(credId, challenge = null)

        val attestationObject = NoneObjectGenerator().attestationObjectFor(credId, signature = null)

        assertCanonicalFraming(
            attestationObject,
            expectedFmt = AttestationStatementFormat.NONE.value,
            // An empty attStmt: a0 is a definite-length map with no pairs, not bf ... ff.
            expectedAttStmtHeader = 0xa0.toByte(),
        )
        assertAuthenticatorDataLayout(attestationObject.authData, credId)
    }

    @Test
    fun anAndroidKeyAttestationObjectFromARealKeyIsCanonicalCborAtEveryLevel() {
        val credId = newCredentialId()
        val keyPair = generateKey(credId, challenge = clientDataHash)

        val attestationObject = AndroidKeyObjectGenerator()
            .attestationObjectFor(credId, signature = signatureFor(keyPair))

        assertCanonicalFraming(
            attestationObject,
            expectedFmt = AttestationStatementFormat.ANDROID_KEY.value,
            // The nested statement map has to be definite too: a3 for alg/sig/x5c. This is the level that
            // stayed indefinite before 1.2.0, inside an otherwise conformant attestation object.
            expectedAttStmtHeader = 0xa3.toByte(),
        )
        assertAuthenticatorDataLayout(attestationObject.authData, credId)
    }

    /**
     * The non-canonical switch is a diagnostic for a relying party that cannot accept the conformant
     * framing. It is only useful if it reproduces the released bytes on a real object, so it is checked
     * here as well as on the JVM fixtures - both levels have to revert.
     */
    @Test
    fun theNonCanonicalSwitchStillEmitsIndefiniteLengthMapsForARealObject() {
        val credId = newCredentialId()
        val keyPair = generateKey(credId, challenge = clientDataHash)
        val attestationObject = AndroidKeyObjectGenerator()
            .attestationObjectFor(credId, signature = signatureFor(keyPair))

        val encoded = attestationObject.toCBOR(canonical = false)

        assertThat(encoded.first()).isEqualTo(0xbf.toByte())
        // Insertion order, so the indefinite attStmt map is last: its break byte and the outer one close
        // the encoding.
        assertThat(encoded.last()).isEqualTo(0xff.toByte())
        assertThat(encoded.attStmtMapHeader()).isEqualTo(0xbf.toByte())
    }

    private fun assertCanonicalFraming(
        attestationObject: AttestationObject,
        expectedFmt: String,
        expectedAttStmtHeader: Byte,
    ) {
        val encoded = attestationObject.toCBOR()

        // a3 = definite-length map of 3 pairs, which WebAuthn Level 2 section 2.4 requires via CTAP2
        // canonical CBOR. bf would be the indefinite-length form.
        assertThat(encoded.first()).isEqualTo(0xa3.toByte())
        // Canonical key ordering puts authData last, so the encoding ends with the authenticator data
        // itself: nothing follows it, and in particular no break byte does. Asserted this way rather than
        // as "the last byte is not ff" because the last byte of a real key's y coordinate is arbitrary.
        assertThat(encoded.takeLast(attestationObject.authData.size))
            .isEqualTo(attestationObject.authData.toList())

        val decoded = CborDecoder.decode(encoded)
        // One data item and nothing else: a trailing break byte would be a second item, or a decode error.
        assertThat(decoded).hasSize(1)
        val map = decoded.first() as CborMap
        assertThat(map.keys.map { (it as UnicodeString).string })
            .containsExactly("fmt", "attStmt", "authData").inOrder()
        assertThat((map.get(UnicodeString("fmt")) as UnicodeString).string).isEqualTo(expectedFmt)
        assertThat((map.get(UnicodeString("authData")) as ByteString).bytes)
            .isEqualTo(attestationObject.authData)

        // Checked on the raw bytes because a decoded map cannot show whether it was definite-length.
        assertThat(encoded.attStmtMapHeader()).isEqualTo(expectedAttStmtHeader)
    }

    /**
     * Parses the authenticator data by the fixed layout of the specification, rather than by reusing the
     * SDK's own writer, and checks the credential public key a relying party would import.
     */
    private fun assertAuthenticatorDataLayout(authData: ByteArray, credId: String) {
        val buffer = ByteBuffer.wrap(authData)
        val rpIdHash = ByteArray(32).also { buffer.get(it) }
        val flags = buffer.get().toInt() and 0xff
        val signCount = buffer.int
        val readAaguid = ByteArray(16).also { buffer.get(it) }
        val credIdLength = buffer.short.toInt() and 0xffff
        val readCredId = ByteArray(credIdLength).also { buffer.get(it) }
        val coseKey = ByteArray(buffer.remaining()).also { buffer.get(it) }

        assertThat(rpIdHash).isEqualTo(MessageDigest.getInstance("SHA-256").digest(rpId.toByteArray()))
        // AT: attested credential data is present, which is what makes the rest of this parse valid.
        assertThat(flags and AuthenticatorDataFlags.AT.value.toInt())
            .isEqualTo(AuthenticatorDataFlags.AT.value.toInt())
        assertThat(signCount).isEqualTo(0)
        assertThat(readAaguid).isEqualTo(aaguid)
        assertThat(credIdLength).isEqualTo(32)
        assertThat(readCredId.toBase64url()).isEqualTo(credId)

        // a5 = definite-length map of 5 pairs. The COSE key is nested inside a byte string, so a relying
        // party decodes it separately and an indefinite-length map here is a second, hidden defect.
        assertThat(coseKey.first()).isEqualTo(0xa5.toByte())
        val decodedKey = CborDecoder.decode(coseKey)
        assertThat(decodedKey).hasSize(1)
        val keyMap = decodedKey.first() as CborMap
        val labels: List<DataItem> = keyMap.keys.toList()
        assertThat(labels.map { (it as CborNumber).value.toLong() })
            .containsExactly(1L, 3L, -1L, -2L, -3L).inOrder()
        assertThat((keyMap.get(labels[0]) as CborNumber).value.toLong()).isEqualTo(2L)
        assertThat((keyMap.get(labels[1]) as CborNumber).value.toLong()).isEqualTo(-7L)
        assertThat((keyMap.get(labels[2]) as CborNumber).value.toLong()).isEqualTo(1L)
        // The core fix of this release. BigInteger.toByteArray() is minimal-length two's complement, so it
        // produced 33 bytes whenever the high bit was set and 31 or fewer when a leading byte was zero;
        // RFC 9052 section 7.1.1 and SEC1 require exactly the field size, 32 bytes for P-256.
        assertThat((keyMap.get(labels[3]) as ByteString).bytes).hasLength(32)
        assertThat((keyMap.get(labels[4]) as ByteString).bytes).hasLength(32)
    }

    private fun Fido2ObjectGenerator.attestationObjectFor(credId: String, signature: Signature?) =
        createAttestationObject(
            hash = clientDataHash,
            rpId = rpId,
            aaguid = aaguid,
            credId = credId,
            signCount = 0u,
            extensions = null,
            signature = signature,
        )

    private fun signatureFor(keyPair: KeyPair): Signature = Signature.getInstance(
        COSEAlgorithmIdentifier.ES256.getSignatureAlgorithmName()
    ).apply { initSign(keyPair.private) }

    private fun newCredentialId(): String = Fido2Util.generateRandomByteArray(32).toBase64url()

    private fun generateKey(credId: String, challenge: ByteArray?): KeyPair {
        generatedAliases.add(credId)
        return BiometricKeyGenerator().generateFido2Key(
            keyAlias = credId,
            challenge = challenge,
            publicKeyAlgorithm = COSEAlgorithmIdentifier.ES256,
            isStrongBoxBacked = false,
            // The alias, the algorithm and the attestation challenge are production values; only the user
            // authentication requirement is dropped, so that signing needs no prompt.
            userAuthenticationRequired = false,
        )
    }

    /** The map header byte that follows the encoded `attStmt` key, which is the nested map's framing. */
    private fun ByteArray.attStmtMapHeader(): Byte {
        val keyIndex = indexOfSubArray(ATT_STMT_KEY)
        assertThat(keyIndex).isAtLeast(0)
        return this[keyIndex + ATT_STMT_KEY.size]
    }

    private fun ByteArray.indexOfSubArray(pattern: ByteArray): Int {
        outer@ for (start in 0..size - pattern.size) {
            for (offset in pattern.indices) {
                if (this[start + offset] != pattern[offset]) {
                    continue@outer
                }
            }
            return start
        }
        return -1
    }

    private companion object {
        /** `67` - a text string of seven bytes - followed by "attStmt". */
        private val ATT_STMT_KEY = byteArrayOf(0x67) + "attStmt".toByteArray()
    }
}

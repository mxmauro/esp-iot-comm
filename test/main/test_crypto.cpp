#include <unity.h>
#include <iot_comm/crypto/aes.h>
#include <iot_comm/crypto/hkdf.h>
#include <iot_comm/crypto/p256.h>
#include <iot_comm/crypto/utils.h>
#include <mbedtls/ecp.h>
#include <mbedtls/gcm.h>
#include <string.h>

// -----------------------------------------------------------------------------

static void fillPattern(uint8_t *dest, size_t len, uint8_t seed)
{
    for (size_t i = 0; i < len; i++) {
        dest[i] = (uint8_t)(seed + i * 13);
    }
}

TEST_CASE("constantTimeCompare reports equality and inequality", "[crypto]")
{
    const uint8_t a[] = { 0x10, 0x20, 0x30, 0x40 };
    const uint8_t b[] = { 0x10, 0x20, 0x30, 0x40 };
    const uint8_t c[] = { 0x10, 0x20, 0x30, 0x41 };

    TEST_ASSERT_TRUE(constantTimeCompare(a, b, sizeof(a)));
    TEST_ASSERT_FALSE(constantTimeCompare(a, c, sizeof(a)));
}

TEST_CASE("hkdfSha256DeriveKey matches RFC5869 test vector", "[crypto]")
{
    const uint8_t ikm[22] = {
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b
    };
    const uint8_t salt[13] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
        0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c
    };
    const uint8_t info[10] = {
        0xf0, 0xf1, 0xf2, 0xf3, 0xf4,
        0xf5, 0xf6, 0xf7, 0xf8, 0xf9
    };
    const uint8_t expected[42] = {
        0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f,
        0x64, 0xd0, 0x36, 0x2f, 0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a,
        0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4, 0xc5, 0xbf, 0x34,
        0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65
    };
    uint8_t out[sizeof(expected)] = {0};

    TEST_ASSERT_EQUAL(ESP_OK, hkdfSha256DeriveKey(
        ikm, sizeof(ikm),
        salt, sizeof(salt),
        info, sizeof(info),
        out, sizeof(out)
    ));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected, out, sizeof(expected));
}

TEST_CASE("aesEncrypt and aesDecrypt roundtrip and detect tampering", "[crypto]")
{
    mbedtls_gcm_context ctx;
    uint8_t key[32];
    uint8_t iv[12];
    uint8_t aad[20];
    uint8_t plaintext[48];
    uint8_t ciphertext[sizeof(plaintext) + 16];
    uint8_t decrypted[sizeof(plaintext)];

    fillPattern(key, sizeof(key), 0x21);
    fillPattern(iv, sizeof(iv), 0x31);
    fillPattern(aad, sizeof(aad), 0x41);
    fillPattern(plaintext, sizeof(plaintext), 0x51);

    aesInit(&ctx);
    TEST_ASSERT_EQUAL(ESP_OK, aesSetKey(&ctx, key, sizeof(key)));
    TEST_ASSERT_EQUAL(ESP_OK, aesEncrypt(&ctx, plaintext, sizeof(plaintext), iv, sizeof(iv), aad, sizeof(aad), ciphertext));
    TEST_ASSERT_EQUAL(ESP_OK, aesDecrypt(&ctx, ciphertext, sizeof(ciphertext), iv, sizeof(iv), aad, sizeof(aad), decrypted));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(plaintext, decrypted, sizeof(plaintext));

    ciphertext[sizeof(ciphertext) - 1] ^= 0x80;
    TEST_ASSERT_NOT_EQUAL(ESP_OK, aesDecrypt(&ctx, ciphertext, sizeof(ciphertext), iv, sizeof(iv), aad, sizeof(aad), decrypted));
    aesDone(&ctx);
}

TEST_CASE("p256 public and private key base64 roundtrip works", "[crypto]")
{
    P256KeyPair_t original;
    P256KeyPair_t loaded;
    uint8_t publicKey[P256_PUBLIC_KEY_SIZE];
    uint8_t privateKey[P256_PRIVATE_KEY_SIZE];
    uint8_t loadedPublicKey[P256_PUBLIC_KEY_SIZE];
    uint8_t loadedPrivateKey[P256_PRIVATE_KEY_SIZE];
    char publicKeyB64[P256_MAX_B64_PUBLIC_KEY_SIZE];
    char privateKeyB64[P256_MAX_B64_PRIVATE_KEY_SIZE];
    size_t publicKeyB64Len = sizeof(publicKeyB64);
    size_t privateKeyB64Len = sizeof(privateKeyB64);

    p256KeyPairInit(&original);
    p256KeyPairInit(&loaded);

    TEST_ASSERT_EQUAL(ESP_OK, ecdsaGeneratePair(&original));
    TEST_ASSERT_EQUAL(ESP_OK, p256SavePublicKey(&original, publicKey));
    TEST_ASSERT_EQUAL(ESP_OK, p256SavePrivateKey(&original, privateKey));
    TEST_ASSERT_TRUE(p256ValidatePublicKey(publicKey, sizeof(publicKey)));

    TEST_ASSERT_EQUAL(ESP_OK, p256SavePublicKeyB64(&original, publicKeyB64, &publicKeyB64Len, false));
    TEST_ASSERT_EQUAL(ESP_OK, p256SavePrivateKeyB64(&original, privateKeyB64, &privateKeyB64Len, false));

    TEST_ASSERT_EQUAL(ESP_OK, p256LoadPublicKeyB64(&loaded, publicKeyB64, publicKeyB64Len, false));
    TEST_ASSERT_EQUAL(ESP_OK, p256LoadPrivateKeyB64(&loaded, privateKeyB64, privateKeyB64Len, false));
    TEST_ASSERT_EQUAL(ESP_OK, p256SavePublicKey(&loaded, loadedPublicKey));
    TEST_ASSERT_EQUAL(ESP_OK, p256SavePrivateKey(&loaded, loadedPrivateKey));

    TEST_ASSERT_EQUAL_HEX8_ARRAY(publicKey, loadedPublicKey, sizeof(publicKey));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(privateKey, loadedPrivateKey, sizeof(privateKey));

    p256KeyPairDone(&loaded);
    p256KeyPairDone(&original);
}

TEST_CASE("ecdh shared secret matches on both sides", "[crypto]")
{
    P256KeyPair_t alice;
    P256KeyPair_t bob;
    uint8_t alicePublic[P256_PUBLIC_KEY_SIZE];
    uint8_t bobPublic[P256_PUBLIC_KEY_SIZE];
    uint8_t aliceSecret[P256_SHARED_SECRET_SIZE];
    uint8_t bobSecret[P256_SHARED_SECRET_SIZE];

    p256KeyPairInit(&alice);
    p256KeyPairInit(&bob);

    TEST_ASSERT_EQUAL(ESP_OK, ecdhGeneratePair(&alice));
    TEST_ASSERT_EQUAL(ESP_OK, ecdhGeneratePair(&bob));

    TEST_ASSERT_EQUAL(ESP_OK, p256SavePublicKey(&alice, alicePublic));
    TEST_ASSERT_EQUAL(ESP_OK, p256SavePublicKey(&bob, bobPublic));

    TEST_ASSERT_EQUAL(ESP_OK, p256LoadPublicKey(&alice, bobPublic));
    TEST_ASSERT_EQUAL(ESP_OK, p256LoadPublicKey(&bob, alicePublic));

    TEST_ASSERT_EQUAL(ESP_OK, ecdhComputeSharedSecret(&alice, aliceSecret));
    TEST_ASSERT_EQUAL(ESP_OK, ecdhComputeSharedSecret(&bob, bobSecret));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(aliceSecret, bobSecret, sizeof(aliceSecret));

    p256KeyPairDone(&bob);
    p256KeyPairDone(&alice);
}

TEST_CASE("ecdsa sign and verify succeed", "[crypto]")
{
    P256KeyPair_t pair;
    uint8_t hash[P256_HASH_SIZE];
    uint8_t signature[P256_SIGNATURE_SIZE];

    fillPattern(hash, sizeof(hash), 0x61);
    p256KeyPairInit(&pair);

    TEST_ASSERT_EQUAL(ESP_OK, ecdsaGeneratePair(&pair));
    TEST_ASSERT_EQUAL(ESP_OK, ecdsaSign(&pair, hash, signature));
    TEST_ASSERT_EQUAL(ESP_OK, ecdsaVerify(&pair, hash, signature));

    p256KeyPairDone(&pair);
}

TEST_CASE("ecdsa verify reports invalid signature after tampering", "[crypto]")
{
    P256KeyPair_t pair;
    uint8_t hash[P256_HASH_SIZE];
    uint8_t signature[P256_SIGNATURE_SIZE];

    fillPattern(hash, sizeof(hash), 0x61);
    p256KeyPairInit(&pair);

    TEST_ASSERT_EQUAL(ESP_OK, ecdsaGeneratePair(&pair));
    TEST_ASSERT_EQUAL(ESP_OK, ecdsaSign(&pair, hash, signature));

    signature[0] ^= 0x01;
    TEST_ASSERT_EQUAL(MBEDTLS_ERR_ECP_VERIFY_FAILED, ecdsaVerify(&pair, hash, signature));

    p256KeyPairDone(&pair);
}

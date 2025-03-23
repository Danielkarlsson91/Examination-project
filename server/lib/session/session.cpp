#include "communication.h"
#include "session.h"
#include <Arduino.h>
#include <mbedtls/md.h>
#include <mbedtls/pk.h>
#include <mbedtls/rsa.h>
#include <mbedtls/aes.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>

constexpr int AES_SIZE{32};       /**< AES key size (256 bits) */
constexpr int AES_BLOCK_SIZE{16}; /**< AES block size (128 bits) */
constexpr int RSA_SIZE{256};      /**< RSA key size (2048 bits) */
constexpr int DER_SIZE{294};      /**< Maximum DER encoding size */
constexpr int HASH_SIZE{32};      /**< Hash size for HMAC (256 bits) */
constexpr int EXPONENT{65537};
constexpr int SESSION_TIMEOUT{3000}; /**< Session timeout in milliseconds */

// Static contexts for cryptographic operations
static mbedtls_aes_context aes_ctx;       /**< AES Context */
static mbedtls_md_context_t hmac_ctx;     /**< HMAC Context */
static mbedtls_pk_context client_key_ctx; /**< Client Public Key Context */
static mbedtls_pk_context server_key_ctx; /**< Server Public Key Context */
static mbedtls_entropy_context entropy;   /**< Entropy Context */
static mbedtls_ctr_drbg_context ctr_drbg; /**< CTR DRBG Context */

// Session variables
static uint32_t last_accessed = 0;
static uint64_t session_id = 0;
static uint8_t aes_key[AES_SIZE] = {0};
static uint8_t enc_lv[AES_BLOCK_SIZE]{0};
static uint8_t dec_lv[AES_BLOCK_SIZE]{0};
static uint8_t buffer[DER_SIZE + RSA_SIZE] = {0};
static const uint8_t secret_key[HASH_SIZE] = {
    0x29, 0x49, 0xde, 0xc2, 0x3e, 0x1e, 0x34, 0xb5,
    0x2d, 0x22, 0xba, 0x4c, 0x34, 0x23, 0x3a, 0x9d,
    0x3f, 0xe2, 0x97, 0x14, 0x24, 0x62, 0x81, 0x0c,
    0x86, 0xb1, 0xf6, 0x92, 0x54, 0xd6};

// Relay state pin
const int RELAY_PIN = 32;
const int LED_PIN = 21;

// Simple write with HMAC for key exchange
static bool write(const uint8_t *buf, size_t dlen)
{
    // Calculate HMAC
    uint8_t hmac[HASH_SIZE];
    mbedtls_md_hmac_starts(&hmac_ctx, secret_key, HASH_SIZE);
    mbedtls_md_hmac_update(&hmac_ctx, buf, dlen);
    mbedtls_md_hmac_finish(&hmac_ctx, hmac);

    // Prepare final buffer with payload and HMAC
    uint8_t final_buf[dlen + HASH_SIZE];
    memcpy(final_buf, buf, dlen);
    memcpy(final_buf + dlen, hmac, HASH_SIZE);

    // Send via communication layer
    return communication_write(final_buf, dlen + HASH_SIZE);
}

// Simple read with HMAC verification for key exchange
static size_t read(uint8_t *buf, size_t blen)
{
    size_t length = communication_read(buf, blen + HASH_SIZE);

    if (length > HASH_SIZE)
    {
        // Separate payload and HMAC
        size_t payload_length = length - HASH_SIZE;
        uint8_t received_hmac[HASH_SIZE];
        memcpy(received_hmac, buf + payload_length, HASH_SIZE);

        // Calculate HMAC of payload
        uint8_t calculated_hmac[HASH_SIZE];
        mbedtls_md_hmac_starts(&hmac_ctx, secret_key, HASH_SIZE);
        mbedtls_md_hmac_update(&hmac_ctx, buf, payload_length);
        mbedtls_md_hmac_finish(&hmac_ctx, calculated_hmac);

        // Verify HMAC
        if (memcmp(received_hmac, calculated_hmac, HASH_SIZE) == 0)
        {
            return payload_length;
        }

        delay(5000);
        printf("Received hmac\n");
        for (int i = 0; i < HASH_SIZE; i++)
        {
            printf("%.2X ", received_hmac[i]);
        }

        Serial.printf("\ncalculated hmac\n");

        for (int i = 0; i < HASH_SIZE; i++)
        {
            printf("%.2X ", calculated_hmac[i]);
        }
        printf("\nlength = %d\n", length);

        for (int i = 0; i < length; i++)
        {
            printf("%.2X ", buf[i]);
        }
        // HMAC verification failed
        return 0;
    }

    return 0;
}

// Client read with HMAC verification
static size_t client_read(uint8_t *buf, size_t blen)
{
    size_t length = communication_read(buf, blen + HASH_SIZE);

    if (length > HASH_SIZE)
    {
        // Separate payload and HMAC
        size_t payload_length = length - HASH_SIZE;
        uint8_t received_hmac[HASH_SIZE];
        memcpy(received_hmac, buf + payload_length, HASH_SIZE);

        // Calculate HMAC of payload
        uint8_t calculated_hmac[HASH_SIZE];
        mbedtls_md_hmac_starts(&hmac_ctx, secret_key, HASH_SIZE);
        mbedtls_md_hmac_update(&hmac_ctx, buf, payload_length);
        mbedtls_md_hmac_finish(&hmac_ctx, calculated_hmac);

        // Verify HMAC
        if (memcmp(received_hmac, calculated_hmac, HASH_SIZE) == 0)
        {
            // Decrypt payload if needed
            mbedtls_aes_setkey_dec(&aes_ctx, aes_key, AES_SIZE * 8);
            mbedtls_aes_crypt_cbc(&aes_ctx, MBEDTLS_AES_DECRYPT, payload_length,
                                  dec_lv, buf, buf);

            // Copy decrypted payload to output buffer
            memcpy(buf, buf, payload_length);
            return payload_length;
        }

        // HMAC verification failed
        return 0;
    }

    return 0;
}

// Client write with HMAC generation
static bool client_write(uint8_t *buf, size_t dlen)
{
    // Prepare buffer for encryption
    size_t padded_len = ((dlen + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
    uint8_t padded_buf[padded_len];
    memcpy(padded_buf, buf, dlen);

    // Pad with PKCS7
    uint8_t pad_value = padded_len - dlen;
    for (size_t i = dlen; i < padded_len; i++)
    {
        padded_buf[i] = pad_value;
    }

    // Encrypt payload
    mbedtls_aes_setkey_enc(&aes_ctx, aes_key, AES_SIZE * 8);
    mbedtls_aes_crypt_cbc(&aes_ctx, MBEDTLS_AES_ENCRYPT, padded_len,
                          enc_lv, padded_buf, padded_buf);

    // Calculate HMAC
    uint8_t hmac[HASH_SIZE];
    mbedtls_md_hmac_starts(&hmac_ctx, secret_key, HASH_SIZE);
    mbedtls_md_hmac_update(&hmac_ctx, padded_buf, padded_len);
    mbedtls_md_hmac_finish(&hmac_ctx, hmac);

    // Prepare final buffer with encrypted payload and HMAC
    uint8_t final_buf[padded_len + HASH_SIZE];
    memcpy(final_buf, padded_buf, padded_len);
    memcpy(final_buf + padded_len, hmac, HASH_SIZE);

    // Send via communication layer
    return communication_write(final_buf, sizeof(final_buf));
}

// Exchange public keys for secure communication
static int exchange_keys(void)
{
    // Initialize cryptographic contexts
    mbedtls_pk_init(&client_key_ctx);
    mbedtls_pk_init(&server_key_ctx);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    // Seed the random number generator
    const char *pers = "rsa_genkey";
    int ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                    (const unsigned char *)pers, strlen(pers));
    if (ret != 0)
    {
        return SESSION_ERROR;
    }

    // Read client public key
    uint8_t client_pub_key[RSA_SIZE * 2] = {0};
    size_t read_size = read(client_pub_key, RSA_SIZE * 2);

    delay(5000);
    Serial.printf("read size = %d", read_size);

    if (read_size == 0)
    {
        return SESSION_ERROR;
    }
    while (1)
    {
        digitalWrite(21, HIGH);
        delay(200);
        digitalWrite(21, LOW);
        delay(200);
    }

    // Parse client public key
    mbedtls_pk_context client_temp_pub_key_ctx;
    mbedtls_pk_init(&client_temp_pub_key_ctx);
    ret = mbedtls_pk_parse_public_key(&client_temp_pub_key_ctx, client_pub_key, read_size);
    if (ret != 0)
    {
        mbedtls_pk_free(&client_temp_pub_key_ctx);
        return SESSION_ERROR;
    }

    // Generate server keypair
    mbedtls_pk_context rsa_keys_ctx;
    mbedtls_pk_init(&rsa_keys_ctx);
    ret = mbedtls_pk_setup(&rsa_keys_ctx, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
    if (ret != 0)
    {
        mbedtls_pk_free(&client_temp_pub_key_ctx);
        mbedtls_pk_free(&rsa_keys_ctx);
        return SESSION_ERROR;
    }

    ret = mbedtls_rsa_gen_key(mbedtls_pk_rsa(rsa_keys_ctx),
                              mbedtls_ctr_drbg_random, &ctr_drbg,
                              2048, EXPONENT);
    if (ret != 0)
    {
        mbedtls_pk_free(&client_temp_pub_key_ctx);
        mbedtls_pk_free(&rsa_keys_ctx);
        return SESSION_ERROR;
    }

    // Serialize server public key in DER format
    uint8_t server_pub_key[DER_SIZE];
    ret = mbedtls_pk_write_pubkey_der(&rsa_keys_ctx, server_pub_key, DER_SIZE);
    if (ret < 0)
    {
        mbedtls_pk_free(&client_temp_pub_key_ctx);
        mbedtls_pk_free(&rsa_keys_ctx);
        return SESSION_ERROR;
    }

    // Encrypt server public key with client public key
    uint8_t enc_server_pub_key[RSA_SIZE * 2];
    size_t enc_size = 0;

    // Encrypt first half of the key
    ret = mbedtls_pk_encrypt(&client_temp_pub_key_ctx,
                             server_pub_key + (DER_SIZE - ret),
                             ret / 2,
                             enc_server_pub_key,
                             &enc_size,
                             RSA_SIZE,
                             mbedtls_ctr_drbg_random,
                             &ctr_drbg);
    if (ret != 0)
    {
        mbedtls_pk_free(&client_temp_pub_key_ctx);
        mbedtls_pk_free(&rsa_keys_ctx);
        return SESSION_ERROR;
    }

    // Encrypt second half of the key
    size_t enc_size2 = 0;
    ret = mbedtls_pk_encrypt(&client_temp_pub_key_ctx,
                             server_pub_key + (DER_SIZE - ret) + (ret / 2),
                             ret / 2,
                             enc_server_pub_key + RSA_SIZE,
                             &enc_size2,
                             RSA_SIZE,
                             mbedtls_ctr_drbg_random,
                             &ctr_drbg);
    if (ret != 0)
    {
        mbedtls_pk_free(&client_temp_pub_key_ctx);
        mbedtls_pk_free(&rsa_keys_ctx);
        return SESSION_ERROR;
    }

    // Send encrypted server public key
    if (!write(enc_server_pub_key, RSA_SIZE * 2))
    {
        mbedtls_pk_free(&client_temp_pub_key_ctx);
        mbedtls_pk_free(&rsa_keys_ctx);
        return SESSION_ERROR;
    }

    // Read client encrypted public key
    uint8_t enc_client_key[RSA_SIZE * 2];
    if (read(enc_client_key, RSA_SIZE * 2) != RSA_SIZE * 2)
    {
        mbedtls_pk_free(&client_temp_pub_key_ctx);
        mbedtls_pk_free(&rsa_keys_ctx);
        return SESSION_ERROR;
    }

    // Decrypt client public key
    uint8_t client_new_key[DER_SIZE];
    size_t client_key_len = 0;

    // Decrypt first half
    ret = mbedtls_pk_decrypt(&rsa_keys_ctx,
                             enc_client_key,
                             RSA_SIZE,
                             client_new_key,
                             &client_key_len,
                             DER_SIZE / 2,
                             mbedtls_ctr_drbg_random,
                             &ctr_drbg);
    if (ret != 0)
    {
        mbedtls_pk_free(&client_temp_pub_key_ctx);
        mbedtls_pk_free(&rsa_keys_ctx);
        return SESSION_ERROR;
    }

    // Decrypt second half
    size_t client_key_len2 = 0;
    ret = mbedtls_pk_decrypt(&rsa_keys_ctx,
                             enc_client_key + RSA_SIZE,
                             RSA_SIZE,
                             client_new_key + client_key_len,
                             &client_key_len2,
                             DER_SIZE / 2,
                             mbedtls_ctr_drbg_random,
                             &ctr_drbg);
    if (ret != 0)
    {
        mbedtls_pk_free(&client_temp_pub_key_ctx);
        mbedtls_pk_free(&rsa_keys_ctx);
        return SESSION_ERROR;
    }

    // Parse the decrypted client public key
    ret = mbedtls_pk_parse_public_key(&client_key_ctx, client_new_key, client_key_len + client_key_len2);
    if (ret != 0)
    {
        mbedtls_pk_free(&client_temp_pub_key_ctx);
        mbedtls_pk_free(&rsa_keys_ctx);
        return SESSION_ERROR;
    }

    // Send confirmation (1 byte)
    uint8_t confirm = 1;
    if (!write(&confirm, 1))
    {
        mbedtls_pk_free(&client_temp_pub_key_ctx);
        mbedtls_pk_free(&rsa_keys_ctx);
        return SESSION_ERROR;
    }

    // Store the server key context
    server_key_ctx = rsa_keys_ctx;

    // Free the temporary context
    mbedtls_pk_free(&client_temp_pub_key_ctx);

    return SESSION_OKAY;
}

// Write session data
static int session_write(const uint8_t *res, size_t size)
{
    // Check session validity
    if (millis() - last_accessed > SESSION_TIMEOUT)
    {
        return SESSION_ERROR;
    }

    // Write with HMAC protection
    uint8_t buf[size];
    memcpy(buf, res, size);

    return client_write(buf, size) ? SESSION_OKAY : SESSION_ERROR;
}

// Initialize session
int session_init(const int comparam)
{
    // Initialize communication
    if (!communication_init(comparam))
    {
        return SESSION_ERROR;
    }

    // Initialize cryptographic contexts
    mbedtls_md_init(&hmac_ctx);
    mbedtls_md_setup(&hmac_ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);

    mbedtls_aes_init(&aes_ctx);

    // Setup LED and Relay pins
    pinMode(LED_PIN, OUTPUT);
    pinMode(RELAY_PIN, OUTPUT);

    return SESSION_OKAY;
}

// Establish secure session
int session_establish(void)
{
    // Exchange keys
    int ret = exchange_keys();
    if (ret != SESSION_OKAY)
    {
        return SESSION_ERROR;
    }

    // Generate session ID
    uint8_t session_id_buf[8];
    mbedtls_ctr_drbg_random(&ctr_drbg, session_id_buf, sizeof(session_id_buf));
    memcpy(&session_id, session_id_buf, sizeof(session_id));

    // Send session establishment confirmation
    uint8_t response[9] = {SESSION_ESTABLISH};
    memcpy(response + 1, session_id_buf, 8);

    ret = session_write(response, sizeof(response));
    if (ret != SESSION_OKAY)
    {
        return SESSION_ERROR;
    }

    // Reset access time
    last_accessed = millis();

    // Signal successful establishment with LED
    digitalWrite(LED_PIN, HIGH);

    return SESSION_OKAY;
}

// Handle session request
int session_request(void)
{
    // Check session timeout
    if (millis() - last_accessed > SESSION_TIMEOUT)
    {
        return SESSION_ERROR;
    }

    // Update last accessed time
    last_accessed = millis();

    // Read incoming command
    uint8_t command[300];
    size_t len = client_read(command, sizeof(command));

    if (len < 32)
    {
        return SESSION_ERROR;
    }

    float temperature = 25.5; // Example temperature
    switch (command[0])
    {
    case SESSION_GET_TEMP:
        // Simulate temperature reading (replace with actual sensor reading)
        return session_send_temperature(temperature);

    case SESSION_TOGGLE_RELAY:
    {
        // Toggle relay state
        digitalWrite(RELAY_PIN, !digitalRead(RELAY_PIN));
        return session_send_relay_state(digitalRead(RELAY_PIN));
    }

    default:
        return SESSION_ERROR;
    }
}

// Close session
int session_close(void)
{
    // Disable LED and Relay
    digitalWrite(LED_PIN, LOW);
    digitalWrite(RELAY_PIN, LOW);

    // Reset session variables
    session_id = 0;
    last_accessed = 0;
    memset(aes_key, 0, sizeof(aes_key));

    // Close communication
    communication_close();

    // Clear cryptographic contexts
    mbedtls_md_free(&hmac_ctx);
    mbedtls_aes_free(&aes_ctx);
    mbedtls_pk_free(&client_key_ctx);
    mbedtls_pk_free(&server_key_ctx);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    return SESSION_OKAY;
}

// Send error message
int session_send_error(void)
{
    uint8_t error_msg[1] = {SESSION_ERROR};
    return session_write(error_msg, sizeof(error_msg));
}

// Send temperature
int session_send_temperature(float temp)
{
    uint8_t buf[5] = {SESSION_OKAY};
    memcpy(buf + 1, &temp, sizeof(float));
    return session_write(buf, sizeof(buf));
}

// Send relay state
int session_send_relay_state(uint8_t state)
{
    uint8_t buf[2] = {SESSION_OKAY, state};
    return session_write(buf, sizeof(buf));
}
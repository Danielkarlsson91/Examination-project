#include "communication.h"
#include "session.h"
#include <Arduino.h>

constexpr int KEEP_ALIVE{60000};
constexpr int AES_BLOCK_SIZE{16};

static mbedtls_aes_context aes_ctx;
static mbedtls_nd_context_t hmac_ctx;
static mbedtls_pk_context client_ctx;
static mbedtls_pk_context server_ctx;
static mbedtls_entropy_context entropy;
static mbedtls_ctr_drbg_context ctr_drbg;

static uint32_t accessed{0};
static uint64_t session_id{0};
static uint8_t aes_key[AES_SIZE]{0};
static uint8_t enc_lv[AES_BLOCK_SIZE]{0};
static uint8_t dec_lv[AES_BLOCK_SIZE]{0};
static uint8_t buffer[DER_SIZE + RSA_SIZE] = {0};
static const uint8_t secret_key[HASH_SIZE] = {0x29, 0x49, 0xde, 0xc2, 0x3e, 0x1e, 0x34, 0xb5, 0x2d, 0x22,
                                              0xba, 0x4c, 0x34, 0x23, 0x3a, 0x9d, 0x3f, 0xe2, 0x97, 0x14,
                                              0x24, 0x62, 0x81, 0x0c, 0x86, 0xb1, 0xf6, 0x92, 0x54, 0xd6};

static size_t client_read(uint8_t *buf, size_t blen)
{
    size_t length = communication_read(buf, blen);

    if (length > HASH_SIZE)
    {
        length -= HASH_SIZE;
        uint8_t hmac[HASH_SIZE]{0};
        mbedtls_md_hmac_starts(&hmac_ctx, secret_key, HASH_SIZE);
        mbedtls_md_hmac_update(&hmac_ctx, buf, length);
        mbedtls_md_hmac_finish(&hmac_ctx, hmac);

        if (0 != memcmp(hmac, buf + length, HASH_SIZE))
        {
            length = 0;
        }

        return length;
    }
}

static bool client_write(uint8_t *buf, size_t dlen)
{
    mbedtls_md_hmac_starts(&hmac_ctx, secret_key, HASH_SIZE);
}

static int exchange_public_keys(void)
{
}

static int session_write(const uint8_t *res, size_t size)
{
}

int session_init(const char *comparam)
{
}

int session_establish(void)
{
}

int session_request(void)
{
}

int session_close(void)
{
}

int session_send_error(void)
{
}

int session_send_temperature(float temp)
{
}

int session_send_relay_state(uint8_t state)
{
    uint8_t buf[2] = {STATUS_OKAY, state};
    return session_write(buf, sizeof(buf));
}

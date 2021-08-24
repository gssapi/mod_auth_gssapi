/* Copyright (C) 2014 mod_auth_gssapi contributors - See COPYING for (C) terms */

#include "config.h"
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <stdbool.h>
#include "crypto.h"

#ifndef HAVE_HMAC_CTX_NEW
HMAC_CTX *HMAC_CTX_new(void)
{
    HMAC_CTX *ctx;

    ctx = OPENSSL_malloc(sizeof(HMAC_CTX));
    if (!ctx) return NULL;

    HMAC_CTX_init(ctx);

    return ctx;
}

void HMAC_CTX_free(HMAC_CTX *ctx)
{
    if (ctx == NULL) return;

    HMAC_CTX_cleanup(ctx);
    OPENSSL_free(ctx);
}
#endif

#ifndef HAVE_EVP_CIPHER_CTX_NEW
EVP_CIPHER_CTX *EVP_CIPHER_CTX_new(void)
{
    EVP_CIPHER_CTX *ctx;

    ctx = OPENSSL_malloc(sizeof(EVP_CIPHER_CTX));
    if (!ctx) return NULL;

    EVP_CIPHER_CTX_init(ctx);

    return ctx;
}

void EVP_CIPHER_CTX_free(EVP_CIPHER_CTX *ctx)
{
    if (ctx == NULL) return;

    EVP_CIPHER_CTX_cleanup(ctx);
    OPENSSL_free(ctx);
}
#endif

struct seal_key {
    const EVP_CIPHER *cipher;
    const EVP_MD *md;
    unsigned char *ekey;
    unsigned char *hkey;
};

apr_status_t SEAL_KEY_CREATE(apr_pool_t *p, struct seal_key **skey,
                             struct databuf *keys)
{
    struct seal_key *n;
    int keylen;
    int ret;

    n = apr_pcalloc(p, sizeof(*n));
    if (!n) return ENOMEM;

    n->cipher = EVP_aes_128_cbc();
    if (!n->cipher) {
        ret = EFAULT;
        goto done;
    }

    keylen = EVP_CIPHER_key_length(n->cipher);

    n->md = EVP_sha256();
    if (!n->md) {
        ret = EFAULT;
        goto done;
    }

    n->ekey = apr_palloc(p, keylen);
    if (!n->ekey) {
        ret = ENOMEM;
        goto done;
    }

    n->hkey = apr_palloc(p, keylen);
    if (!n->hkey) {
        ret = ENOMEM;
        goto done;
    }

    if (keys) {
        if (keys->length != (keylen * 2)) {
            ret = EINVAL;
            goto done;
        }
        memcpy(n->ekey, keys->value, keylen);
        memcpy(n->hkey, keys->value + keylen, keylen);
    } else {
        ret = apr_generate_random_bytes(n->ekey, keylen);
        if (ret != 0) {
            ret = EFAULT;
            goto done;
        }

        ret = apr_generate_random_bytes(n->hkey, keylen);
        if (ret != 0) {
            ret = EFAULT;
            goto done;
        }
    }

    ret = 0;
done:
    if (ret == 0) {
        *skey = n;
    }
    return ret;
}

apr_status_t HMAC_BUFFER(struct seal_key *skey, struct databuf *buffer,
                         struct databuf *result)
{
    HMAC_CTX *hmac_ctx;
    unsigned int len;
    int ret = 0;

    /* now MAC the buffer */
    hmac_ctx = HMAC_CTX_new();
    if (!hmac_ctx) goto done;

    ret = HMAC_Init_ex(hmac_ctx, skey->hkey,
                       EVP_CIPHER_key_length(skey->cipher), skey->md, NULL);
    if (ret == 0) goto done;

    ret = HMAC_Update(hmac_ctx, buffer->value, buffer->length);
    if (ret == 0) goto done;

    ret = HMAC_Final(hmac_ctx, result->value, &len);

done:
    HMAC_CTX_free(hmac_ctx);
    if (ret == 0) return EFAULT;

    result->length = len;
    return 0;
}

apr_status_t SEAL_BUFFER(apr_pool_t *p, struct seal_key *skey,
                         struct databuf *plain, struct databuf *cipher)
{
    int blksz = EVP_CIPHER_block_size(skey->cipher);
    apr_status_t err = EFAULT;
    EVP_CIPHER_CTX *ctx;
    uint8_t rbuf[blksz];
    struct databuf hmacbuf;
    int outlen, totlen;
    int ret;

    ctx = EVP_CIPHER_CTX_new();

    /* confounder to avoid exposing random numbers directly to clients
     * as IVs */
    ret = apr_generate_random_bytes(rbuf, sizeof(rbuf));
    if (ret != 0) goto done;

    if (cipher->length == 0) {
        /* add space for confounder and padding and MAC */
        cipher->length = (plain->length / blksz + 2) * blksz;
        cipher->value = apr_palloc(p, cipher->length + EVP_MD_size(skey->md));
        if (!cipher->value) {
            err = ENOMEM;
            goto done;
        }
    }

    ret = EVP_EncryptInit_ex(ctx, skey->cipher, NULL, skey->ekey, NULL);
    if (ret == 0) goto done;
    totlen = 0;

    outlen = cipher->length;
    ret = EVP_EncryptUpdate(ctx, cipher->value, &outlen, rbuf, sizeof(rbuf));
    if (ret == 0) goto done;
    totlen += outlen;

    outlen = cipher->length - totlen;
    ret = EVP_EncryptUpdate(ctx, &cipher->value[totlen], &outlen,
                            plain->value, plain->length);
    if (ret == 0) goto done;
    totlen += outlen;

    outlen = cipher->length - totlen;
    ret = EVP_EncryptFinal_ex(ctx, &cipher->value[totlen], &outlen);
    if (ret == 0) goto done;
    totlen += outlen;

    /* now MAC the buffer */
    cipher->length = totlen;
    hmacbuf.value = &cipher->value[totlen];
    ret = HMAC_BUFFER(skey, cipher, &hmacbuf);
    if (ret != 0) goto done;

    cipher->length += hmacbuf.length;
    err = 0;

done:
    EVP_CIPHER_CTX_free(ctx);
    return err;
}

apr_status_t UNSEAL_BUFFER(apr_pool_t *p, struct seal_key *skey,
                           struct databuf *cipher, struct databuf *plain)
{
    apr_status_t err = EFAULT;
    EVP_CIPHER_CTX *ctx = NULL;
    int blksz = EVP_CIPHER_block_size(skey->cipher);
    int md_size = EVP_MD_size(skey->md);
    unsigned char mac[md_size];
    struct databuf hmacbuf;
    int outlen, totlen;
    volatile bool equal = true;
    int ret, i;

    /* check MAC first */
    cipher->length -= md_size;
    hmacbuf.value = mac;
    ret = HMAC_BUFFER(skey, cipher, &hmacbuf);
    if (ret != 0) goto done;

    if (hmacbuf.length != md_size) goto done;
    for (i = 0; i < md_size; i++) {
        if (cipher->value[cipher->length + i] != mac[i]) equal = false;
        /* not breaking intentionally,
         * or we would allow an oracle attack */
    }
    if (!equal) goto done;

    ctx = EVP_CIPHER_CTX_new();

    if (plain->length == 0) {
        plain->length = cipher->length;
        plain->value = apr_palloc(p, plain->length);
        if (!plain->value) {
            err = ENOMEM;
            goto done;
        }
    }

    ret = EVP_DecryptInit_ex(ctx, skey->cipher, NULL, skey->ekey, NULL);
    if (ret == 0) goto done;

    totlen = 0;
    outlen = plain->length;
    ret = EVP_DecryptUpdate(ctx, plain->value, &outlen,
                            cipher->value, cipher->length);
    if (ret == 0) goto done;

    totlen += outlen;
    outlen = plain->length - totlen;
    ret = EVP_DecryptFinal_ex(ctx, plain->value + totlen, &outlen);
    if (ret == 0) goto done;

    totlen += outlen;
    /* now remove the confounder */
    totlen -= blksz;
    memmove(plain->value, plain->value + blksz, totlen);

    plain->length = totlen;
    err = 0;

done:
    EVP_CIPHER_CTX_free(ctx);
    return err;
}

int get_mac_size(struct seal_key *skey)
{
    if (skey) {
        return EVP_MD_size(skey->md);
    } else {
        return 0;
    }
}

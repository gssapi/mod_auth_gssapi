/* Copyright (C) 2014 mod_auth_gssapi authors - See COPYING for (C) terms */

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <stdbool.h>
#include "crypto.h"

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

    keylen = n->cipher->key_len;

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
    if (ret) {
        free(n->ekey);
        free(n->hkey);
        free(n);
    } else {
        *skey = n;
    }
    return ret;
}

apr_status_t HMAC_BUFFER(struct seal_key *skey, struct databuf *buffer,
                         struct databuf *result)
{
    HMAC_CTX hmac_ctx = { 0 };
    unsigned int len;
    int ret;

    /* now MAC the buffer */
    HMAC_CTX_init(&hmac_ctx);

    ret = HMAC_Init_ex(&hmac_ctx, skey->hkey,
                       skey->cipher->key_len, skey->md, NULL);
    if (ret == 0) goto done;

    ret = HMAC_Update(&hmac_ctx, buffer->value, buffer->length);
    if (ret == 0) goto done;

    ret = HMAC_Final(&hmac_ctx, result->value, &len);

done:
    HMAC_CTX_cleanup(&hmac_ctx);
    if (ret == 0) return EFAULT;

    result->length = len;
    return 0;
}

apr_status_t SEAL_BUFFER(apr_pool_t *p, struct seal_key *skey,
                         struct databuf *plain, struct databuf *cipher)
{
    int blksz = skey->cipher->block_size;
    apr_status_t err = EFAULT;
    EVP_CIPHER_CTX ctx = { 0 };
    uint8_t rbuf[blksz];
    struct databuf hmacbuf;
    int outlen, totlen;
    int ret;

    EVP_CIPHER_CTX_init(&ctx);

    /* confounder to avoid exposing random numbers directly to clients
     * as IVs */
    ret = apr_generate_random_bytes(rbuf, sizeof(rbuf));
    if (ret != 0) goto done;

    if (cipher->length == 0) {
        /* add space for confounder and padding and MAC */
        cipher->length = (plain->length / blksz + 2) * blksz;
        cipher->value = apr_palloc(p, cipher->length + skey->md->md_size);
        if (!cipher->value) {
            err = ENOMEM;
            goto done;
        }
    }

    ret = EVP_EncryptInit_ex(&ctx, skey->cipher, NULL, skey->ekey, NULL);
    if (ret == 0) goto done;
    totlen = 0;

    outlen = cipher->length;
    ret = EVP_EncryptUpdate(&ctx, cipher->value, &outlen, rbuf, sizeof(rbuf));
    if (ret == 0) goto done;
    totlen += outlen;

    outlen = cipher->length - totlen;
    ret = EVP_EncryptUpdate(&ctx, &cipher->value[totlen], &outlen,
                            plain->value, plain->length);
    if (ret == 0) goto done;
    totlen += outlen;

    outlen = cipher->length - totlen;
    ret = EVP_EncryptFinal_ex(&ctx, &cipher->value[totlen], &outlen);
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
    EVP_CIPHER_CTX_cleanup(&ctx);
    return err;
}

apr_status_t UNSEAL_BUFFER(apr_pool_t *p, struct seal_key *skey,
                           struct databuf *cipher, struct databuf *plain)
{
    apr_status_t err = EFAULT;
    EVP_CIPHER_CTX ctx = { 0 };
    unsigned char mac[skey->md->md_size];
    struct databuf hmacbuf;
    int outlen, totlen;
    volatile bool equal = true;
    int ret, i;

    /* check MAC first */
    cipher->length -= skey->md->md_size;
    hmacbuf.value = mac;
    ret = HMAC_BUFFER(skey, cipher, &hmacbuf);
    if (ret != 0) goto done;

    if (hmacbuf.length != skey->md->md_size) goto done;
    for (i = 0; i < skey->md->md_size; i++) {
        if (cipher->value[cipher->length + i] != mac[i]) equal = false;
        /* not breaking intentionally,
         * or we would allow an oracle attack */
    }
    if (!equal) goto done;

    EVP_CIPHER_CTX_init(&ctx);

    if (plain->length == 0) {
        plain->length = cipher->length;
        plain->value = apr_palloc(p, plain->length);
        if (!plain->value) {
            err = ENOMEM;
            goto done;
        }
    }

    ret = EVP_DecryptInit_ex(&ctx, skey->cipher, NULL, skey->ekey, NULL);
    if (ret == 0) goto done;

    totlen = 0;
    outlen = plain->length;
    ret = EVP_DecryptUpdate(&ctx, plain->value, &outlen,
                            cipher->value, cipher->length);
    if (ret == 0) goto done;

    totlen += outlen;
    outlen = plain->length - totlen;
    ret = EVP_DecryptFinal_ex(&ctx, plain->value, &outlen);
    if (ret == 0) goto done;

    totlen += outlen;
    /* now remove the confounder */
    totlen -= skey->cipher->block_size;
    memmove(plain->value, plain->value + skey->cipher->block_size, totlen);

    plain->length = totlen;
    err = 0;

done:
    EVP_CIPHER_CTX_cleanup(&ctx);
    return err;
}

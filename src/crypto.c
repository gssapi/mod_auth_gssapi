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

apr_status_t SEAL_KEY_CREATE(struct seal_key **skey)
{
    struct seal_key *n;
    int ret;

    n = calloc(1, sizeof(*n));
    if (!n) return ENOMEM;

    n->cipher = EVP_aes_128_cbc();
    if (!n->cipher) {
        free(n);
        return EFAULT;
    }

    n->md = EVP_sha256();
    if (!n->md) {
        free(n);
        return EFAULT;
    }

    n->ekey = malloc(n->cipher->key_len);
    if (!n->ekey) {
        free(n);
        return ENOMEM;
    }

    n->hkey = malloc(n->cipher->key_len);
    if (!n->hkey) {
        free(n);
        return ENOMEM;
    }

    ret = RAND_bytes(n->ekey, n->cipher->key_len);
    if (ret == 0) {
        free(n->ekey);
        free(n->hkey);
        free(n);
        return EFAULT;
    }

    ret = RAND_bytes(n->hkey, n->cipher->key_len);
    if (ret == 0) {
        free(n->ekey);
        free(n->hkey);
        free(n);
        return EFAULT;
    }

    *skey = n;
    return 0;
}

apr_status_t SEAL_BUFFER(apr_pool_t *p, struct seal_key *skey,
                         struct databuf *plain, struct databuf *cipher)
{
    apr_status_t err = EFAULT;
    EVP_CIPHER_CTX ctx = { 0 };
    HMAC_CTX hmac_ctx = { 0 };
    uint8_t rbuf[16];
    unsigned int len;
    int outlen, totlen;
    int ret;

    EVP_CIPHER_CTX_init(&ctx);

    /* confounder to avoid exposing random numbers directly to clients
     * as IVs */
    ret = RAND_bytes(rbuf, 16);
    if (ret == 0) goto done;

    if (cipher->length == 0) {
        /* add space for confounder and padding and MAC */
        cipher->length = (plain->length / 16 + 2) * 16;
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
    ret = EVP_EncryptUpdate(&ctx, cipher->value, &outlen, rbuf, 16);
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
    HMAC_CTX_init(&hmac_ctx);

    ret = HMAC_Init_ex(&hmac_ctx, skey->hkey,
                       skey->cipher->key_len, skey->md, NULL);
    if (ret == 0) goto done;

    ret = HMAC_Update(&hmac_ctx, cipher->value, totlen);
    if (ret == 0) goto done;

    ret = HMAC_Final(&hmac_ctx, &cipher->value[totlen], &len);
    if (ret == 0) goto done;

    cipher->length = totlen + len;
    err = 0;

done:
    EVP_CIPHER_CTX_cleanup(&ctx);
    HMAC_CTX_cleanup(&hmac_ctx);
    return err;
}

apr_status_t UNSEAL_BUFFER(apr_pool_t *p, struct seal_key *skey,
                           struct databuf *cipher, struct databuf *plain)
{
    apr_status_t err = EFAULT;
    EVP_CIPHER_CTX ctx = { 0 };
    HMAC_CTX hmac_ctx = { 0 };
    unsigned char mac[skey->md->md_size];
    unsigned int len;
    int outlen, totlen;
    volatile bool equal = true;
    int ret, i;

    /* check MAC first */
    HMAC_CTX_init(&hmac_ctx);

    ret = HMAC_Init_ex(&hmac_ctx, skey->hkey,
                       skey->cipher->key_len, skey->md, NULL);
    if (ret == 0) goto done;

    cipher->length -= skey->md->md_size;

    ret = HMAC_Update(&hmac_ctx, cipher->value, cipher->length);
    if (ret == 0) goto done;

    ret = HMAC_Final(&hmac_ctx, mac, &len);
    if (ret == 0) goto done;

    if (len != skey->md->md_size) goto done;
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
    totlen -= 16;
    memmove(plain->value, plain->value + 16, totlen);

    plain->length = totlen;
    err = 0;

done:
    EVP_CIPHER_CTX_cleanup(&ctx);
    HMAC_CTX_cleanup(&hmac_ctx);
    return err;
}

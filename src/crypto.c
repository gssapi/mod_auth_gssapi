/* Copyright (C) 2014 mod_auth_gssapi authors - See COPYING for (C) terms */

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <stdbool.h>
#include "crypto.h"

#define TAGSIZE 16

struct seal_key {
    const EVP_CIPHER *cipher;
    unsigned char *ekey;
};

apr_status_t SEAL_KEY_CREATE(apr_pool_t *p, struct seal_key **skey,
                             struct databuf *key)
{
    struct seal_key *n;
    int keylen;
    int ret;

    n = apr_pcalloc(p, sizeof(*n));
    if (!n) return ENOMEM;

    n->cipher = EVP_aes_256_gcm();
    if (!n->cipher) {
        ret = EFAULT;
        goto done;
    }

    keylen = n->cipher->key_len;

    n->ekey = apr_palloc(p, keylen);
    if (!n->ekey) {
        ret = ENOMEM;
        goto done;
    }

    if (key) {
        if (key->length < keylen) {
            ret = EINVAL;
            goto done;
        }
        memcpy(n->ekey, key->value, keylen);
    } else {
        ret = apr_generate_random_bytes(n->ekey, keylen);
        if (ret != 0) {
            ret = EFAULT;
            goto done;
        }
    }

    ret = 0;
done:
    if (ret) {
        free(n->ekey);
        free(n);
    } else {
        *skey = n;
    }
    return ret;
}

apr_status_t SEAL_BUFFER(apr_pool_t *p, struct seal_key *skey,
                         struct databuf *plain, struct databuf *cipher)
{
    apr_status_t err = EFAULT;
    EVP_CIPHER_CTX ctx = {};
    int minlen;
    int outlen;
    int ret;

    EVP_CIPHER_CTX_init(&ctx);

	/* Add space for padding, IV and tag. */
    minlen = plain->length / skey->cipher->block_size + 1;
    minlen *= skey->cipher->block_size;
    minlen += skey->cipher->iv_len + TAGSIZE;
    if (cipher->length < minlen) {
        cipher->length = minlen;
        cipher->value = apr_palloc(p, cipher->length);
        if (!cipher->value) {
            err = ENOMEM;
            goto done;
        }
    }

    /* Generate IV. */
    ret = apr_generate_random_bytes(cipher->value, skey->cipher->iv_len);
    if (ret != 0) goto done;
    cipher->length = skey->cipher->iv_len;

    ret = EVP_EncryptInit_ex(&ctx, skey->cipher, NULL,
                             skey->ekey, cipher->value);
    if (ret != 1) goto done;

    /* Encrypt the data. */
    outlen = 0;
    ret = EVP_EncryptUpdate(&ctx, &cipher->value[cipher->length],
                            &outlen, plain->value, plain->length);
    if (ret != 1) goto done;
    cipher->length += outlen;

    outlen = 0;
    ret = EVP_EncryptFinal_ex(&ctx, &cipher->value[cipher->length], &outlen);
    if (ret != 1) goto done;
    cipher->length += outlen;

    /* Get the tag */
    ret = EVP_CIPHER_CTX_ctrl(&ctx, EVP_CTRL_GCM_GET_TAG, TAGSIZE,
                              &cipher->value[cipher->length]);
    if (ret != 1) goto done;
    cipher->length += TAGSIZE;

    err = 0;

done:
    EVP_CIPHER_CTX_cleanup(&ctx);
    return err;
}

apr_status_t UNSEAL_BUFFER(apr_pool_t *p, struct seal_key *skey,
                           struct databuf *cipher, struct databuf *plain)
{
    apr_status_t err = EFAULT;
    EVP_CIPHER_CTX ctx = {};
    int outlen;
    int ret;

    EVP_CIPHER_CTX_init(&ctx);

    if (plain->length < cipher->length - skey->cipher->iv_len - TAGSIZE) {
        plain->length = cipher->length - skey->cipher->iv_len - TAGSIZE;
        plain->value = apr_palloc(p, plain->length);
        if (!plain->value) {
            err = ENOMEM;
            goto done;
        }
    }

    ret = EVP_DecryptInit_ex(&ctx, skey->cipher, NULL,
                             skey->ekey, cipher->value);
    if (ret != 1) goto done;
    plain->length = 0;

    outlen = 0;
    ret = EVP_DecryptUpdate(&ctx, plain->value, &outlen,
                            &cipher->value[skey->cipher->iv_len],
                            cipher->length - skey->cipher->iv_len - TAGSIZE);
    if (ret != 1) goto done;
    plain->length += outlen;

    ret = EVP_CIPHER_CTX_ctrl(&ctx, EVP_CTRL_GCM_SET_TAG, TAGSIZE,
                              &cipher->value[cipher->length - TAGSIZE]);
    if (ret != 1) goto done;

    outlen = 0;
    ret = EVP_DecryptFinal_ex(&ctx, &plain->value[plain->length], &outlen);
    if (ret != 1) goto done;
    plain->length += outlen;

    err = 0;

done:
    EVP_CIPHER_CTX_cleanup(&ctx);
    return err;
}

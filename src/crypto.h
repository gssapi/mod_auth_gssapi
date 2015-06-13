/* Copyright (C) 2014 mod_auth_gssapi authors - See COPYING for (C) terms */

#include <apr_errno.h>
#include <apr_pools.h>

struct seal_key;

struct databuf {
    unsigned char *value;
    int length;
};

apr_status_t SEAL_KEY_CREATE(apr_pool_t *p, struct seal_key **skey,
                             struct databuf *keys);
apr_status_t HMAC_BUFFER(struct seal_key *skey, struct databuf *buffer,
                         struct databuf *result);
apr_status_t SEAL_BUFFER(apr_pool_t *p, struct seal_key *skey,
                         struct databuf *plain, struct databuf *cipher);
apr_status_t UNSEAL_BUFFER(apr_pool_t *p, struct seal_key *skey,
                           struct databuf *cipher, struct databuf *plain);

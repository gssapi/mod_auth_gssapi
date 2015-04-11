/* Copyright (C) 2014 mod_auth_gssapi authors - See COPYING for (C) terms */

#include "mod_auth_gssapi.h"
#include "asn1c/GSSSessionData.h"

APLOG_USE_MODULE(auth_gssapi);

static APR_OPTIONAL_FN_TYPE(ap_session_load) *mag_sess_load_fn = NULL;
static APR_OPTIONAL_FN_TYPE(ap_session_get) *mag_sess_get_fn = NULL;
static APR_OPTIONAL_FN_TYPE(ap_session_set) *mag_sess_set_fn = NULL;

void mag_post_config_session(void)
{
    mag_sess_load_fn = APR_RETRIEVE_OPTIONAL_FN(ap_session_load);
    mag_sess_get_fn = APR_RETRIEVE_OPTIONAL_FN(ap_session_get);
    mag_sess_set_fn = APR_RETRIEVE_OPTIONAL_FN(ap_session_set);
}

static apr_status_t mag_session_load(request_rec *req, session_rec **sess)
{
    if (mag_sess_load_fn) {
        return mag_sess_load_fn(req, sess);
    }
    return DECLINED;
}

static apr_status_t mag_session_get(request_rec *req, session_rec *sess,
                                    const char *key, const char **value)
{
    if (mag_sess_get_fn) {
        return mag_sess_get_fn(req, sess, key, value);
    }
    return DECLINED;
}

static apr_status_t mag_session_set(request_rec *req, session_rec *sess,
                                    const char *key, const char *value)
{
    if (mag_sess_set_fn) {
        return mag_sess_set_fn(req, sess, key, value);
    }
    return DECLINED;
}

static bool encode_GSSSessionData(apr_pool_t *mempool,
                                  GSSSessionData_t *gsessdata,
                                  unsigned char **buf, int *len)
{
    asn_enc_rval_t rval;
    unsigned char *buffer = NULL;
    size_t buflen;
    bool ret = false;

    /* dry run to compute the size */
    rval = der_encode(&asn_DEF_GSSSessionData, gsessdata, NULL, NULL);
    if (rval.encoded == -1) goto done;

    buflen = rval.encoded;
    buffer = apr_pcalloc(mempool, buflen);

    /* now for real */
    rval = der_encode_to_buffer(&asn_DEF_GSSSessionData,
                                gsessdata, buffer, buflen);
    if (rval.encoded == -1) goto done;

    *buf = buffer;
    *len = buflen;
    ret = true;

done:
    return ret;
}

static GSSSessionData_t *decode_GSSSessionData(void *buf, size_t len)
{
    GSSSessionData_t *gsessdata = NULL;
    asn_dec_rval_t rval;

    rval = ber_decode(NULL, &asn_DEF_GSSSessionData,
                      (void **)&gsessdata, buf, len);
    if (rval.code == RC_OK) {
        return gsessdata;
    }
    return NULL;
}

#define MAG_BEARER_KEY "MagBearerToken"

void mag_check_session(request_rec *req,
                       struct mag_config *cfg, struct mag_conn **conn)
{
    struct mag_conn *mc;
    apr_status_t rc;
    session_rec *sess = NULL;
    const char *sessval = NULL;
    int declen;
    struct databuf ctxbuf = { 0 };
    struct databuf cipherbuf = { 0 };
    GSSSessionData_t *gsessdata;
    time_t expiration;

    rc = mag_session_load(req, &sess);
    if (rc != OK || sess == NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_INFO|APLOG_NOERRNO, 0, req,
                      "Sessions not available, no cookies!");
        return;
    }

    mc = *conn;
    if (!mc) {
        mc = apr_pcalloc(req->pool, sizeof(struct mag_conn));
        if (!mc) return;

        mc->parent = req->pool;
        *conn = mc;
    }

    rc = mag_session_get(req, sess, MAG_BEARER_KEY, &sessval);
    if (rc != OK) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, req,
                      "Failed to get session data!");
        return;
    }
    if (!sessval) {
        /* no session established, just return */
        return;
    }

    if (!cfg->mag_skey) {
        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, req,
                      "Session key not available, no cookies!");
        /* we do not have a key, just return */
        return;
    }

    /* decode it */
    declen = apr_base64_decode_len(sessval);
    cipherbuf.value = apr_palloc(req->pool, declen);
    if (!cipherbuf.value) return;
    cipherbuf.length = (int)apr_base64_decode((char *)cipherbuf.value, sessval);

    rc = UNSEAL_BUFFER(req->pool, cfg->mag_skey, &cipherbuf, &ctxbuf);
    if (rc != OK) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, req,
                      "Failed to unseal session data!");
        return;
    }

    gsessdata = decode_GSSSessionData(ctxbuf.value, ctxbuf.length);
    if (!gsessdata) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, req,
                      "Failed to unpack session data!");
        return;
    }

    /* booleans */
    if (gsessdata->established != 0) mc->established = true;
    if (gsessdata->delegated != 0) mc->delegated = true;

    /* get time */
    expiration = gsessdata->expiration;
    if (expiration < time(NULL)) {
        /* credentials fully expired, return nothing */
        goto done;
    }

    /* user name */
    mc->user_name = apr_pstrndup(mc->parent,
                                 (char *)gsessdata->username.buf,
                                 gsessdata->username.size);
    if (!mc->user_name) goto done;

    /* gssapi name */
    mc->gss_name = apr_pstrndup(mc->parent,
                                (char *)gsessdata->gssname.buf,
                                gsessdata->gssname.size);
    if (!mc->gss_name) goto done;

    /* OK we have a valid token */
    mc->established = true;

done:
    ASN_STRUCT_FREE(asn_DEF_GSSSessionData, gsessdata);
}

void mag_attempt_session(request_rec *req,
                         struct mag_config *cfg, struct mag_conn *mc)
{
    session_rec *sess = NULL;
    struct databuf plainbuf = { 0 };
    struct databuf cipherbuf = { 0 };
    struct databuf ctxbuf = { 0 };
    GSSSessionData_t gsessdata = { 0 };
    apr_status_t rc;
    bool ret;

    /* we save the session only if the authentication is established */

    if (!mc->established) return;
    rc = mag_session_load(req, &sess);
    if (rc != OK || sess == NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, req,
                      "Sessions not available, can't send cookies!");
        return;
    }

    if (!cfg->mag_skey) {
        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, req,
                      "Session key not available, generating new one.");
        rc = SEAL_KEY_CREATE(cfg->pool, &cfg->mag_skey, NULL);
        if (rc != OK) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, req,
                          "Failed to create sealing key!");
            return;
        }
    }

    gsessdata.established = mc->established?1:0;
    gsessdata.delegated = mc->delegated?1:0;
    gsessdata.expiration = mc->expiration;
    if (OCTET_STRING_fromString(&gsessdata.username, mc->user_name) != 0)
        goto done;
    if (OCTET_STRING_fromString(&gsessdata.gssname, mc->gss_name) != 0)
        goto done;
    ret = encode_GSSSessionData(req->pool, &gsessdata,
                                &plainbuf.value, &plainbuf.length);
    if (ret == false) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, req,
                      "Failed to pack session data!");
        goto done;
    }

    rc = SEAL_BUFFER(req->pool, cfg->mag_skey, &plainbuf, &cipherbuf);
    if (rc != OK) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, req,
                      "Failed to seal session data!");
        goto done;
    }

    ctxbuf.length = apr_base64_encode_len(cipherbuf.length);
    ctxbuf.value = apr_pcalloc(req->pool, ctxbuf.length);
    if (!ctxbuf.value) goto done;

    ctxbuf.length = apr_base64_encode((char *)ctxbuf.value,
                                      (char *)cipherbuf.value,
                                      cipherbuf.length);

    rc = mag_session_set(req, sess, MAG_BEARER_KEY, (char *)ctxbuf.value);
    if (rc != OK) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, req,
                      "Failed to set session data!");
    }

done:
    ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_GSSSessionData, &gsessdata);
}


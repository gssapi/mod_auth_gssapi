/* Copyright (C) 2014 mod_auth_gssapi authors - See COPYING for (C) terms */

#include "mod_auth_gssapi.h"

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
    char *next, *last;
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

    /* get time */
    next = apr_strtok((char *)ctxbuf.value, ":", &last);
    expiration = (time_t)apr_atoi64(next);
    if (expiration < time(NULL)) {
        /* credentials fully expired, return nothing */
        return;
    }

    /* user name is next */
    next = apr_strtok(NULL, ":", &last);
    mc->user_name = apr_pstrdup(mc->parent, next);
    if (!mc->user_name) return;

    /* gssapi name (often a principal) is last.
     * (because it may contain the separator as a valid char we
     * just read last as is, without further tokenizing */
    mc->gss_name = apr_pstrdup(mc->parent, last);
    if (!mc->gss_name) return;

    /* OK we have a valid token */
    mc->established = true;
}

void mag_attempt_session(request_rec *req,
                         struct mag_config *cfg, struct mag_conn *mc)
{
    session_rec *sess = NULL;
    char *sessval = NULL;
    struct databuf plainbuf = { 0 };
    struct databuf cipherbuf = { 0 };
    struct databuf ctxbuf = { 0 };
    apr_status_t rc;

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

    sessval = apr_psprintf(req->pool, "%ld:%s:%s",
                           (long)mc->expiration, mc->user_name, mc->gss_name);
    if (!sessval) return;

    plainbuf.length = strlen(sessval) + 1;
    plainbuf.value = (unsigned char *)sessval;

    rc = SEAL_BUFFER(req->pool, cfg->mag_skey, &plainbuf, &cipherbuf);
    if (rc != OK) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, req,
                      "Failed to seal session data!");
        return;
    }

    ctxbuf.length = apr_base64_encode_len(cipherbuf.length);
    ctxbuf.value = apr_pcalloc(req->pool, ctxbuf.length);
    if (!ctxbuf.value) return;

    ctxbuf.length = apr_base64_encode((char *)ctxbuf.value,
                                      (char *)cipherbuf.value,
                                      cipherbuf.length);

    rc = mag_session_set(req, sess, MAG_BEARER_KEY, (char *)ctxbuf.value);
    if (rc != OK) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, req,
                      "Failed to set session data!");
        return;
    }
}


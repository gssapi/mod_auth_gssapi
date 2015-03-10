/*
   MOD AUTH GSSAPI

   Copyright (C) 2014 Simo Sorce <simo@redhat.com>

   Permission is hereby granted, free of charge, to any person obtaining a
   copy of this software and associated documentation files (the "Software"),
   to deal in the Software without restriction, including without limitation
   the rights to use, copy, modify, merge, publish, distribute, sublicense,
   and/or sell copies of the Software, and to permit persons to whom the
   Software is furnished to do so, subject to the following conditions:

   The above copyright notice and this permission notice shall be included in
   all copies or substantial portions of the Software.

   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
   THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
   FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
   DEALINGS IN THE SOFTWARE.
*/

#include "mod_auth_gssapi.h"

#define MOD_AUTH_GSSAPI_VERSION PACKAGE_NAME "/" PACKAGE_VERSION

module AP_MODULE_DECLARE_DATA auth_gssapi_module;

APLOG_USE_MODULE(auth_gssapi);

APR_DECLARE_OPTIONAL_FN(int, ssl_is_https, (conn_rec *));

static char *mag_status(request_rec *req, int type, uint32_t err)
{
    uint32_t maj_ret, min_ret;
    gss_buffer_desc text;
    uint32_t msg_ctx;
    char *msg_ret;
    int len;

    msg_ret = NULL;
    msg_ctx = 0;
    do {
        maj_ret = gss_display_status(&min_ret, err, type,
                                     GSS_C_NO_OID, &msg_ctx, &text);
        if (maj_ret != GSS_S_COMPLETE) {
            return msg_ret;
        }

        len = text.length;
        if (msg_ret) {
            msg_ret = apr_psprintf(req->pool, "%s, %*s",
                                   msg_ret, len, (char *)text.value);
        } else {
            msg_ret = apr_psprintf(req->pool, "%*s", len, (char *)text.value);
        }
        gss_release_buffer(&min_ret, &text);
    } while (msg_ctx != 0);

    return msg_ret;
}

static char *mag_error(request_rec *req, const char *msg,
                       uint32_t maj, uint32_t min)
{
    char *msg_maj;
    char *msg_min;

    msg_maj = mag_status(req, GSS_C_GSS_CODE, maj);
    msg_min = mag_status(req, GSS_C_MECH_CODE, min);
    return apr_psprintf(req->pool, "%s: [%s (%s)]", msg, msg_maj, msg_min);
}

static APR_OPTIONAL_FN_TYPE(ssl_is_https) *mag_is_https = NULL;

static int mag_post_config(apr_pool_t *cfgpool, apr_pool_t *log,
                           apr_pool_t *temp, server_rec *s)
{
    /* FIXME: create mutex to deal with connections and contexts ? */
    mag_is_https = APR_RETRIEVE_OPTIONAL_FN(ssl_is_https);
    mag_post_config_session();
    ap_add_version_component(cfgpool, MOD_AUTH_GSSAPI_VERSION);

    return OK;
}

static int mag_pre_connection(conn_rec *c, void *csd)
{
    struct mag_conn *mc;

    mc = apr_pcalloc(c->pool, sizeof(struct mag_conn));
    if (!mc) return DECLINED;

    mc->parent = c->pool;
    ap_set_module_config(c->conn_config, &auth_gssapi_module, (void*)mc);
    return OK;
}

static apr_status_t mag_conn_destroy(void *ptr)
{
    struct mag_conn *mc = (struct mag_conn *)ptr;
    uint32_t min;

    if (mc->ctx) {
        (void)gss_delete_sec_context(&min, &mc->ctx, GSS_C_NO_BUFFER);
        mc->established = false;
    }
    return APR_SUCCESS;
}

static bool mag_conn_is_https(conn_rec *c)
{
    if (mag_is_https) {
        if (mag_is_https(c)) return true;
    }

    return false;
}

static void mag_store_deleg_creds(request_rec *req,
                                  char *dir, char *clientname,
                                  gss_cred_id_t delegated_cred,
                                  char **ccachefile)
{
    gss_key_value_element_desc element;
    gss_key_value_set_desc store;
    char *value;
    uint32_t maj, min;

    value = apr_psprintf(req->pool, "FILE:%s/%s", dir, clientname);
    if (!value) {
        ap_log_error(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, NULL,
                     "OOM storing delegated credentials");
        return;
    }

    element.key = "ccache";
    element.value = value;
    store.elements = &element;
    store.count = 1;

    maj = gss_store_cred_into(&min, delegated_cred, GSS_C_INITIATE,
                              GSS_C_NULL_OID, 1, 1, &store, NULL, NULL);
    if (GSS_ERROR(maj)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, req, "%s",
                      mag_error(req, "failed to store delegated creds",
                                maj, min));
    }

    *ccachefile = value;
}

static int mag_auth(request_rec *req)
{
    const char *type;
    const char *auth_type;
    struct mag_config *cfg;
    const char *auth_header;
    char *auth_header_type;
    char *auth_header_value;
    int ret = HTTP_UNAUTHORIZED;
    gss_ctx_id_t ctx = GSS_C_NO_CONTEXT;
    gss_ctx_id_t *pctx;
    gss_buffer_desc input = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc output = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc name = GSS_C_EMPTY_BUFFER;
    gss_name_t client = GSS_C_NO_NAME;
    gss_cred_id_t user_cred = GSS_C_NO_CREDENTIAL;
    gss_cred_id_t acquired_cred = GSS_C_NO_CREDENTIAL;
    gss_cred_id_t delegated_cred = GSS_C_NO_CREDENTIAL;
    gss_cred_usage_t cred_usage = GSS_C_ACCEPT;
    uint32_t flags;
    uint32_t vtime;
    uint32_t maj, min;
    char *reply;
    size_t replen;
    char *clientname;
    gss_OID mech_type = GSS_C_NO_OID;
    gss_buffer_desc lname = GSS_C_EMPTY_BUFFER;
    struct mag_conn *mc = NULL;
    bool is_basic = false;
    gss_ctx_id_t user_ctx = GSS_C_NO_CONTEXT;
    gss_name_t server = GSS_C_NO_NAME;
#ifdef HAVE_GSS_KRB5_CCACHE_NAME
    const char *user_ccache = NULL;
    char *orig_ccache = NULL;
#endif

    type = ap_auth_type(req);
    if ((type == NULL) || (strcasecmp(type, "GSSAPI") != 0)) {
        return DECLINED;
    }

    /* ignore auth for subrequests */
    if (!ap_is_initial_req(req)) {
        return OK;
    }

    cfg = ap_get_module_config(req->per_dir_config, &auth_gssapi_module);

    if (cfg->ssl_only) {
        if (!mag_conn_is_https(req->connection)) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, req,
                          "Not a TLS connection, refusing to authenticate!");
            goto done;
        }
    }

    if (cfg->gss_conn_ctx) {
        mc = (struct mag_conn *)ap_get_module_config(
                                                req->connection->conn_config,
                                                &auth_gssapi_module);
        if (!mc) {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, req,
                          "Failed to retrieve connection context!");
            goto done;
        }
    }

    /* if available, session always supersedes connection bound data */
    if (cfg->use_sessions) {
        mag_check_session(req, cfg, &mc);
    }

    if (mc) {
        /* register the context in the memory pool, so it can be freed
         * when the connection/request is terminated */
        apr_pool_userdata_set(mc, "mag_conn_ptr",
                              mag_conn_destroy, mc->parent);

        if (mc->established) {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG|APLOG_NOERRNO, 0, req,
                          "Already established context found!");
            apr_table_set(req->subprocess_env, "GSS_NAME", mc->gss_name);
            req->ap_auth_type = apr_pstrdup(req->pool, mc->auth_type);
            req->user = apr_pstrdup(req->pool, mc->user_name);
            ret = OK;
            goto done;
        }
        pctx = &mc->ctx;
    } else {
        pctx = &ctx;
    }

    auth_header = apr_table_get(req->headers_in, "Authorization");
    if (!auth_header) goto done;

    auth_header_type = ap_getword_white(req->pool, &auth_header);
    if (!auth_header_type) goto done;

    if (strcasecmp(auth_header_type, "Negotiate") == 0) {
        auth_type = "Negotiate";

        auth_header_value = ap_getword_white(req->pool, &auth_header);
        if (!auth_header_value) goto done;
        input.length = apr_base64_decode_len(auth_header_value) + 1;
        input.value = apr_pcalloc(req->pool, input.length);
        if (!input.value) goto done;
        input.length = apr_base64_decode(input.value, auth_header_value);
    } else if ((strcasecmp(auth_header_type, "Basic") == 0) &&
               (cfg->use_basic_auth == true)) {
        auth_type = "Basic";
        is_basic = true;

        gss_buffer_desc ba_user;
        gss_buffer_desc ba_pwd;

        ba_pwd.value = ap_pbase64decode(req->pool, auth_header);
        if (!ba_pwd.value) goto done;
        ba_user.value = ap_getword_nulls_nc(req->pool,
                                            (char **)&ba_pwd.value, ':');
        if (!ba_user.value) goto done;
        if (((char *)ba_user.value)[0] == '\0' ||
            ((char *)ba_pwd.value)[0] == '\0') {
            ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, req,
                          "Invalid empty user or password for Basic Auth");
            goto done;
        }
        ba_user.length = strlen(ba_user.value);
        ba_pwd.length = strlen(ba_pwd.value);
        maj = gss_import_name(&min, &ba_user, GSS_C_NT_USER_NAME, &client);
        if (GSS_ERROR(maj)) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, req,
                          "In Basic Auth, %s",
                          mag_error(req, "gss_import_name() failed",
                                    maj, min));
            goto done;
        }
#ifdef HAVE_GSS_KRB5_CCACHE_NAME
        /* Set a per-thread ccache in case we are using kerberos,
         * it is not elegant but avoids interference between threads */
        long long unsigned int rndname;
        apr_status_t rs;
        rs = apr_generate_random_bytes((unsigned char *)(&rndname),
                                       sizeof(long long unsigned int));
        if (rs != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, req,
                          "Failed to generate random ccache name");
            goto done;
        }
        user_ccache = apr_psprintf(req->pool, "MEMORY:user_%qu", rndname);
        maj = gss_krb5_ccache_name(&min, user_ccache,
                                   (const char **)&orig_ccache);
        if (GSS_ERROR(maj)) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, req,
                          "In Basic Auth, %s",
                          mag_error(req, "gss_krb5_ccache_name() "
                                    "failed", maj, min));
            goto done;
        }
#endif
        maj = gss_acquire_cred_with_password(&min, client, &ba_pwd,
                                             GSS_C_INDEFINITE,
                                             GSS_C_NO_OID_SET,
                                             GSS_C_INITIATE,
                                             &user_cred, NULL, NULL);
        if (GSS_ERROR(maj)) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, req,
                          "In Basic Auth, %s",
                          mag_error(req, "gss_acquire_cred_with_password() "
                                    "failed", maj, min));
            goto done;
        }
        gss_release_name(&min, &client);
    } else {
        goto done;
    }

    req->ap_auth_type = apr_pstrdup(req->pool, auth_type);

#ifdef HAVE_GSS_ACQUIRE_CRED_FROM
    if (cfg->use_s4u2proxy) {
        cred_usage = GSS_C_BOTH;
    }
    if (cfg->cred_store) {
        maj = gss_acquire_cred_from(&min, GSS_C_NO_NAME, GSS_C_INDEFINITE,
                                    GSS_C_NO_OID_SET, cred_usage,
                                    cfg->cred_store, &acquired_cred,
                                    NULL, NULL);
        if (GSS_ERROR(maj)) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, req, "%s",
                          mag_error(req, "gss_acquire_cred_from() failed",
                                    maj, min));
            goto done;
        }
    }
#endif

    if (is_basic) {
        if (!acquired_cred) {
            /* Try to acquire default creds */
            maj = gss_acquire_cred(&min, GSS_C_NO_NAME, GSS_C_INDEFINITE,
                                   GSS_C_NO_OID_SET, cred_usage,
                                   &acquired_cred, NULL, NULL);
            if (GSS_ERROR(maj)) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, req,
                              "%s", mag_error(req, "gss_acquire_cred_from()"
                                              " failed", maj, min));
                goto done;
            }
        }
        maj = gss_inquire_cred(&min, acquired_cred, &server,
                               NULL, NULL, NULL);
        if (GSS_ERROR(maj)) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, req,
                          "%s", mag_error(req, "gss_inquired_cred_() "
                                          "failed", maj, min));
            goto done;
        }
        /* output and input are inverted here, this is intentional */
        maj = gss_init_sec_context(&min, user_cred, &user_ctx, server,
                                   GSS_C_NO_OID, 0, 300,
                                   GSS_C_NO_CHANNEL_BINDINGS, &output,
                                   NULL, &input, NULL, NULL);
        if (GSS_ERROR(maj)) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, req,
                          "%s", mag_error(req, "gss_init_sec_context() "
                                          "failed", maj, min));
            goto done;
        }
    }

    maj = gss_accept_sec_context(&min, pctx, acquired_cred,
                                 &input, GSS_C_NO_CHANNEL_BINDINGS,
                                 &client, &mech_type, &output, &flags, &vtime,
                                 &delegated_cred);
    if (GSS_ERROR(maj)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, req, "%s",
                      mag_error(req, "gss_accept_sec_context() failed",
                                maj, min));
        goto done;
    }
    if (is_basic) {
        while (maj == GSS_S_CONTINUE_NEEDED) {
            gss_release_buffer(&min, &input);
            /* output and input are inverted here, this is intentional */
            maj = gss_init_sec_context(&min, user_cred, &user_ctx, server,
                                       GSS_C_NO_OID, 0, 300,
                                       GSS_C_NO_CHANNEL_BINDINGS, &output,
                                       NULL, &input, NULL, NULL);
            if (GSS_ERROR(maj)) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, req,
                              "%s", mag_error(req, "gss_init_sec_context() "
                                              "failed", maj, min));
                goto done;
            }
            gss_release_buffer(&min, &output);
            maj = gss_accept_sec_context(&min, pctx, acquired_cred,
                                         &input, GSS_C_NO_CHANNEL_BINDINGS,
                                         &client, &mech_type, &output, &flags,
                                         &vtime, &delegated_cred);
            if (GSS_ERROR(maj)) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, req,
                              "%s", mag_error(req, "gss_accept_sec_context()"
                                              " failed", maj, min));
                goto done;
            }
        }
    } else if (maj == GSS_S_CONTINUE_NEEDED) {
        if (!mc) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, req,
                          "Mechanism needs continuation but neither "
                          "GssapiConnectionBound nor "
                          "GssapiUseSessions are available");
            gss_delete_sec_context(&min, pctx, GSS_C_NO_BUFFER);
            gss_release_buffer(&min, &output);
            output.length = 0;
        }
        /* auth not complete send token and wait next packet */
        goto done;
    }

    /* Always set the GSS name in an env var */
    maj = gss_display_name(&min, client, &name, NULL);
    if (GSS_ERROR(maj)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, req, "%s",
                      mag_error(req, "gss_display_name() failed",
                                maj, min));
        goto done;
    }
    clientname = apr_pstrndup(req->pool, name.value, name.length);
    apr_table_set(req->subprocess_env, "GSS_NAME", clientname);

#ifdef HAVE_GSS_STORE_CRED_INTO
    if (cfg->deleg_ccache_dir && delegated_cred != GSS_C_NO_CREDENTIAL) {
        char *ccachefile = NULL;

        mag_store_deleg_creds(req, cfg->deleg_ccache_dir, clientname,
                              delegated_cred, &ccachefile);

        if (ccachefile) {
            apr_table_set(req->subprocess_env, "KRB5CCNAME", ccachefile);
        }
    }
#endif

    if (cfg->map_to_local) {
        maj = gss_localname(&min, client, mech_type, &lname);
        if (maj != GSS_S_COMPLETE) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, req, "%s",
                          mag_error(req, "gss_localname() failed", maj, min));
            goto done;
        }
        req->user = apr_pstrndup(req->pool, lname.value, lname.length);
    } else {
        req->user = clientname;
    }

    if (mc) {
        mc->user_name = apr_pstrdup(mc->parent, req->user);
        mc->gss_name = apr_pstrdup(mc->parent, clientname);
        mc->established = true;
        if (vtime == GSS_C_INDEFINITE || vtime < MIN_SESS_EXP_TIME) {
            vtime = MIN_SESS_EXP_TIME;
        }
        mc->expiration = time(NULL) + vtime;
        if (cfg->use_sessions) {
            mag_attempt_session(req, cfg, mc);
        }
        mc->auth_type = auth_type;
    }

    ret = OK;

done:
    if (ret == HTTP_UNAUTHORIZED) {
        if (output.length != 0) {
            replen = apr_base64_encode_len(output.length) + 1;
            reply = apr_pcalloc(req->pool, 10 + replen);
            if (reply) {
                memcpy(reply, "Negotiate ", 10);
                apr_base64_encode(&reply[10], output.value, output.length);
                apr_table_add(req->err_headers_out,
                              "WWW-Authenticate", reply);
            }
        } else {
            apr_table_add(req->err_headers_out,
                          "WWW-Authenticate", "Negotiate");
            if (cfg->use_basic_auth) {
                apr_table_add(req->err_headers_out,
                              "WWW-Authenticate",
                              apr_psprintf(req->pool, "Basic realm=\"%s\"",
                                           ap_auth_name(req)));
            }
        }
    }
#ifdef HAVE_GSS_KRB5_CCACHE_NAME
    if (user_ccache != NULL) {
        maj = gss_krb5_ccache_name(&min, orig_ccache, NULL);
        if (maj != GSS_S_COMPLETE) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, req,
                          "Failed to restore per-thread ccache, %s",
                          mag_error(req, "gss_krb5_ccache_name() "
                                    "failed", maj, min));
        }
    }
    free(orig_ccache);
    orig_ccache = NULL;
#endif
    gss_delete_sec_context(&min, &user_ctx, &output);
    gss_release_cred(&min, &user_cred);
    gss_release_cred(&min, &acquired_cred);
    gss_release_cred(&min, &delegated_cred);
    gss_release_buffer(&min, &output);
    gss_release_name(&min, &client);
    gss_release_name(&min, &server);
    gss_release_buffer(&min, &name);
    gss_release_buffer(&min, &lname);
    return ret;
}


static void *mag_create_dir_config(apr_pool_t *p, char *dir)
{
    struct mag_config *cfg;

    cfg = (struct mag_config *)apr_pcalloc(p, sizeof(struct mag_config));
    if (!cfg) return NULL;
    cfg->pool = p;

    return cfg;
}

static const char *mag_ssl_only(cmd_parms *parms, void *mconfig, int on)
{
    struct mag_config *cfg = (struct mag_config *)mconfig;
    cfg->ssl_only = on ? true : false;
    return NULL;
}

static const char *mag_map_to_local(cmd_parms *parms, void *mconfig, int on)
{
    struct mag_config *cfg = (struct mag_config *)mconfig;
    cfg->map_to_local = on ? true : false;
    return NULL;
}

static const char *mag_conn_ctx(cmd_parms *parms, void *mconfig, int on)
{
    struct mag_config *cfg = (struct mag_config *)mconfig;
    cfg->gss_conn_ctx = on ? true : false;
    return NULL;
}

static const char *mag_use_sess(cmd_parms *parms, void *mconfig, int on)
{
    struct mag_config *cfg = (struct mag_config *)mconfig;
    cfg->use_sessions = on ? true : false;
    return NULL;
}

static const char *mag_use_s4u2p(cmd_parms *parms, void *mconfig, int on)
{
    struct mag_config *cfg = (struct mag_config *)mconfig;
    cfg->use_s4u2proxy = on ? true : false;

    if (cfg->deleg_ccache_dir == NULL) {
        cfg->deleg_ccache_dir = apr_pstrdup(parms->pool, "/tmp");
        if (!cfg->deleg_ccache_dir) {
            ap_log_error(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0,
                         parms->server, "%s", "OOM setting deleg_ccache_dir.");
        }
    }
    return NULL;
}

static const char *mag_sess_key(cmd_parms *parms, void *mconfig, const char *w)
{
    struct mag_config *cfg = (struct mag_config *)mconfig;
    struct databuf keys;
    unsigned char *val;
    apr_status_t rc;
    const char *k;
    int l;

    if (strncmp(w, "key:", 4) != 0) {
        ap_log_error(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, parms->server,
                     "Invalid key format, expected prefix 'key:'");
        return NULL;
    }
    k = w + 4;

    l = apr_base64_decode_len(k);
    val = apr_palloc(parms->temp_pool, l);
    if (!val) {
        ap_log_error(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, parms->server,
                     "Failed to get memory to decode key");
        return NULL;
    }

    keys.length = (int)apr_base64_decode_binary(val, k);
    keys.value = (unsigned char *)val;

    if (keys.length != 32) {
        ap_log_error(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, parms->server,
                     "Invalid key lenght, expected 32 got %d", keys.length);
        return NULL;
    }

    rc = SEAL_KEY_CREATE(cfg->pool, &cfg->mag_skey, &keys);
    if (rc != OK) {
        ap_log_error(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, parms->server,
                     "Failed to import sealing key!");
    }
    return NULL;
}

#define MAX_CRED_OPTIONS 10

static const char *mag_cred_store(cmd_parms *parms, void *mconfig,
                                  const char *w)
{
    struct mag_config *cfg = (struct mag_config *)mconfig;
    gss_key_value_element_desc *elements;
    uint32_t count;
    size_t size;
    const char *p;
    char *value;
    char *key;

    p = strchr(w, ':');
    if (!p) {
        ap_log_error(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, parms->server,
                     "%s [%s]", "Invalid syntax for GssapiCredStore option", w);
        return NULL;
    }

    key = apr_pstrndup(parms->pool, w, (p-w));
    value = apr_pstrdup(parms->pool, p + 1);
    if (!key || !value) {
        ap_log_error(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, parms->server,
                     "%s", "OOM handling GssapiCredStore option");
        return NULL;
    }

    if (!cfg->cred_store) {
        cfg->cred_store = apr_pcalloc(parms->pool,
                                      sizeof(gss_key_value_set_desc));
        if (!cfg->cred_store) {
            ap_log_error(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, parms->server,
                         "%s", "OOM handling GssapiCredStore option");
            return NULL;
        }
        size = sizeof(gss_key_value_element_desc) * MAX_CRED_OPTIONS;
        cfg->cred_store->elements = apr_palloc(parms->pool, size);
        if (!cfg->cred_store->elements) {
            ap_log_error(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, parms->server,
                         "%s", "OOM handling GssapiCredStore option");
        }
    }

    elements = cfg->cred_store->elements;
    count = cfg->cred_store->count;

    if (count >= MAX_CRED_OPTIONS) {
        ap_log_error(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, parms->server,
                     "Too many GssapiCredStore options (MAX: %d)",
                     MAX_CRED_OPTIONS);
        return NULL;
    }
    cfg->cred_store->count++;

    elements[count].key = key;
    elements[count].value = value;

    return NULL;
}

static const char *mag_deleg_ccache_dir(cmd_parms *parms, void *mconfig,
                                        const char *value)
{
    struct mag_config *cfg = (struct mag_config *)mconfig;

    cfg->deleg_ccache_dir = apr_pstrdup(parms->pool, value);
    if (!cfg->deleg_ccache_dir) {
        ap_log_error(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, parms->server,
                     "%s", "OOM handling GssapiDelegCcacheDir option");
    }

    return NULL;
}

static const char *mag_use_basic_auth(cmd_parms *parms, void *mconfig, int on)
{
    struct mag_config *cfg = (struct mag_config *)mconfig;

    cfg->use_basic_auth = on ? true : false;
    return NULL;
}

static const command_rec mag_commands[] = {
    AP_INIT_FLAG("GssapiSSLonly", mag_ssl_only, NULL, OR_AUTHCFG,
                  "Work only if connection is SSL Secured"),
    AP_INIT_FLAG("GssapiLocalName", mag_map_to_local, NULL, OR_AUTHCFG,
                  "Translate principals to local names"),
    AP_INIT_FLAG("GssapiConnectionBound", mag_conn_ctx, NULL, OR_AUTHCFG,
                  "Authentication is bound to the TCP connection"),
    AP_INIT_FLAG("GssapiUseSessions", mag_use_sess, NULL, OR_AUTHCFG,
                  "Authentication uses mod_sessions to hold status"),
    AP_INIT_RAW_ARGS("GssapiSessionKey", mag_sess_key, NULL, OR_AUTHCFG,
                     "Key Used to seal session data."),
#ifdef HAVE_GSS_ACQUIRE_CRED_FROM
    AP_INIT_FLAG("GssapiUseS4U2Proxy", mag_use_s4u2p, NULL, OR_AUTHCFG,
                  "Initializes credentials for s4u2proxy usage"),
#endif
#ifdef HAVE_GSS_STORE_CRED_INTO
    AP_INIT_ITERATE("GssapiCredStore", mag_cred_store, NULL, OR_AUTHCFG,
                    "Credential Store"),
    AP_INIT_RAW_ARGS("GssapiDelegCcacheDir", mag_deleg_ccache_dir, NULL,
                     OR_AUTHCFG, "Directory to store delegated credentials"),
#endif
#ifdef HAVE_GSS_ACQUIRE_CRED_WITH_PASSWORD
    AP_INIT_FLAG("GssapiBasicAuth", mag_use_basic_auth, NULL, OR_AUTHCFG,
                     "Allows use of Basic Auth for authentication"),
#endif
    { NULL }
};

static void
mag_register_hooks(apr_pool_t *p)
{
    ap_hook_check_user_id(mag_auth, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_post_config(mag_post_config, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_pre_connection(mag_pre_connection, NULL, NULL, APR_HOOK_MIDDLE);
}

module AP_MODULE_DECLARE_DATA auth_gssapi_module =
{
    STANDARD20_MODULE_STUFF,
    mag_create_dir_config,
    NULL,
    NULL,
    NULL,
    mag_commands,
    mag_register_hooks
};

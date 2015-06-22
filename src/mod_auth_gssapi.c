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

const gss_OID_desc gss_mech_spnego = {
    6, "\x2b\x06\x01\x05\x05\x02"
};

const gss_OID_desc gss_mech_ntlmssp = {
    GSS_NTLMSSP_OID_LENGTH, GSS_NTLMSSP_OID_STRING
};

const gss_OID_set_desc gss_mech_set_ntlmssp = {
    1, discard_const(&gss_mech_ntlmssp)
};

#define MOD_AUTH_GSSAPI_VERSION PACKAGE_NAME "/" PACKAGE_VERSION

module AP_MODULE_DECLARE_DATA auth_gssapi_module;

APLOG_USE_MODULE(auth_gssapi);

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

    mc = mag_new_conn_ctx(c->pool);
    ap_set_module_config(c->conn_config, &auth_gssapi_module, (void*)mc);
    return OK;
}

static apr_status_t mag_conn_destroy(void *ptr)
{
    struct mag_conn *mc = (struct mag_conn *)ptr;
    uint32_t min;

    if (mc->ctx) {
        (void)gss_delete_sec_context(&min, &mc->ctx, GSS_C_NO_BUFFER);
    }
    return APR_SUCCESS;
}

struct mag_conn *mag_new_conn_ctx(apr_pool_t *pool)
{
    struct mag_conn *mc;

    mc = apr_pcalloc(pool, sizeof(struct mag_conn));
    apr_pool_create(&mc->pool, pool);
    /* register the context in the memory pool, so it can be freed
     * when the connection/request is terminated */
    apr_pool_cleanup_register(mc->pool, (void *)mc,
                              mag_conn_destroy, apr_pool_cleanup_null);

    return mc;
}

static void mag_conn_clear(struct mag_conn *mc)
{
    (void)mag_conn_destroy(mc);
    apr_pool_t *temp;

    apr_pool_clear(mc->pool);
    temp = mc->pool;
    memset(mc, 0, sizeof(struct mag_conn));
    mc->pool = temp;
}

static bool mag_conn_is_https(conn_rec *c)
{
    if (mag_is_https) {
        if (mag_is_https(c)) return true;
    }

    return false;
}

static bool mag_acquire_creds(request_rec *req,
                              struct mag_config *cfg,
                              gss_OID_set desired_mechs,
                              gss_cred_usage_t cred_usage,
                              gss_cred_id_t *creds,
                              gss_OID_set *actual_mechs)
{
    uint32_t maj, min;
#ifdef HAVE_CRED_STORE
    gss_const_key_value_set_t store = cfg->cred_store;

    maj = gss_acquire_cred_from(&min, GSS_C_NO_NAME, GSS_C_INDEFINITE,
                                desired_mechs, cred_usage, store, creds,
                                actual_mechs, NULL);
#else
    maj = gss_acquire_cred(&min, GSS_C_NO_NAME, GSS_C_INDEFINITE,
                           desired_mechs, cred_usage, creds,
                           actual_mechs, NULL);
#endif

    if (GSS_ERROR(maj)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, req, "%s",
                      mag_error(req, "gss_acquire_cred[_from]() "
                                "failed to get server creds",
                                maj, min));
        return false;
    }

    return true;
}

#ifdef HAVE_CRED_STORE
static char *escape(apr_pool_t *pool, const char *name,
                    char find, const char *replace)
{
    char *escaped = NULL;
    char *namecopy;
    char *n;
    char *p;

    namecopy = apr_pstrdup(pool, name);

    p = strchr(namecopy, find);
    if (!p) return namecopy;

    /* first segment */
    n = namecopy;
    while (p) {
        /* terminate previous segment */
        *p = '\0';
        if (escaped) {
            escaped = apr_pstrcat(pool, escaped, n, replace, NULL);
        } else {
            escaped = apr_pstrcat(pool, n, replace, NULL);
        }
        /* move to next segment */
        n = p + 1;
        p = strchr(n, find);
    }
    /* append last segment if any */
    if (*n) {
        escaped = apr_pstrcat(pool, escaped, n, NULL);
    }

    return escaped;
}

static char *mag_gss_name_to_ccache_name(request_rec *req,
                                         char *dir, const char *gss_name)
{
    char *escaped;

    /* We need to escape away '/', we can't have path separators in
     * a ccache file name */
    /* first double escape the esacping char (~) if any */
    escaped = escape(req->pool, gss_name, '~', "~~");
    /* then escape away the separator (/) if any */
    escaped = escape(req->pool, escaped, '/', "~");

    return apr_psprintf(req->pool, "%s/%s", dir, escaped);
}

static void mag_set_KRB5CCANME(request_rec *req, char *ccname)
{
    apr_status_t status;
    apr_finfo_t finfo;
    char *value;

    status = apr_stat(&finfo, ccname, APR_FINFO_MIN, req->pool);
    if (status != APR_SUCCESS && status != APR_INCOMPLETE) {
        /* set the file cache anyway, but warn */
        ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, req,
                      "KRB5CCNAME file (%s) lookup failed!", ccname);
    }

    value = apr_psprintf(req->pool, "FILE:%s", ccname);
    apr_table_set(req->subprocess_env, "KRB5CCNAME", value);
}

static void mag_store_deleg_creds(request_rec *req,
                                  char *dir, char *clientname,
                                  gss_cred_id_t delegated_cred,
                                  char **ccachefile)
{
    gss_key_value_element_desc element;
    gss_key_value_set_desc store;
    char *ccname;
    uint32_t maj, min;
    element.key = "ccache";
    store.elements = &element;
    store.count = 1;

    ccname = mag_gss_name_to_ccache_name(req, dir, clientname);
    element.value = apr_psprintf(req->pool, "FILE:%s", ccname);

    maj = gss_store_cred_into(&min, delegated_cred, GSS_C_INITIATE,
                              GSS_C_NULL_OID, 1, 1, &store, NULL, NULL);
    if (GSS_ERROR(maj)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, req, "%s",
                      mag_error(req, "failed to store delegated creds",
                                maj, min));
    }

    *ccachefile = ccname;
}
#endif

static bool parse_auth_header(apr_pool_t *pool, const char **auth_header,
                              gss_buffer_t value)
{
    char *auth_header_value;

    auth_header_value = ap_getword_white(pool, auth_header);
    if (!auth_header_value) return false;
    value->length = apr_base64_decode_len(auth_header_value) + 1;
    value->value = apr_pcalloc(pool, value->length);
    if (!value->value) return false;
    value->length = apr_base64_decode(value->value, auth_header_value);

    return true;
}

static bool is_mech_allowed(struct mag_config *cfg, gss_const_OID mech)
{
    if (cfg->allowed_mechs == GSS_C_NO_OID_SET) return true;

    for (int i = 0; i < cfg->allowed_mechs->count; i++) {
        if (gss_oid_equal(&cfg->allowed_mechs->elements[i], mech)) {
            return true;
        }
    }
    return false;
}

#define AUTH_TYPE_NEGOTIATE 0
#define AUTH_TYPE_BASIC 1
#define AUTH_TYPE_RAW_NTLM 2
const char *auth_types[] = {
    "Negotiate",
    "Basic",
    "NTLM",
    NULL
};

static void mag_set_req_data(request_rec *req,
                             struct mag_config *cfg,
                             struct mag_conn *mc)
{
    apr_table_set(req->subprocess_env, "GSS_NAME", mc->gss_name);
    apr_table_set(req->subprocess_env, "GSS_SESSION_EXPIRATION",
                  apr_psprintf(req->pool,
                               "%ld", (long)mc->expiration));
    req->ap_auth_type = apr_pstrdup(req->pool,
                                    auth_types[mc->auth_type]);
    req->user = apr_pstrdup(req->pool, mc->user_name);
    if (cfg->deleg_ccache_dir && mc->delegated) {
        char *ccname;
        ccname = mag_gss_name_to_ccache_name(req,
                                             cfg->deleg_ccache_dir,
                                             mc->gss_name);
        if (ccname) {
            mag_set_KRB5CCANME(req, ccname);
        }
    }
}

gss_OID_set mag_filter_unwanted_mechs(gss_OID_set src)
{
    gss_const_OID unwanted_mechs[] = {
        &gss_mech_spnego,
        gss_mech_krb5_old,
        gss_mech_krb5_wrong,
        gss_mech_iakerb,
        GSS_C_NO_OID
    };
    gss_OID_set dst;
    uint32_t maj, min;
    int present = 0;

    for (int i = 0; unwanted_mechs[i] != GSS_C_NO_OID; i++) {
        maj = gss_test_oid_set_member(&min,
                                      discard_const(unwanted_mechs[i]),
                                      src, &present);
        if (present) break;
    }
    if (present) {
        maj = gss_create_empty_oid_set(&min, &dst);
        if (maj != GSS_S_COMPLETE) {
            return GSS_C_NO_OID_SET;
        }
        for (int i = 0; i < src->count; i++) {
            present = 0;
            for (int j = 0; unwanted_mechs[j] != GSS_C_NO_OID; j++) {
                if (gss_oid_equal(&src->elements[i], unwanted_mechs[j])) {
                    present = 1;
                    break;
                }
            }
            if (present) continue;
            maj = gss_add_oid_set_member(&min, &src->elements[i], &dst);
            if (maj != GSS_S_COMPLETE) {
                gss_release_oid_set(&min, &dst);
                return GSS_C_NO_OID_SET;
            }
        }
        return dst;
    }
    return src;
}

static bool mag_auth_basic(request_rec *req,
                           struct mag_config *cfg,
                           gss_buffer_desc ba_user,
                           gss_buffer_desc ba_pwd,
                           gss_cred_usage_t cred_usage,
                           gss_name_t *client,
                           gss_OID *mech_type,
                           gss_cred_id_t *delegated_cred,
                           uint32_t *vtime)
{
#ifdef HAVE_GSS_KRB5_CCACHE_NAME
    const char *user_ccache = NULL;
    const char *orig_ccache = NULL;
    long long unsigned int rndname;
    apr_status_t rs;
#endif
    gss_name_t user = GSS_C_NO_NAME;
    gss_cred_id_t user_cred = GSS_C_NO_CREDENTIAL;
    gss_ctx_id_t user_ctx = GSS_C_NO_CONTEXT;
    gss_name_t server = GSS_C_NO_NAME;
    gss_cred_id_t server_cred = GSS_C_NO_CREDENTIAL;
    gss_ctx_id_t server_ctx = GSS_C_NO_CONTEXT;
    gss_cred_id_t acquired_cred = GSS_C_NO_CREDENTIAL;
    gss_buffer_desc input = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc output = GSS_C_EMPTY_BUFFER;
    gss_OID_set indicated_mechs = GSS_C_NO_OID_SET;
    gss_OID_set allowed_mechs;
    gss_OID_set filtered_mechs;
    gss_OID_set actual_mechs = GSS_C_NO_OID_SET;
    uint32_t init_flags = 0;
    uint32_t maj, min;
    int present = 0;
    bool ret = false;

    maj = gss_import_name(&min, &ba_user, GSS_C_NT_USER_NAME, &user);
    if (GSS_ERROR(maj)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, req,
                      "In Basic Auth, %s",
                      mag_error(req, "gss_import_name() failed",
                                maj, min));
        goto done;
    }

    if (cfg->basic_mechs) {
        allowed_mechs = cfg->basic_mechs;
    } else if (cfg->allowed_mechs) {
        allowed_mechs = cfg->allowed_mechs;
    } else {
        /* Try to fetch the default set if not explicitly configured,
         * We need to do this because gss_acquire_cred_with_password()
         * is currently limited to acquire creds for a single "default"
         * mechanism if no desired mechanisms are passed in. This causes
         * authentication to fail for secondary mechanisms as no user
         * credentials are generated for those. */
        maj = gss_indicate_mechs(&min, &indicated_mechs);
        if (maj != GSS_S_COMPLETE) {
            ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, req, "%s",
                          mag_error(req, "gss_indicate_mechs() failed",
                                    maj, min));
            /* if indicated _mechs failed, set GSS_C_NO_OID_SET. This
             * generally causes only the krb5 mechanism to be tried due
             * to implementation constraints, but may change in future. */
            allowed_mechs = GSS_C_NO_OID_SET;
        } else {
            allowed_mechs = indicated_mechs;
        }
    }

    /* Remove Spnego if present, or we'd repeat failed authentiations
     * multiple times, one within Spnego and then again with an explicit
     * mechanism. We would normally just force Spnego and use
     * gss_set_neg_mechs, but due to the way we source the server name
     * and the fact MIT up to 1.14 at least does no handle union names,
     * we can't provide spnego with a server name that can be used by
     * multiple mechanisms, causing any but the first mechanism to fail.
     * Also remove unwanted krb mechs, or AS requests will be repeated
     * multiple times uselessly.
     */
    filtered_mechs = mag_filter_unwanted_mechs(allowed_mechs);
    if (filtered_mechs == GSS_C_NO_OID_SET) {
        ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, req, "Fatal "
                      "failure while filtering mechs, aborting");
        goto done;
    } else if (filtered_mechs != allowed_mechs) {
        /* if indicated_mechs where sourced then free them here before
         * reusing the pointer */
        gss_release_oid_set(&min, &indicated_mechs);

        /* mark the list of mechs needs to be freed */
        indicated_mechs = filtered_mechs;

        /* use the filtered list */
        allowed_mechs = filtered_mechs;
    }

#ifdef HAVE_GSS_KRB5_CCACHE_NAME
    /* If we are using the krb5 mechanism make sure to set a per thread
     * memory ccache so that there can't be interferences between threads.
     * Also make sure we have  new cache so no cached results end up being
     * used. Some implementations of gss_acquire_cred_with_password() do
     * not reacquire creds if cached ones are around, failing to check
     * again for the password. */
    maj = gss_test_oid_set_member(&min, discard_const(gss_mech_krb5),
                                  allowed_mechs, &present);
    if (GSS_ERROR(maj)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, req,
                      "In Basic Auth, %s",
                      mag_error(req, "gss_test_oid_set_member() failed",
                                maj, min));
        goto done;
    }
    if (present) {
        rs = apr_generate_random_bytes((unsigned char *)(&rndname),
                                       sizeof(long long unsigned int));
        if (rs != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, req,
                          "Failed to generate random ccache name");
            goto done;
        }
        user_ccache = apr_psprintf(req->pool, "MEMORY:user_%qu", rndname);
        maj = gss_krb5_ccache_name(&min, user_ccache, &orig_ccache);
        if (GSS_ERROR(maj)) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, req,
                          "In Basic Auth, %s",
                          mag_error(req, "gss_krb5_ccache_name() "
                                    "failed", maj, min));
            goto done;
        }
    }
#endif

    maj = gss_acquire_cred_with_password(&min, user, &ba_pwd,
                                         GSS_C_INDEFINITE,
                                         allowed_mechs,
                                         GSS_C_INITIATE,
                                         &user_cred, &actual_mechs, NULL);
    if (GSS_ERROR(maj)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, req,
                      "In Basic Auth, %s",
                      mag_error(req, "gss_acquire_cred_with_password() "
                                "failed", maj, min));
        goto done;
    }

    /* must acquire creds based on the actual mechs we want to try */
    if (!mag_acquire_creds(req, cfg, actual_mechs,
                           GSS_C_BOTH, &acquired_cred, NULL)) {
        goto done;
    }

    if (cred_usage == GSS_C_BOTH) {
        /* must acquire with GSS_C_ACCEPT to get the server name */
        if (!mag_acquire_creds(req, cfg, actual_mechs,
                               GSS_C_ACCEPT, &server_cred, NULL)) {
            goto done;
        }
    } else {
        server_cred = acquired_cred;
    }

#ifdef HAVE_CRED_STORE
    if (cfg->deleg_ccache_dir) {
        /* delegate ourselves credentials so we store them as requested */
        init_flags |= GSS_C_DELEG_FLAG;
    }
#endif

    for (int i = 0; i < actual_mechs->count; i++) {

        /* skip spnego if present */
        if (gss_oid_equal(&actual_mechs->elements[i],
                          &gss_mech_spnego)) {
            continue;
        }

        /* free these if looping */
        gss_release_buffer(&min, &output);
        gss_release_buffer(&min, &input);
        gss_release_name(&min, &server);

        maj = gss_inquire_cred_by_mech(&min, server_cred,
                                       &actual_mechs->elements[i],
                                       &server, NULL, NULL, NULL);
        if (GSS_ERROR(maj)) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, req,
                          "%s", mag_error(req, "gss_inquired_cred_by_mech() "
                                          "failed", maj, min));
            continue;
        }

        do {
            /* output and input are inverted here, this is intentional */
            maj = gss_init_sec_context(&min, user_cred, &user_ctx, server,
                                       &actual_mechs->elements[i], init_flags,
                                       300, GSS_C_NO_CHANNEL_BINDINGS, &output,
                                       NULL, &input, NULL, NULL);
            if (GSS_ERROR(maj)) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, req,
                              "%s", mag_error(req, "gss_init_sec_context() "
                                              "failed", maj, min));
                break;
            }
            gss_release_buffer(&min, &output);
            maj = gss_accept_sec_context(&min, &server_ctx, acquired_cred,
                                         &input, GSS_C_NO_CHANNEL_BINDINGS,
                                         client, mech_type, &output, NULL,
                                         vtime, delegated_cred);
            if (GSS_ERROR(maj)) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, req,
                              "%s", mag_error(req, "gss_accept_sec_context()"
                                              " failed", maj, min));
                break;
            }
            gss_release_buffer(&min, &input);
        } while (maj == GSS_S_CONTINUE_NEEDED);

        if (maj == GSS_S_COMPLETE) {
            ret = true;
            break;
        }
    }

done:
    gss_release_buffer(&min, &output);
    gss_release_buffer(&min, &input);
    gss_release_name(&min, &server);
    if (server_cred != acquired_cred)
        gss_release_cred(&min, &server_cred);
    gss_delete_sec_context(&min, &server_ctx, GSS_C_NO_BUFFER);
    gss_release_cred(&min, &acquired_cred);
    gss_release_name(&min, &user);
    gss_release_cred(&min, &user_cred);
    gss_delete_sec_context(&min, &user_ctx, GSS_C_NO_BUFFER);
    gss_release_oid_set(&min, &actual_mechs);
    gss_release_oid_set(&min, &indicated_mechs);
#ifdef HAVE_GSS_KRB5_CCACHE_NAME
    if (user_ccache != NULL) {
        maj = gss_krb5_ccache_name(&min, orig_ccache, NULL);
        if (maj != GSS_S_COMPLETE) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, req,
                          "Failed to restore per-thread ccache, %s",
                          mag_error(req, "gss_krb5_ccache_name() "
                                    "failed", maj, min));
        }
    }
#endif
    return ret;
}


static int mag_auth(request_rec *req)
{
    const char *type;
    int auth_type = -1;
    struct mag_config *cfg;
    const char *auth_header;
    char *auth_header_type;
    int ret = HTTP_UNAUTHORIZED;
    gss_ctx_id_t ctx = GSS_C_NO_CONTEXT;
    gss_ctx_id_t *pctx;
    gss_buffer_desc input = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc output = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc name = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc ba_user;
    gss_buffer_desc ba_pwd;
    gss_name_t client = GSS_C_NO_NAME;
    gss_cred_id_t acquired_cred = GSS_C_NO_CREDENTIAL;
    gss_cred_id_t delegated_cred = GSS_C_NO_CREDENTIAL;
    gss_cred_usage_t cred_usage = GSS_C_ACCEPT;
    uint32_t vtime;
    uint32_t maj, min;
    char *reply;
    size_t replen;
    char *clientname;
    gss_OID mech_type = GSS_C_NO_OID;
    gss_OID_set desired_mechs = GSS_C_NO_OID_SET;
    gss_OID_set indicated_mechs = GSS_C_NO_OID_SET;
    gss_buffer_desc lname = GSS_C_EMPTY_BUFFER;
    struct mag_conn *mc = NULL;
    time_t expiration;
    int i;

    type = ap_auth_type(req);
    if ((type == NULL) || (strcasecmp(type, "GSSAPI") != 0)) {
        return DECLINED;
    }

    cfg = ap_get_module_config(req->per_dir_config, &auth_gssapi_module);

    if (cfg->allowed_mechs) {
        desired_mechs = cfg->allowed_mechs;
    } else {
        /* Try to fetch the default set if not explicitly configured */
        maj = gss_indicate_mechs(&min, &indicated_mechs);
        if (maj != GSS_S_COMPLETE) {
            ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, req, "%s",
                          mag_error(req, "gss_indicate_mechs() failed",
                                    maj, min));
        }
        desired_mechs = indicated_mechs;
    }

    /* implicit auth for subrequests if main auth already happened */
    if (!ap_is_initial_req(req) && req->main != NULL) {
        type = ap_auth_type(req->main);
        if ((type != NULL) && (strcasecmp(type, "GSSAPI") == 0)) {
            /* warn if the subrequest location and the main request
             * location have different configs */
            if (cfg != ap_get_module_config(req->main->per_dir_config,
                                            &auth_gssapi_module)) {
                ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0,
                              req, "Subrequest authentication bypass on "
                                   "location with different configuration!");
            }
            if (req->main->user) {
                req->user = apr_pstrdup(req->pool, req->main->user);
                return OK;
            } else {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, req,
                              "The main request is tasked to establish the "
                              "security context, can't proceed!");
                return HTTP_UNAUTHORIZED;
            }
        } else {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, req,
                          "Subrequest GSSAPI auth with no auth on the main "
                          "request. This operation may fail if other "
                          "subrequests already established a context or the "
                          "mechanism requires multiple roundtrips.");
        }
    }

    if (cfg->ssl_only) {
        if (!mag_conn_is_https(req->connection)) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, req,
                          "Not a TLS connection, refusing to authenticate!");
            goto done;
        }
    }

    if (cfg->gss_conn_ctx) {
        mc = (struct mag_conn *)ap_get_module_config(
                                                req->connection->conn_config,
                                                &auth_gssapi_module);
        if (!mc) {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, req,
                          "Failed to retrieve connection context!");
            goto done;
        }
    }

    /* if available, session always supersedes connection bound data */
    if (cfg->use_sessions) {
        mag_check_session(req, cfg, &mc);
    }

    auth_header = apr_table_get(req->headers_in, "Authorization");

    if (mc) {
        if (mc->established &&
            (auth_header == NULL) &&
            (mc->auth_type != AUTH_TYPE_BASIC)) {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, req,
                          "Already established context found!");
            mag_set_req_data(req, cfg, mc);
            ret = OK;
            goto done;
        }
        pctx = &mc->ctx;
    } else {
        pctx = &ctx;
    }

    /* We can proceed only if we do have an auth header */
    if (!auth_header) goto done;

    auth_header_type = ap_getword_white(req->pool, &auth_header);
    if (!auth_header_type) goto done;

    for (i = 0; auth_types[i] != NULL; i++) {
        if (strcasecmp(auth_header_type, auth_types[i]) == 0) {
            auth_type = i;
            break;
        }
    }

    switch (auth_type) {
    case AUTH_TYPE_NEGOTIATE:
        if (!parse_auth_header(req->pool, &auth_header, &input)) {
            goto done;
        }
        break;
    case AUTH_TYPE_BASIC:
        if (!cfg->use_basic_auth) {
            goto done;
        }

        ba_pwd.value = ap_pbase64decode(req->pool, auth_header);
        if (!ba_pwd.value) goto done;
        ba_user.value = ap_getword_nulls_nc(req->pool,
                                            (char **)&ba_pwd.value, ':');
        if (!ba_user.value) goto done;
        if (((char *)ba_user.value)[0] == '\0' ||
            ((char *)ba_pwd.value)[0] == '\0') {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, req,
                          "Invalid empty user or password for Basic Auth");
            goto done;
        }
        ba_user.length = strlen(ba_user.value);
        ba_pwd.length = strlen(ba_pwd.value);

        if (mc && mc->established &&
            mag_basic_check(cfg, mc, ba_user, ba_pwd)) {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, req,
                          "Already established BASIC AUTH context found!");
            mag_set_req_data(req, cfg, mc);
            ret = OK;
            goto done;
        }

        break;

    case AUTH_TYPE_RAW_NTLM:
        if (!is_mech_allowed(cfg, &gss_mech_ntlmssp)) {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, req,
                          "NTLM Authentication is not allowed!");
            goto done;
        }

        if (!parse_auth_header(req->pool, &auth_header, &input)) {
            goto done;
        }

        desired_mechs = discard_const(&gss_mech_set_ntlmssp);
        break;

    default:
        goto done;
    }

    if (mc && mc->established) {
        /* if we are re-authenticating make sure the conn context
         * is cleaned up so we do not accidentally reuse an existing
         * established context */
        mag_conn_clear(mc);
    }

    req->ap_auth_type = apr_pstrdup(req->pool, auth_types[auth_type]);

#ifdef HAVE_CRED_STORE
    if (cfg->use_s4u2proxy) {
        cred_usage = GSS_C_BOTH;
    }
#endif

    if (auth_type == AUTH_TYPE_BASIC) {
        if (mag_auth_basic(req, cfg, ba_user, ba_pwd,
                           cred_usage, &client, &mech_type,
                           &delegated_cred, &vtime)) {
            goto complete;
        }
        goto done;
    }

    if (!mag_acquire_creds(req, cfg, desired_mechs,
                           cred_usage, &acquired_cred, NULL)) {
        goto done;
    }

    if (auth_type == AUTH_TYPE_NEGOTIATE &&
        cfg->allowed_mechs != GSS_C_NO_OID_SET) {
        maj = gss_set_neg_mechs(&min, acquired_cred, cfg->allowed_mechs);
        if (GSS_ERROR(maj)) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, req, "%s",
                          mag_error(req, "gss_set_neg_mechs() failed",
                                    maj, min));
            goto done;
        }
    }

    maj = gss_accept_sec_context(&min, pctx, acquired_cred,
                                 &input, GSS_C_NO_CHANNEL_BINDINGS,
                                 &client, &mech_type, &output, NULL, &vtime,
                                 &delegated_cred);
    if (GSS_ERROR(maj)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, req, "%s",
                      mag_error(req, "gss_accept_sec_context() failed",
                                maj, min));
        goto done;
    } else if (maj == GSS_S_CONTINUE_NEEDED) {
        if (!mc) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, req,
                          "Mechanism needs continuation but neither "
                          "GssapiConnectionBound nor "
                          "GssapiUseSessions are available");
            gss_release_buffer(&min, &output);
            output.length = 0;
        }
        /* auth not complete send token and wait next packet */
        goto done;
    }

complete:
    /* Always set the GSS name in an env var */
    maj = gss_display_name(&min, client, &name, NULL);
    if (GSS_ERROR(maj)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, req, "%s",
                      mag_error(req, "gss_display_name() failed",
                                maj, min));
        goto done;
    }
    clientname = apr_pstrndup(req->pool, name.value, name.length);
    apr_table_set(req->subprocess_env, "GSS_NAME", clientname);
    expiration = time(NULL) + vtime;
    apr_table_set(req->subprocess_env, "GSS_SESSION_EXPIRATION",
                  apr_psprintf(req->pool, "%ld", (long)expiration));

#ifdef HAVE_CRED_STORE
    if (cfg->deleg_ccache_dir && delegated_cred != GSS_C_NO_CREDENTIAL) {
        char *ccachefile = NULL;

        mag_store_deleg_creds(req, cfg->deleg_ccache_dir, clientname,
                              delegated_cred, &ccachefile);

        if (ccachefile) {
            mag_set_KRB5CCANME(req, ccachefile);
        }

        if (mc) {
            mc->delegated = true;
        }
    }
#endif

    if (cfg->map_to_local) {
        maj = gss_localname(&min, client, mech_type, &lname);
        if (maj != GSS_S_COMPLETE) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, req, "%s",
                          mag_error(req, "gss_localname() failed", maj, min));
            goto done;
        }
        req->user = apr_pstrndup(req->pool, lname.value, lname.length);
    } else {
        req->user = clientname;
    }

    if (mc) {
        mc->user_name = apr_pstrdup(mc->pool, req->user);
        mc->gss_name = apr_pstrdup(mc->pool, clientname);
        mc->established = true;
        if (vtime == GSS_C_INDEFINITE || vtime < MIN_SESS_EXP_TIME) {
            vtime = MIN_SESS_EXP_TIME;
        }
        mc->expiration = expiration;
        mc->auth_type = auth_type;
        if (auth_type == AUTH_TYPE_BASIC) {
            mag_basic_cache(cfg, mc, ba_user, ba_pwd);
        }
        if (cfg->use_sessions) {
            mag_attempt_session(req, cfg, mc);
        }
    }

    if (cfg->send_persist)
        apr_table_set(req->headers_out, "Persistent-Auth",
            cfg->gss_conn_ctx ? "true" : "false");

    ret = OK;

done:
    if ((auth_type != AUTH_TYPE_BASIC) && (output.length != 0)) {
        int prefixlen = strlen(auth_types[auth_type]) + 1;
        replen = apr_base64_encode_len(output.length) + 1;
        reply = apr_pcalloc(req->pool, prefixlen + replen);
        if (reply) {
            memcpy(reply, auth_types[auth_type], prefixlen - 1);
            reply[prefixlen - 1] = ' ';
            apr_base64_encode(&reply[prefixlen], output.value, output.length);
            apr_table_add(req->err_headers_out,
                          "WWW-Authenticate", reply);
        }
    } else if (ret == HTTP_UNAUTHORIZED) {
        apr_table_add(req->err_headers_out, "WWW-Authenticate", "Negotiate");
        if (is_mech_allowed(cfg, &gss_mech_ntlmssp)) {
            apr_table_add(req->err_headers_out, "WWW-Authenticate", "NTLM");
        }
        if (cfg->use_basic_auth) {
            apr_table_add(req->err_headers_out,
                          "WWW-Authenticate",
                          apr_psprintf(req->pool, "Basic realm=\"%s\"",
                                       ap_auth_name(req)));
        }
    }
    gss_release_oid_set(&min, &indicated_mechs);
    if (ctx != GSS_C_NO_CONTEXT)
        gss_delete_sec_context(&min, &ctx, GSS_C_NO_BUFFER);
    gss_release_cred(&min, &acquired_cred);
    gss_release_cred(&min, &delegated_cred);
    gss_release_buffer(&min, &output);
    gss_release_name(&min, &client);
    gss_release_buffer(&min, &name);
    gss_release_buffer(&min, &lname);
    return ret;
}


static void *mag_create_dir_config(apr_pool_t *p, char *dir)
{
    struct mag_config *cfg;

    cfg = (struct mag_config *)apr_pcalloc(p, sizeof(struct mag_config));
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

static const char *mag_send_persist(cmd_parms *parms, void *mconfig, int on)
{
    struct mag_config *cfg = (struct mag_config *)mconfig;
    cfg->send_persist = on ? true : false;
    return NULL;
}

static const char *mag_use_sess(cmd_parms *parms, void *mconfig, int on)
{
    struct mag_config *cfg = (struct mag_config *)mconfig;
    cfg->use_sessions = on ? true : false;
    return NULL;
}

#ifdef HAVE_CRED_STORE
static const char *mag_use_s4u2p(cmd_parms *parms, void *mconfig, int on)
{
    struct mag_config *cfg = (struct mag_config *)mconfig;
    cfg->use_s4u2proxy = on ? true : false;

    if (cfg->deleg_ccache_dir == NULL) {
        cfg->deleg_ccache_dir = apr_pstrdup(parms->pool, "/tmp");
    }
    return NULL;
}
#endif

static const char *mag_sess_key(cmd_parms *parms, void *mconfig, const char *w)
{
    struct mag_config *cfg = (struct mag_config *)mconfig;
    struct databuf keys;
    unsigned char *val;
    apr_status_t rc;
    const char *k;
    int l;

    if (strncmp(w, "key:", 4) != 0) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, parms->server,
                     "Invalid key format, expected prefix 'key:'");
        return NULL;
    }
    k = w + 4;

    l = apr_base64_decode_len(k);
    val = apr_palloc(parms->temp_pool, l);

    keys.length = (int)apr_base64_decode_binary(val, k);
    keys.value = (unsigned char *)val;

    if (keys.length != 32) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, parms->server,
                     "Invalid key length, expected 32 got %d", keys.length);
        return NULL;
    }

    rc = SEAL_KEY_CREATE(cfg->pool, &cfg->mag_skey, &keys);
    if (rc != OK) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, parms->server,
                     "Failed to import sealing key!");
    }
    return NULL;
}

#ifdef HAVE_CRED_STORE

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
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, parms->server,
                     "%s [%s]", "Invalid syntax for GssapiCredStore option", w);
        return NULL;
    }

    key = apr_pstrndup(parms->pool, w, (p-w));
    value = apr_pstrdup(parms->pool, p + 1);

    if (!cfg->cred_store) {
        cfg->cred_store = apr_pcalloc(parms->pool,
                                      sizeof(gss_key_value_set_desc));
        size = sizeof(gss_key_value_element_desc) * MAX_CRED_OPTIONS;
        cfg->cred_store->elements = apr_palloc(parms->pool, size);
    }

    elements = cfg->cred_store->elements;
    count = cfg->cred_store->count;

    if (count >= MAX_CRED_OPTIONS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, parms->server,
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

    return NULL;
}
#endif

#ifdef HAVE_GSS_ACQUIRE_CRED_WITH_PASSWORD
static const char *mag_use_basic_auth(cmd_parms *parms, void *mconfig, int on)
{
    struct mag_config *cfg = (struct mag_config *)mconfig;

    cfg->use_basic_auth = on ? true : false;
    return NULL;
}
#endif

static apr_status_t mag_oid_set_destroy(void *ptr)
{
    uint32_t min;
    gss_OID_set set = (gss_OID_set)ptr;
    (void)gss_release_oid_set(&min, &set);
    return APR_SUCCESS;
}

static void mag_list_of_mechs(cmd_parms *parms, gss_OID_set *oidset,
                              bool add_spnego, const char *w)
{
    gss_buffer_desc buf = { 0 };
    uint32_t maj, min;
    gss_OID_set set;
    gss_OID oid;
    bool release_oid = false;

    if (NULL == *oidset) {
        maj = gss_create_empty_oid_set(&min, &set);
        if (maj != GSS_S_COMPLETE) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, parms->server,
                         "gss_create_empty_oid_set() failed.");
            *oidset = GSS_C_NO_OID_SET;
            return;
        }
        if (add_spnego) {
            oid = discard_const(&gss_mech_spnego);
            maj = gss_add_oid_set_member(&min, oid, &set);
            if (maj != GSS_S_COMPLETE) {
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, parms->server,
                             "gss_add_oid_set_member() failed.");
                (void)gss_release_oid_set(&min, &set);
                *oidset = GSS_C_NO_OID_SET;
                return;
            }
        }
        /* register in the pool so it can be released once the server
         * winds down */
        apr_pool_cleanup_register(parms->pool, (void *)set,
                                  mag_oid_set_destroy,
                                  apr_pool_cleanup_null);
        *oidset = set;
    } else {
        set = *oidset;
    }

    if (strcmp(w, "krb5") == 0) {
        oid = discard_const(gss_mech_krb5);
    } else if (strcmp(w, "iakerb") == 0) {
        oid = discard_const(gss_mech_iakerb);
    } else if (strcmp(w, "ntlmssp") == 0) {
        oid = discard_const(&gss_mech_ntlmssp);
    } else {
        buf.value = discard_const(w);
        buf.length = strlen(w);
        maj = gss_str_to_oid(&min, &buf, &oid);
        if (maj != GSS_S_COMPLETE) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, parms->server,
                         "Unrecognized GSSAPI Mechanism: [%s]", w);
            return;
        }
        release_oid = true;
    }
    maj = gss_add_oid_set_member(&min, oid, &set);
    if (maj != GSS_S_COMPLETE) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, parms->server,
                         "gss_add_oid_set_member() failed for [%s].", w);
    }
    if (release_oid) {
        (void)gss_release_oid(&min, &oid);
    }
}

static const char *mag_allow_mech(cmd_parms *parms, void *mconfig,
                                  const char *w)
{
    struct mag_config *cfg = (struct mag_config *)mconfig;

    mag_list_of_mechs(parms, &cfg->allowed_mechs, true, w);

    return NULL;
}

#ifdef HAVE_GSS_ACQUIRE_CRED_WITH_PASSWORD
static const char *mag_basic_auth_mechs(cmd_parms *parms, void *mconfig,
                                        const char *w)
{
    struct mag_config *cfg = (struct mag_config *)mconfig;

    mag_list_of_mechs(parms, &cfg->basic_mechs, false, w);

    return NULL;
}
#endif

static const command_rec mag_commands[] = {
    AP_INIT_FLAG("GssapiSSLonly", mag_ssl_only, NULL, OR_AUTHCFG,
                  "Work only if connection is SSL Secured"),
    AP_INIT_FLAG("GssapiLocalName", mag_map_to_local, NULL, OR_AUTHCFG,
                  "Translate principals to local names"),
    AP_INIT_FLAG("GssapiConnectionBound", mag_conn_ctx, NULL, OR_AUTHCFG,
                  "Authentication is bound to the TCP connection"),
    AP_INIT_FLAG("GssapiSignalPersistentAuth", mag_send_persist, NULL, OR_AUTHCFG,
                  "Send Persitent-Auth header according to connection bound"),
    AP_INIT_FLAG("GssapiUseSessions", mag_use_sess, NULL, OR_AUTHCFG,
                  "Authentication uses mod_sessions to hold status"),
    AP_INIT_RAW_ARGS("GssapiSessionKey", mag_sess_key, NULL, OR_AUTHCFG,
                     "Key Used to seal session data."),
#ifdef HAVE_CRED_STORE
    AP_INIT_FLAG("GssapiUseS4U2Proxy", mag_use_s4u2p, NULL, OR_AUTHCFG,
                  "Initializes credentials for s4u2proxy usage"),
    AP_INIT_ITERATE("GssapiCredStore", mag_cred_store, NULL, OR_AUTHCFG,
                    "Credential Store"),
    AP_INIT_RAW_ARGS("GssapiDelegCcacheDir", mag_deleg_ccache_dir, NULL,
                     OR_AUTHCFG, "Directory to store delegated credentials"),
#endif
#ifdef HAVE_GSS_ACQUIRE_CRED_WITH_PASSWORD
    AP_INIT_FLAG("GssapiBasicAuth", mag_use_basic_auth, NULL, OR_AUTHCFG,
                     "Allows use of Basic Auth for authentication"),
    AP_INIT_ITERATE("GssapiBasicAuthMech", mag_basic_auth_mechs, NULL,
                    OR_AUTHCFG, "Mechanisms to use for basic auth"),
#endif
    AP_INIT_ITERATE("GssapiAllowedMech", mag_allow_mech, NULL, OR_AUTHCFG,
                    "Allowed Mechanisms"),
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

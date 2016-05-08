/* Copyright (C) 2014, 2016 mod_auth_gssapi contributors - See COPYING for (C) terms */

#include "mod_auth_gssapi.h"

const gss_OID_desc gss_mech_spnego = {
    6, "\x2b\x06\x01\x05\x05\x02"
};

#ifdef HAVE_GSSAPI_GSSAPI_NTLMSSP_H
const gss_OID_desc gss_mech_ntlmssp_desc = {
    GSS_NTLMSSP_OID_LENGTH, GSS_NTLMSSP_OID_STRING
};
gss_const_OID gss_mech_ntlmssp = &gss_mech_ntlmssp_desc;

const gss_OID_set_desc gss_mech_set_ntlmssp_desc = {
    1, discard_const(&gss_mech_ntlmssp_desc)
};
gss_const_OID_set gss_mech_set_ntlmssp = &gss_mech_set_ntlmssp_desc;

#else
gss_OID gss_mech_ntlmssp = GSS_C_NO_OID;
gss_OID_set gss_mech_set_ntlmssp = GSS_C_NO_OID_SET;
#endif

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

char *mag_error(request_rec *req, const char *msg, uint32_t maj, uint32_t min)
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
    mc->is_preserved = true;
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

static char *get_ccache_name(request_rec *req, char *dir, const char *gss_name,
                             bool use_unique, struct mag_conn *mc)
{
    char *ccname, *escaped;
    int ccachefd;

    /* We need to escape away '/', we can't have path separators in
     * a ccache file name */
    /* first double escape the esacping char (~) if any */
    escaped = escape(req->pool, gss_name, '~', "~~");
    /* then escape away the separator (/) if any */
    escaped = escape(req->pool, escaped, '/', "~");

    if (use_unique == false) {
        return apr_psprintf(req->pool, "%s/%s", dir, escaped);
    }

    ccname = apr_psprintf(mc->pool, "%s/%s-XXXXXX", dir, escaped);

    ccachefd = mkstemp(ccname);
    if (ccachefd == -1) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, req,
                      "creating unique ccache file %s failed", ccname);
        return NULL;
    }
    close(ccachefd);
    return ccname;
}

static void mag_store_deleg_creds(request_rec *req, const char *ccname,
                                  gss_cred_id_t delegated_cred)
{
    gss_key_value_element_desc element;
    gss_key_value_set_desc store;
    uint32_t maj, min;
    element.key = "ccache";
    store.elements = &element;
    store.count = 1;

    element.value = apr_psprintf(req->pool, "FILE:%s", ccname);

    maj = gss_store_cred_into(&min, delegated_cred, GSS_C_INITIATE,
                              GSS_C_NULL_OID, 1, 1, &store, NULL, NULL);
    if (GSS_ERROR(maj)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, req, "%s",
                      mag_error(req, "failed to store delegated creds",
                                maj, min));
    }
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

static bool is_mech_allowed(gss_OID_set allowed_mechs, gss_const_OID mech,
                            bool multi_step_supported)
{
    if (mech == GSS_C_NO_OID) return false;

    if (!multi_step_supported && gss_oid_equal(gss_mech_ntlmssp, mech))
        return false;

    if (allowed_mechs == GSS_C_NO_OID_SET) return true;

    for (int i = 0; i < allowed_mechs->count; i++) {
        if (gss_oid_equal(&allowed_mechs->elements[i], mech)) {
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

const char *mag_str_auth_type(int auth_type)
{
    return auth_types[auth_type];
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

    if (src == GSS_C_NO_OID_SET) return GSS_C_NO_OID_SET;

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
    gss_buffer_desc input = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc output = GSS_C_EMPTY_BUFFER;
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
        struct mag_server_config *scfg;
        /* Try to fetch the default set if not explicitly configured,
         * We need to do this because gss_acquire_cred_with_password()
         * is currently limited to acquire creds for a single "default"
         * mechanism if no desired mechanisms are passed in. This causes
         * authentication to fail for secondary mechanisms as no user
         * credentials are generated for those. */
        scfg = ap_get_module_config(req->server->module_config,
                                    &auth_gssapi_module);
        /* In the worst case scenario default_mechs equals to GSS_C_NO_OID_SET.
         * This generally causes only the krb5 mechanism to be tried due
         * to implementation constraints, but may change in future. */
        allowed_mechs = scfg->default_mechs;
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
    if (filtered_mechs == allowed_mechs) {
        /* in case filtered_mechs was not allocated here don't free it */
        filtered_mechs = GSS_C_NO_OID_SET;
    } else if (filtered_mechs == GSS_C_NO_OID_SET) {
        ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, req, "Fatal "
                      "failure while filtering mechs, aborting");
        goto done;
    } else {
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
                           GSS_C_ACCEPT, &server_cred, NULL)) {
        goto done;
    }

#ifdef HAVE_CRED_STORE
    if (cfg->deleg_ccache_dir) {
        /* delegate ourselves credentials so we store them as requested */
        init_flags |= GSS_C_DELEG_FLAG;
    }
#endif

    for (int i = 0; i < actual_mechs->count; i++) {

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
            maj = gss_accept_sec_context(&min, &server_ctx, server_cred,
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
    gss_delete_sec_context(&min, &server_ctx, GSS_C_NO_BUFFER);
    gss_release_cred(&min, &server_cred);
    gss_release_name(&min, &user);
    gss_release_cred(&min, &user_cred);
    gss_delete_sec_context(&min, &user_ctx, GSS_C_NO_BUFFER);
    gss_release_oid_set(&min, &actual_mechs);
    gss_release_oid_set(&min, &filtered_mechs);
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

struct mag_req_cfg *mag_init_cfg(request_rec *req)
{
    struct mag_server_config *scfg;
    struct mag_req_cfg *req_cfg = apr_pcalloc(req->pool,
                                              sizeof(struct mag_req_cfg));
    req_cfg->req = req;
    req_cfg->cfg = ap_get_module_config(req->per_dir_config,
                                        &auth_gssapi_module);

    scfg = ap_get_module_config(req->server->module_config,
                                &auth_gssapi_module);

    if (req_cfg->cfg->allowed_mechs) {
        req_cfg->desired_mechs = req_cfg->cfg->allowed_mechs;
    } else {
        /* Use the default set if not explicitly configured */
        req_cfg->desired_mechs = scfg->default_mechs;
    }

    if (req_cfg->cfg->mag_skey) {
        req_cfg->mag_skey = req_cfg->cfg->mag_skey;
    } else {
        /* Use server random key if not explicitly configured */
        req_cfg->mag_skey = scfg->mag_skey;
    }

    if (req->proxyreq == PROXYREQ_PROXY) {
        req_cfg->req_proto = "Proxy-Authorization";
        req_cfg->rep_proto = "Proxy-Authenticate";
    } else {
        req_cfg->req_proto = "Authorization";
        req_cfg->rep_proto = "WWW-Authenticate";
        req_cfg->use_sessions = req_cfg->cfg->use_sessions;
        req_cfg->send_persist = req_cfg->cfg->send_persist;
    }

    return req_cfg;
}

#ifdef HAVE_CRED_STORE
static bool use_s4u2proxy(struct mag_req_cfg *req_cfg) {
    if (req_cfg->cfg->use_s4u2proxy) {
        if (req_cfg->cfg->deleg_ccache_dir != NULL) {
            return true;
        } else {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, req_cfg->req,
                          "S4U2 Proxy requested but GssapiDelegCcacheDir "
                          "is not set. Constrained delegation disabled!");
        }
    }
    return false;
}
#endif

static int mag_auth(request_rec *req)
{
    const char *type;
    int auth_type = -1;
    struct mag_req_cfg *req_cfg;
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
    gss_OID mech_type = GSS_C_NO_OID;
    gss_OID_set desired_mechs = GSS_C_NO_OID_SET;
    gss_buffer_desc lname = GSS_C_EMPTY_BUFFER;
    struct mag_conn *mc = NULL;
    int i;
    bool send_auth_header = true;

    type = ap_auth_type(req);
    if ((type == NULL) || (strcasecmp(type, "GSSAPI") != 0)) {
        return DECLINED;
    }

    req_cfg = mag_init_cfg(req);

    cfg = req_cfg->cfg;

    desired_mechs = req_cfg->desired_mechs;

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
    if (req_cfg->use_sessions) {
        mag_check_session(req_cfg, &mc);
    }

    auth_header = apr_table_get(req->headers_in, req_cfg->req_proto);

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
        /* no preserved mc, create one just for this request */
        mc = mag_new_conn_ctx(req->pool);
        pctx = &ctx;
    }

    /* We can proceed only if we do have an auth header */
    if (!auth_header) goto done;

    auth_header_type = ap_getword_white(req->pool, &auth_header);
    if (!auth_header_type) goto done;

    /* We got auth header, sending auth header would mean re-auth */
    send_auth_header = !cfg->negotiate_once;

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

        if (mc->is_preserved && mc->established &&
            mag_basic_check(req_cfg, mc, ba_user, ba_pwd)) {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, req,
                          "Already established BASIC AUTH context found!");
            mag_set_req_data(req, cfg, mc);
            ret = OK;
            goto done;
        }

        break;

    case AUTH_TYPE_RAW_NTLM:
        if (!is_mech_allowed(desired_mechs, gss_mech_ntlmssp,
                             cfg->gss_conn_ctx)) {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, req,
                          "NTLM Authentication is not allowed!");
            goto done;
        }

        if (!parse_auth_header(req->pool, &auth_header, &input)) {
            goto done;
        }

        desired_mechs = discard_const(gss_mech_set_ntlmssp);
        break;

    default:
        goto done;
    }

    if (mc->established) {
        /* if we are re-authenticating make sure the conn context
         * is cleaned up so we do not accidentally reuse an existing
         * established context */
        mag_conn_clear(mc);
    }

    mc->auth_type = auth_type;

#ifdef HAVE_CRED_STORE
    if (use_s4u2proxy(req_cfg)) {
        cred_usage = GSS_C_BOTH;
    }
#endif

    if (auth_type == AUTH_TYPE_BASIC) {
        if (mag_auth_basic(req, cfg, ba_user, ba_pwd,
                           &client, &mech_type,
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
        if (!mc->is_preserved) {
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
    maj = gss_display_name(&min, client, &name, NULL);
    if (GSS_ERROR(maj)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, req, "%s",
                      mag_error(req, "gss_display_name() failed",
                                maj, min));
        goto done;
    }

    mc->gss_name = apr_pstrndup(req->pool, name.value, name.length);
    if (vtime == GSS_C_INDEFINITE || vtime < MIN_SESS_EXP_TIME) {
        vtime = MIN_SESS_EXP_TIME;
    }
    mc->expiration = time(NULL) + vtime;

    mag_get_name_attributes(req, cfg, client, mc);

#ifdef HAVE_CRED_STORE
    if (cfg->deleg_ccache_dir && delegated_cred != GSS_C_NO_CREDENTIAL) {
        char *ccache_path;

        mc->ccname = 0;
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, req,
                      "requester: %s", mc->gss_name);

        ccache_path = get_ccache_name(req, cfg->deleg_ccache_dir, mc->gss_name,
                                      cfg->deleg_ccache_unique, mc);
        if (ccache_path == NULL) {
            goto done;
        }

        mag_store_deleg_creds(req, ccache_path, delegated_cred);
        mc->delegated = true;

        if (!req_cfg->use_sessions && cfg->deleg_ccache_unique) {
            /* queue removing ccache to avoid littering filesystem */
            apr_pool_cleanup_register(mc->pool, ccache_path,
                                      (int (*)(void *)) unlink,
                                      apr_pool_cleanup_null);
        }

        /* extract filename from full path */
        mc->ccname = strrchr(ccache_path, '/') + 1;
    }
#endif

    if (cfg->map_to_local) {
        maj = gss_localname(&min, client, mech_type, &lname);
        if (maj != GSS_S_COMPLETE) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, req, "%s",
                          mag_error(req, "gss_localname() failed", maj, min));
            goto done;
        }
        mc->user_name = apr_pstrndup(req->pool, lname.value, lname.length);
    } else {
        mc->user_name = apr_pstrdup(mc->pool, mc->gss_name);
    }

    mc->established = true;
    if (auth_type == AUTH_TYPE_BASIC) {
        mag_basic_cache(req_cfg, mc, ba_user, ba_pwd);
    }
    if (req_cfg->use_sessions) {
        mag_attempt_session(req_cfg, mc);
    }

    /* Now set request data and env vars */
    mag_set_req_data(req, cfg, mc);

    if (req_cfg->send_persist)
        apr_table_set(req->headers_out, "Persistent-Auth",
            cfg->gss_conn_ctx ? "true" : "false");

    ret = OK;

done:

    if ((auth_type != AUTH_TYPE_BASIC) && (output.length != 0)) {
        int prefixlen = strlen(mag_str_auth_type(auth_type)) + 1;
        replen = apr_base64_encode_len(output.length) + 1;
        reply = apr_pcalloc(req->pool, prefixlen + replen);
        if (reply) {
            memcpy(reply, mag_str_auth_type(auth_type), prefixlen - 1);
            reply[prefixlen - 1] = ' ';
            apr_base64_encode(&reply[prefixlen], output.value, output.length);
            apr_table_add(req->err_headers_out, req_cfg->rep_proto, reply);
        }
    } else if (ret == HTTP_UNAUTHORIZED) {
        if (send_auth_header) {
            apr_table_add(req->err_headers_out,
                          req_cfg->rep_proto, "Negotiate");
            if (is_mech_allowed(desired_mechs, gss_mech_ntlmssp,
                                cfg->gss_conn_ctx)) {
                apr_table_add(req->err_headers_out, req_cfg->rep_proto,
                              "NTLM");
            }
        }
        if (cfg->use_basic_auth) {
            apr_table_add(req->err_headers_out, req_cfg->rep_proto,
                          apr_psprintf(req->pool, "Basic realm=\"%s\"",
                                       ap_auth_name(req)));
        }
    }

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

    return NULL;
}

static const char *mag_deleg_ccache_unique(cmd_parms *parms, void *mconfig,
                                           int on)
{
    struct mag_config *cfg = (struct mag_config *)mconfig;
    cfg->deleg_ccache_unique = on ? true : false;
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

static bool mag_list_of_mechs(cmd_parms *parms, gss_OID_set *oidset,
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
            return false;
        }
        if (add_spnego) {
            oid = discard_const(&gss_mech_spnego);
            maj = gss_add_oid_set_member(&min, oid, &set);
            if (maj != GSS_S_COMPLETE) {
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, parms->server,
                             "gss_add_oid_set_member() failed.");
                (void)gss_release_oid_set(&min, &set);
                *oidset = GSS_C_NO_OID_SET;
                return false;
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
        oid = discard_const(gss_mech_ntlmssp);
    } else {
        buf.value = discard_const(w);
        buf.length = strlen(w);
        maj = gss_str_to_oid(&min, &buf, &oid);
        if (maj != GSS_S_COMPLETE) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, parms->server,
                         "Unrecognized GSSAPI Mechanism: [%s]", w);
            return false;
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

    return true;
}

static const char *mag_allow_mech(cmd_parms *parms, void *mconfig,
                                  const char *w)
{
    struct mag_config *cfg = (struct mag_config *)mconfig;

    if (!mag_list_of_mechs(parms, &cfg->allowed_mechs, true, w))
        return "Failed to apply GssapiAllowedMech directive";

    return NULL;
}

static const char *mag_negotiate_once(cmd_parms *parms, void *mconfig, int on)
{
    struct mag_config *cfg = (struct mag_config *)mconfig;

    cfg->negotiate_once = on ? true : false;
    return NULL;
}

#define GSS_NAME_ATTR_USERDATA "GSS Name Attributes Userdata"

static apr_status_t mag_name_attrs_cleanup(void *data)
{
    struct mag_config *cfg = (struct mag_config *)data;
    free(cfg->name_attributes);
    cfg->name_attributes = NULL;
    return 0;
}

static const char *mag_name_attrs(cmd_parms *parms, void *mconfig,
                                  const char *w)
{
    struct mag_config *cfg = (struct mag_config *)mconfig;
    void *tmp_na;
    size_t size = 0;
    char *p;
    int c;

    if (!cfg->name_attributes) {
        size = sizeof(struct mag_name_attributes)
                + (sizeof(struct mag_na_map) * 16);
    } else if (cfg->name_attributes->map_count % 16 == 0) {
        size = sizeof(struct mag_name_attributes)
                + (sizeof(struct mag_na_map)
                    * (cfg->name_attributes->map_count + 16));
    }
    if (size) {
        tmp_na = realloc(cfg->name_attributes, size);
        if (!tmp_na) apr_pool_abort_get(cfg->pool)(ENOMEM);

        if (cfg->name_attributes) {
            size_t empty = (sizeof(struct mag_na_map) * 16);
            memset(tmp_na + size - empty, 0, empty);
        } else {
            memset(tmp_na, 0, size);
        }
        cfg->name_attributes = (struct mag_name_attributes *)tmp_na;
        apr_pool_userdata_setn(cfg, GSS_NAME_ATTR_USERDATA,
                               mag_name_attrs_cleanup, cfg->pool);
    }

    p = strchr(w, ' ');
    if (p == NULL) {
        if (strcmp(w, "json") == 0) {
            cfg->name_attributes->output_json = true;
        } else {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, parms->server,
                         "Invalid Name Attributes value [%s].", w);
        }
        return NULL;
    }

    c = cfg->name_attributes->map_count;
    cfg->name_attributes->map[c].env_name = apr_pstrndup(cfg->pool, w, p-w);
    p++;
    cfg->name_attributes->map[c].attr_name = apr_pstrdup(cfg->pool, p);
    cfg->name_attributes->map_count += 1;

    return NULL;
}

#ifdef HAVE_GSS_ACQUIRE_CRED_WITH_PASSWORD
static const char *mag_basic_auth_mechs(cmd_parms *parms, void *mconfig,
                                        const char *w)
{
    struct mag_config *cfg = (struct mag_config *)mconfig;

    if (!mag_list_of_mechs(parms, &cfg->basic_mechs, false, w))
        return "Failed to apply GssapiBasicAuthMech directive";

    return NULL;
}
#endif

static void *mag_create_server_config(apr_pool_t *p, server_rec *s)
{
    struct mag_server_config *scfg;
    uint32_t maj, min;
    apr_status_t rc;

    scfg = apr_pcalloc(p, sizeof(struct mag_server_config));

    maj = gss_indicate_mechs(&min, &scfg->default_mechs);
    if (maj != GSS_S_COMPLETE) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s,
                     "gss_indicate_mechs() failed");
    } else {
        /* Register the set in pool */
        apr_pool_cleanup_register(p, (void *)scfg->default_mechs,
                                  mag_oid_set_destroy, apr_pool_cleanup_null);
    }

    rc = SEAL_KEY_CREATE(p, &scfg->mag_skey, NULL);
    if (rc != OK) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                     "Failed to generate random sealing key!");
    }

    return scfg;
}

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
    AP_INIT_FLAG("GssapiDelegCcacheUnique", mag_deleg_ccache_unique, NULL,
                 OR_AUTHCFG, "Use unique ccaches for delgation"),
#endif
#ifdef HAVE_GSS_ACQUIRE_CRED_WITH_PASSWORD
    AP_INIT_FLAG("GssapiBasicAuth", mag_use_basic_auth, NULL, OR_AUTHCFG,
                     "Allows use of Basic Auth for authentication"),
    AP_INIT_ITERATE("GssapiBasicAuthMech", mag_basic_auth_mechs, NULL,
                    OR_AUTHCFG, "Mechanisms to use for basic auth"),
#endif
    AP_INIT_ITERATE("GssapiAllowedMech", mag_allow_mech, NULL, OR_AUTHCFG,
                    "Allowed Mechanisms"),
    AP_INIT_FLAG("GssapiNegotiateOnce", mag_negotiate_once, NULL, OR_AUTHCFG,
                    "Don't resend negotiate header on negotiate failure"),
    AP_INIT_RAW_ARGS("GssapiNameAttributes", mag_name_attrs, NULL, OR_AUTHCFG,
                     "Name Attributes to be exported as environ variables"),
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
    mag_create_server_config,
    NULL,
    mag_commands,
    mag_register_hooks
};

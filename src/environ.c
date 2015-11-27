/* Copyright (C) 2015 mod_auth_gssapi authors - See COPYING for (C) terms */

#include "mod_auth_gssapi.h"
#include "environ.h"

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

void mag_set_req_data(request_rec *req,
                      struct mag_config *cfg,
                      struct mag_conn *mc)
{
    apr_table_set(req->subprocess_env, "GSS_NAME", mc->gss_name);
    apr_table_set(req->subprocess_env, "GSS_SESSION_EXPIRATION",
                  apr_psprintf(req->pool,
                               "%ld", (long)mc->expiration));
    req->ap_auth_type = apr_pstrdup(req->pool,
                                    mag_str_auth_type(mc->auth_type));
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

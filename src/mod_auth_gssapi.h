/* Copyright (C) 2014 mod_auth_gssapi authors - See COPYING for (C) terms */

#include <stdbool.h>
#include <stdint.h>
#include <time.h>
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_ext.h>
#include <gssapi/gssapi_krb5.h>

#define APR_WANT_STRFUNC
#include "apr_want.h"
#include <apr_strings.h>
#include <apr_base64.h>

#include <httpd.h>
#include <http_core.h>
#include <http_connection.h>
#include <http_log.h>
#include <http_request.h>
#include <mod_session.h>
#include <mod_ssl.h>

/* apache's httpd.h drags in empty PACKAGE_* variables.
 * undefine them to avoid annoying compile warnings as they
 * are re-defined in config.h */
#undef PACKAGE_BUGREPORT
#undef PACKAGE_NAME
#undef PACKAGE_STRING
#undef PACKAGE_TARNAME
#undef PACKAGE_VERSION
#include "config.h"

#include "crypto.h"
#include "sessions.h"

#define MIN_SESS_EXP_TIME 300 /* 5 minutes validity minimum */

struct mag_config {
    apr_pool_t *pool;
    bool ssl_only;
    bool map_to_local;
    bool gss_conn_ctx;
    bool send_persist;
    bool use_sessions;
    bool use_s4u2proxy;
    char *deleg_ccache_dir;
    gss_key_value_set_desc *cred_store;
    struct seal_key *mag_skey;
    bool use_basic_auth;
};

struct mag_conn {
    apr_pool_t *parent;
    gss_ctx_id_t ctx;
    bool established;
    const char *user_name;
    const char *gss_name;
    time_t expiration;
    const char *auth_type;
};

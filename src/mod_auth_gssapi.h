/* Copyright (C) 2014, 2016 mod_auth_gssapi contributors - See COPYING for (C) terms */

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

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

#include <gssapi/gssapi.h>
#include <gssapi/gssapi_ext.h>
#include <gssapi/gssapi_krb5.h>
#ifdef HAVE_GSSAPI_GSSAPI_NTLMSSP_H
#  include <gssapi/gssapi_ntlmssp.h>
#endif

#include "crypto.h"
#include "sessions.h"
#include "environ.h"

#define MIN_SESS_EXP_TIME 300 /* 5 minutes validity minimum */

#ifdef HAVE_GSS_ACQUIRE_CRED_FROM
#  ifdef HAVE_GSS_STORE_CRED_INTO
#define HAVE_CRED_STORE 1
#  endif
#endif

struct mag_na_map {
    char *env_name;
    char *attr_name;
};

struct mag_name_attributes {
    bool output_json;
    int map_count;
    struct mag_na_map map[];
};

struct mag_config {
    apr_pool_t *pool;
    bool ssl_only;
    bool map_to_local;
    bool gss_conn_ctx;
    bool send_persist;
    bool use_sessions;
#ifdef HAVE_CRED_STORE
    bool use_s4u2proxy;
    char *deleg_ccache_dir;
    gss_key_value_set_desc *cred_store;
    bool deleg_ccache_unique;;
#endif
    struct seal_key *mag_skey;

    bool use_basic_auth;
    gss_OID_set_desc *allowed_mechs;
    gss_OID_set_desc *basic_mechs;
    bool negotiate_once;
    struct mag_name_attributes *name_attributes;
};

struct mag_server_config {
    gss_OID_set default_mechs;
    struct seal_key *mag_skey;
};

struct mag_req_cfg {
    request_rec *req;
    struct mag_config *cfg;
    gss_OID_set desired_mechs;
    bool use_sessions;
    bool send_persist;
    const char *req_proto;
    const char *rep_proto;
    struct seal_key *mag_skey;
};

struct mag_attr {
    const char *name;
    const char *value;
};

struct mag_conn {
    apr_pool_t *pool;
    gss_ctx_id_t ctx;
    bool established;
    const char *user_name;
    const char *gss_name;
    time_t expiration;
    int auth_type;
    bool delegated;
    struct databuf basic_hash;
    bool is_preserved;
    int na_count;
    struct mag_attr *name_attributes;
    const char *ccname;
};

#define discard_const(ptr) ((void *)((uintptr_t)(ptr)))

struct mag_conn *mag_new_conn_ctx(apr_pool_t *pool);
const char *mag_str_auth_type(int auth_type);
char *mag_error(request_rec *req, const char *msg, uint32_t maj, uint32_t min);

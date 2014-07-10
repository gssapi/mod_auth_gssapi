/* Copyright (C) 2014 mod_auth_gssapi authors - See COPYING for (C) terms */

#include <stdbool.h>
#include <stdint.h>
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_ext.h>

#include <httpd.h>
#include <http_core.h>
#include <http_connection.h>
#include <http_log.h>
#include <http_request.h>
#include <apr_strings.h>
#include <apr_base64.h>

/* apache's httpd.h drags in empty PACKAGE_* variables.
 * undefine them to avoid annoying compile warnings as they
 * are re-defined in config.h */
#undef PACKAGE_BUGREPORT
#undef PACKAGE_NAME
#undef PACKAGE_STRING
#undef PACKAGE_TARNAME
#undef PACKAGE_VERSION
#include "config.h"

struct mag_config {
    bool ssl_only;
    bool map_to_local;
    bool gss_conn_ctx;
    gss_key_value_set_desc cred_store;
};


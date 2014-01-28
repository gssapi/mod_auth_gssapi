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

#include <stdbool.h>
#include <stdint.h>
#include <gssapi/gssapi.h>

#include <httpd.h>
#include <http_core.h>
#include <http_log.h>
#include <http_request.h>
#include <apr_strings.h>
#include <apr_base64.h>

module AP_MODULE_DECLARE_DATA mag_module;

struct mag_config {
    bool ssl_only;
    bool save_creds;
};

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

static int mag_auth(request_rec *req)
{
    const char *type;
    struct mag_config *cfg;
    const char *auth_header;
    char *auth_header_type;
    char *auth_header_value;
    int ret = HTTP_UNAUTHORIZED;
    gss_ctx_id_t ctx = GSS_C_NO_CONTEXT;
    gss_buffer_desc input = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc output = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc name = GSS_C_EMPTY_BUFFER;
    gss_name_t client = GSS_C_NO_NAME;
    gss_cred_id_t delegated_cred = GSS_C_NO_CREDENTIAL;
    uint32_t flags;
    uint32_t maj, min;
    char *reply;
    size_t replen;

    type = ap_auth_type(req);
    if ((type == NULL) || (strcasecmp(type, "GSSAPI") != 0)) {
        return DECLINED;
    }

    cfg = ap_get_module_config(req->per_dir_config, &mag_module);

    /* FIXME: Checks for ssl only configuration */

    auth_header = apr_table_get(req->headers_in, "Authorization");
    if (!auth_header) goto done;

    auth_header_type = ap_getword_white(req->pool, &auth_header);
    if (!auth_header_type) goto done;

    if (strcasecmp(auth_header_type, "Negotiate") != 0) goto done;

    auth_header_value = ap_getword_white(req->pool, &auth_header);
    if (!auth_header_value) goto done;
    input.length = apr_base64_decode_len(auth_header_value) + 1;
    input.value = apr_pcalloc(req->pool, input.length);
    if (!input.value) goto done;
    input.length = apr_base64_decode(input.value, auth_header_value);

    /* FIXME: this works only with "one-roundtrip" gssapi auth for now,
     * should work with Krb, will fail with NTLMSSP */
    maj = gss_accept_sec_context(&min, &ctx, GSS_C_NO_CREDENTIAL,
                                 &input, GSS_C_NO_CHANNEL_BINDINGS,
                                 &client, NULL, &output, &flags, NULL,
                                 &delegated_cred);
    if (GSS_ERROR(maj)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, req,
                      mag_error(req, "gss_accept_sec_context() failed",
                                maj, min));
        goto done;
    }

    if (output.length) {
        replen = apr_base64_encode_len(output.length) + 1;
        reply = apr_pcalloc(req->pool, 10 + replen);
        if (!reply) goto done;
        memcpy(reply, "Negotiate ", 10);
        apr_base64_encode(&reply[10], output.value, output.length);
        reply[replen] = '\0';
        apr_table_add(req->err_headers_out, "WWW-Authenticate", reply);
    }

    maj = gss_display_name(&min, client, &name, NULL);
    if (GSS_ERROR(maj)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, req,
                      mag_error(req, "gss_accept_sec_context() failed",
                                maj, min));
        goto done;
    }

    /* FIXME: save creds */

    req->ap_auth_type = "Negotiate";
    req->user = apr_pstrndup(req->pool, name.value, name.length);
    ret = OK;

done:
    if (ret == HTTP_UNAUTHORIZED) {
        apr_table_add(req->err_headers_out, "WWW-Authenticate", "Negotiate");
    }
    gss_release_cred(&min, &delegated_cred);
    gss_release_buffer(&min, &output);
    gss_release_name(&min, &client);
    gss_release_buffer(&min, &name);
    gss_delete_sec_context(&min, &ctx, GSS_C_NO_BUFFER);
    return ret;
}


static void *mag_create_dir_config(apr_pool_t *p, char *dir)
{
    struct mag_config *cfg;

    cfg = (struct mag_config *)apr_pcalloc(p, sizeof(struct mag_config));
    if (!cfg) return NULL;

    return cfg;
}

static const char *mag_ssl_only(cmd_parms *parms, void *mconfig, int on)
{
    struct mag_config *cfg = (struct mag_config *)mconfig;
    cfg->ssl_only = on ? true : false;
    return NULL;
}

static const char *mag_save_creds(cmd_parms *parms, void *mconfig, int on)
{
    struct mag_config *cfg = (struct mag_config *)mconfig;
    cfg->save_creds = on ? true : false;
    return NULL;
}

static const command_rec mag_commands[] = {
    AP_INIT_FLAG("GSSSSLOnly", mag_ssl_only, NULL, OR_AUTHCFG,
                  "Work only if connection is SSL Secured"),
    AP_INIT_FLAG("GSSSaveCreds", mag_save_creds, NULL, OR_AUTHCFG,
                  "Save credentials"),
    { NULL }
};

static void
mag_register_hooks(apr_pool_t *p)
{
    ap_hook_check_user_id(mag_auth, NULL, NULL, APR_HOOK_MIDDLE);
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

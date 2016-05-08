/* Copyright (C) 2015, 2016 mod_auth_gssapi contributors - See COPYING for (C) terms */

#include "mod_auth_gssapi.h"

struct name_attr {
    gss_buffer_desc name;
    int authenticated;
    int complete;
    gss_buffer_desc value;
    gss_buffer_desc display_value;
    const char *env_name;
    int number;
    int more;
};

static bool mag_get_name_attr(request_rec *req,
                              gss_name_t name, struct name_attr *attr)
{
    uint32_t maj, min;

    maj = gss_get_name_attribute(&min, name, &attr->name,
                                 &attr->authenticated,
                                 &attr->complete,
                                 &attr->value,
                                 &attr->display_value,
                                 &attr->more);
    if (GSS_ERROR(maj)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, req,
                      "gss_get_name_attribute() failed on %.*s%s",
                      (int)attr->name.length, (char *)attr->name.value,
                      mag_error(req, "", maj, min));
        return false;
    }

    return true;
}

static void mc_add_name_attribute(struct mag_conn *mc,
                                  const char *name, const char *value)
{
    size_t size;

    if (mc->na_count % 16 == 0) {
        size = sizeof(struct mag_attr) * (mc->na_count + 16);
        mc->name_attributes = realloc(mc->name_attributes, size);
        if (!mc->name_attributes) apr_pool_abort_get(mc->pool)(ENOMEM);
    }

    mc->name_attributes[mc->na_count].name = apr_pstrdup(mc->pool, name);
    mc->name_attributes[mc->na_count].value = apr_pstrdup(mc->pool, value);
    mc->na_count++;
}

static void mag_set_env_name_attr(request_rec *req, struct mag_conn *mc,
                                  struct name_attr *attr)
{
    char *value = "";
    int len = 0;

    /* Prefer a display_value, otherwise fallback to value */
    if (attr->display_value.length != 0) {
        len = attr->display_value.length;
        value = (char *)attr->display_value.value;
    } else if (attr->value.length != 0) {
        len = apr_base64_encode_len(attr->value.length);
        value = apr_pcalloc(req->pool, len);
        len = apr_base64_encode(value,
                                (char *)attr->value.value,
                                attr->value.length);
    }

    if (attr->number == 1) {
        mc_add_name_attribute(mc,
                              attr->env_name,
                              apr_psprintf(req->pool, "%.*s", len, value));
    }
    if (attr->more != 0 || attr->number > 1) {
        mc_add_name_attribute(mc,
                              apr_psprintf(req->pool, "%s_%d",
                                           attr->env_name, attr->number),
                              apr_psprintf(req->pool, "%.*s", len, value));
    }
    if (attr->more == 0 && attr->number > 1) {
        mc_add_name_attribute(mc,
                              apr_psprintf(req->pool, "%s_N", attr->env_name),
                              apr_psprintf(req->pool, "%d", attr->number - 1));
    }
}

static void mag_add_json_name_attr(request_rec *req, bool first,
                                   struct name_attr *attr, char **json)
{
    const char *value = "";
    int len = 0;
    char *b64value = NULL;
    int b64len = 0;
    const char *vstart = "";
    const char *vend = "";
    const char *vformat;

    if (attr->value.length != 0) {
        b64len = apr_base64_encode_len(attr->value.length);
        b64value = apr_pcalloc(req->pool, b64len);
        b64len = apr_base64_encode(b64value,
                                   (char *)attr->value.value,
                                   attr->value.length);
    }
    if (attr->display_value.length != 0) {
        len = attr->display_value.length;
        value = (const char *)attr->display_value.value;
    }
    if (attr->number == 1) {
        *json = apr_psprintf(req->pool,
                            "%s%s\"%.*s\":{\"authenticated\":%s,"
                                          "\"complete\":%s,"
                                          "\"values\":[",
                            *json, (first ? "" : ","),
                            (int)attr->name.length, (char *)attr->name.value,
                            attr->authenticated ? "true" : "false",
                            attr->complete ? "true" : "false");
    } else {
        vstart = ",";
    }

    if (b64value) {
        if (len) {
            vformat = "%s%s{\"raw\":\"%s\",\"display\":\"%.*s\"}%s";
        } else {
            vformat = "%s%s{\"raw\":\"%s\",\"display\":%.*s}%s";
        }
    } else {
        if (len) {
            vformat = "%s%s{\"raw\":%s,\"display\":\"%.*s\"}%s";
        } else {
            vformat = "%s%s{\"raw\":%s,\"display\":%.*s}%s";
        }
    }

    if (attr->more == 0) {
        vend = "]}";
    }

    *json = apr_psprintf(req->pool, vformat, *json,
                        vstart,
                        b64value ? b64value : "null",
                        len ? len : 4, len ? value : "null",
                        vend);
}

gss_buffer_desc empty_buffer = GSS_C_EMPTY_BUFFER;

void mag_get_name_attributes(request_rec *req, struct mag_config *cfg,
                             gss_name_t name, struct mag_conn *mc)
{
    if (!cfg->name_attributes) {
        return;
    }

    uint32_t maj, min;
    gss_buffer_set_t attrs = GSS_C_NO_BUFFER_SET;
    struct name_attr attr;
    char *json = NULL;
    char *error;
    int count = 0;
    int i, j;

    maj = gss_inquire_name(&min, name, NULL, NULL, &attrs);
    if (GSS_ERROR(maj)) {
        error = mag_error(req, "gss_inquire_name() failed", maj, min);
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, req, "%s", error);
        apr_table_set(req->subprocess_env, "GSS_NAME_ATTR_ERROR", error);
        return;
    }

    if (!attrs || attrs->count == 0) {
        mc_add_name_attribute(mc, "GSS_NAME_ATTR_ERROR", "0 attributes found");
    }

    if (cfg->name_attributes->output_json) {

        if (attrs) count = attrs->count;

        json = apr_psprintf(req->pool,
                            "{\"name\":\"%s\",\"attributes\":{",
                            mc->gss_name);
    } else {
        count = cfg->name_attributes->map_count;
    }

    for (i = 0; i < count; i++) {

        memset(&attr, 0, sizeof(struct name_attr));

        if (cfg->name_attributes->output_json) {
            attr.name = attrs->elements[i];
            for (j = 0; j < cfg->name_attributes->map_count; j++) {
                if (strncmp(cfg->name_attributes->map[j].attr_name,
                            attrs->elements[i].value,
                            attrs->elements[i].length) == 0) {
                    attr.env_name = cfg->name_attributes->map[j].env_name;
                    break;
                }
            }
        } else {
            attr.name.length = strlen(cfg->name_attributes->map[i].attr_name);
            attr.name.value = cfg->name_attributes->map[i].attr_name;
            attr.env_name = cfg->name_attributes->map[i].env_name;
        }

        attr.number = 0;
        attr.more = -1;
        do {
            attr.number++;
            attr.value = empty_buffer;
            attr.display_value = empty_buffer;

            if (!mag_get_name_attr(req, name, &attr)) break;

            if (cfg->name_attributes->output_json) {
                mag_add_json_name_attr(req, i == 0, &attr, &json);
            }
            if (attr.env_name) {
                mag_set_env_name_attr(req, mc, &attr);
            }

            gss_release_buffer(&min, &attr.value);
            gss_release_buffer(&min, &attr.display_value);
        } while (attr.more != 0);
    }

    if (cfg->name_attributes->output_json) {
        json = apr_psprintf(req->pool, "%s}}", json);
        mc_add_name_attribute(mc, "GSS_NAME_ATTRS_JSON", json);
    }
}

static void mag_set_name_attributes(request_rec *req, struct mag_conn *mc)
{
    for (int i = 0; i < mc->na_count; i++) {
        apr_table_set(req->subprocess_env,
                      mc->name_attributes[i].name,
                      mc->name_attributes[i].value);
    }
}

static void mag_set_KRB5CCANME(request_rec *req, const char *dir,
                               const char *ccname)
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

    value = apr_psprintf(req->pool, "FILE:%s/%s", dir, ccname);
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

    if (mc->name_attributes) {
        mag_set_name_attributes(req, mc);
    }

#ifdef HAVE_CRED_STORE
    if (cfg->deleg_ccache_dir && mc->delegated && mc->ccname) {
        mag_set_KRB5CCANME(req, cfg->deleg_ccache_dir, mc->ccname);
    }
#endif
}

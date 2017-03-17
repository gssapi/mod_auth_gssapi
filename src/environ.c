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
                      mag_error(req->pool, "", maj, min));
        return false;
    }

    return true;
}

static apr_status_t mag_mc_name_attrs_cleanup(void *data)
{
    struct mag_conn *mc = (struct mag_conn *)data;
    free(mc->name_attributes);
    mc->name_attributes = NULL;
    return 0;
}

static void mc_add_name_attribute(struct mag_conn *mc,
                                  const char *name, const char *value)
{
    size_t size;

    if (mc->na_count % 16 == 0) {
        size = sizeof(struct mag_attr) * (mc->na_count + 16);
        mc->name_attributes = realloc(mc->name_attributes, size);
        if (!mc->name_attributes) apr_pool_abort_get(mc->pool)(ENOMEM);
        apr_pool_userdata_setn(mc, GSS_NAME_ATTR_USERDATA,
                               mag_mc_name_attrs_cleanup, mc->pool);
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

static char *mag_escape_display_value(request_rec *req,
                                      gss_buffer_desc disp_value)
{
    /* This function returns a copy (in the pool) of the given gss_buffer_t
     * where some characters are escaped as required by RFC4627. The string is
     * NULL terminated */
    char *value = disp_value.value;
    char *escaped_value = NULL;
    char *p = NULL;

    /* gss_buffer_t are not \0 terminated, but our result will be. Hence,
     * escaped length will be original length * 6 + 1 in the worst case */
    p = escaped_value = apr_palloc(req->pool, disp_value.length * 6 + 1);
    for (size_t i = 0; i < disp_value.length; i++) {
        switch (value[i]) {
        case '"':
            memcpy(p, "\\\"", 2);
            p += 2;
            break;
        case '\\':
            memcpy(p, "\\\\", 2);
            p += 2;
            break;
        case '\b':
            memcpy(p, "\\b", 2);
            p += 2;
            break;
        case '\t':
            memcpy(p, "\\t", 2);
            p += 2;
            break;
        case '\r':
            memcpy(p, "\\r", 2);
            p += 2;
            break;
        case '\f':
            memcpy(p, "\\f", 2);
            p += 2;
            break;
        case '\n':
            memcpy(p, "\\n", 2);
            p += 2;
            break;
        default:
            if (value[i] <= 0x1F) {
                apr_snprintf(p, 7, "\\u%04d", (int)value[i]);
                p += 6;
            } else {
                *p = value[i];
                p += 1;
            }
            break;
        }
    }
    /* make the string NULL terminated */
    *p = '\0';
    return escaped_value;
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
        value = mag_escape_display_value(req, attr->display_value);
        len = strlen(value);
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
        error = mag_error(req->pool, "gss_inquire_name() failed", maj, min);
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, req, "%s", error);
        apr_table_set(mc->env, "GSS_NAME_ATTR_ERROR", error);
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
        apr_table_set(mc->env,
                      mc->name_attributes[i].name,
                      mc->name_attributes[i].value);
    }
}

static void mag_set_ccname_envvar(request_rec *req, struct mag_config *cfg,
                                  struct mag_conn *mc)
{
    apr_status_t status;
    apr_int32_t wanted = APR_FINFO_MIN | APR_FINFO_OWNER | APR_FINFO_PROT;
    apr_finfo_t finfo = { 0 };
    char *path;
    char *value;

    path = apr_psprintf(req->pool, "%s/%s", cfg->deleg_ccache_dir, mc->ccname);

    status = apr_stat(&finfo, path, wanted, req->pool);
    if (status == APR_SUCCESS) {
        if ((cfg->deleg_ccache_mode != 0) &&
            (finfo.protection != cfg->deleg_ccache_mode)) {
            status = apr_file_perms_set(path, cfg->deleg_ccache_mode);
            if (status != APR_SUCCESS)
                ap_log_rerror(APLOG_MARK, APLOG_WARNING|APLOG_NOERRNO, 0, req,
                              "failed to set perms (%o) on file (%s)!",
                              cfg->deleg_ccache_mode, path);
        }
        if ((cfg->deleg_ccache_uid != 0) &&
            (finfo.user != cfg->deleg_ccache_uid)) {
            status = lchown(path, cfg->deleg_ccache_uid, -1);
            if (status != 0)
                ap_log_rerror(APLOG_MARK, APLOG_WARNING|APLOG_NOERRNO, 0, req,
                              "failed to set user (%u) on file (%s)!",
                              cfg->deleg_ccache_uid, path);
        }
        if ((cfg->deleg_ccache_gid != 0) &&
            (finfo.group != cfg->deleg_ccache_gid)) {
            status = lchown(path, -1, cfg->deleg_ccache_gid);
            if (status != 0)
                ap_log_rerror(APLOG_MARK, APLOG_WARNING|APLOG_NOERRNO, 0, req,
                              "failed to set group (%u) on file (%s)!",
                              cfg->deleg_ccache_gid, path);
        }
    } else {
        /* set the file cache anyway, but warn */
        ap_log_rerror(APLOG_MARK, APLOG_WARNING|APLOG_NOERRNO, 0, req,
                      "KRB5CCNAME file (%s) lookup failed!", path);
    }

    value = apr_psprintf(req->pool, "FILE:%s", path);
    apr_table_set(mc->env, cfg->ccname_envvar, value);
}

void mag_export_req_env(request_rec *req, apr_table_t *env)
{
    const apr_array_header_t *arr = apr_table_elts(env);
    const apr_table_entry_t *elts = (const apr_table_entry_t*)arr->elts;

    for (int i = 0; i < arr->nelts; ++i)
        apr_table_set(req->subprocess_env, elts[i].key, elts[i].val);
}

void mag_set_req_data(request_rec *req,
                      struct mag_config *cfg,
                      struct mag_conn *mc)
{
    apr_table_set(mc->env, "GSS_NAME", mc->gss_name);
    apr_table_set(mc->env, "GSS_SESSION_EXPIRATION",
                  apr_psprintf(req->pool,
                               "%ld", (long)mc->expiration));
    req->ap_auth_type = (char *) mag_str_auth_type(mc->auth_type);
    req->user = apr_pstrdup(req->pool, mc->user_name);

    if (mc->name_attributes) {
        mag_set_name_attributes(req, mc);
    }

#ifdef HAVE_CRED_STORE
    if (cfg->deleg_ccache_dir && mc->delegated && mc->ccname) {
        mag_set_ccname_envvar(req, cfg, mc);
    }
#endif

    ap_set_module_config(req->request_config, &auth_gssapi_module, mc->env);
    mag_export_req_env(req, mc->env);
}

void mag_publish_error(request_rec *req, uint32_t maj, uint32_t min,
                       const char *gss_err, const char *mag_err)
{
    if (gss_err) {
        apr_table_set(req->subprocess_env, "GSS_ERROR_MAJ",
                      apr_psprintf(req->pool, "%u", (unsigned)maj));
        apr_table_set(req->subprocess_env, "GSS_ERROR_MIN",
                      apr_psprintf(req->pool, "%u", (unsigned)min));
        apr_table_set(req->subprocess_env, "MAG_ERROR_TEXT", gss_err);
    }
    if (mag_err)
        apr_table_set(req->subprocess_env, "MAG_ERROR", mag_err);
}

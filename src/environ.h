/* Copyright (C) 2015 mod_auth_gssapi contributors - See COPYING for (C) terms */

struct mag_config;
struct mag_conn;

void mag_get_name_attributes(request_rec *req,
                             struct mag_config *cfg,
                             gss_name_t name,
                             struct mag_conn *mc);

void mag_export_req_env(request_rec *req, apr_table_t *env);

void mag_set_req_data(request_rec *req,
                      struct mag_config *cfg,
                      struct mag_conn *mc);

void mag_publish_error(request_rec *req, uint32_t maj, uint32_t min,
                       const char *gss_err, const char *mag_err);
void mag_set_req_attr_fail(request_rec *req, struct mag_config *cfg,
                           struct mag_conn *mc);
void mag_publish_mech(request_rec *req, struct mag_conn *mc,
                      const char *auth_type, gss_OID mech_type);

/* Copyright (C) 2015 mod_auth_gssapi authors - See COPYING for (C) terms */

struct mag_config;
struct mag_conn;

void mag_get_name_attributes(request_rec *req,
                             struct mag_config *cfg,
                             gss_name_t name,
                             struct mag_conn *mc);

void mag_set_req_data(request_rec *req,
                      struct mag_config *cfg,
                      struct mag_conn *mc);

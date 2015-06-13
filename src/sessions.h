/* Copyright (C) 2014 mod_auth_gssapi authors - See COPYING for (C) terms */

struct mag_config;
struct mag_conn;

void mag_post_config_session(void);
void mag_check_session(request_rec *req,
                       struct mag_config *cfg, struct mag_conn **conn);
void mag_attempt_session(request_rec *req,
                         struct mag_config *cfg, struct mag_conn *mc);
bool mag_basic_check(struct mag_config *cfg, struct mag_conn *mc,
                     gss_buffer_desc user, gss_buffer_desc pwd);
void mag_basic_cache(struct mag_config *cfg, struct mag_conn *mc,
                     gss_buffer_desc user, gss_buffer_desc pwd);

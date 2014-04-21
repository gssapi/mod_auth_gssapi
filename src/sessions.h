/* Copyright (C) 2014 mod_auth_gssapi authors - See COPYING for (C) terms */

struct mag_config;
struct mag_conn;

void mag_post_config_session(void);
void mag_check_session(request_rec *req,
                       struct mag_config *cfg, struct mag_conn **conn);
void mag_attempt_session(request_rec *req,
                         struct mag_config *cfg, struct mag_conn *mc);

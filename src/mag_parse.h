/* Copyright (C) 2017 mod_auth_gssapi contributors - See COPYING for (C) terms */

#ifndef _MAG_PARSE_H_
#define _MAG_PARSE_H_
extern int mag_verify_name_attributes(const char *expr, const char **attrs,
                                      const char **vals);
extern int mag_check_name_attr_expr(const char *expr);
#endif /* _MAG_PARSE_H_ */

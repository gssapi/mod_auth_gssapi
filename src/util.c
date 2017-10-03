/* Copyright (C) 2017 mod_auth_gssapi contributors - See COPYING for (C) terms */

#include "mod_auth_gssapi.h"

#define NSS_BUF_MIN 1024
#define NSS_BUF_MAX 1024*1024
static char *get_buf(char *cur, size_t *len)
{
    if (*len == 0) {
        *len = NSS_BUF_MIN;
    } else {
        *len *= 2;
    }
    if (*len > NSS_BUF_MAX) {
        *len = 0; /* will free the buf and return NULL */
    }
    return realloc(cur, *len);
}

int mag_get_user_uid(const char *name, uid_t *uid)
{
    struct passwd pwd, *user;
    size_t buflen = 0;
    char *buf = NULL;
    int ret;

    do {
        buf = get_buf(buf, &buflen);
        if (buf == NULL || buflen == 0) {
            ret = ENOMEM;
            break;
        }
        ret = getpwnam_r(name, &pwd, buf, buflen, &user);
    } while (ret == ERANGE);
    if (ret != 0 || user != &pwd) {
        ret = (ret == 0) ? EINVAL : ret;
    } else {
        *uid = user->pw_uid;
    }
    free(buf);
    return ret;
}

int mag_get_group_gid(const char *name, gid_t *gid)
{
    struct group grp, *group;
    size_t buflen = 0;
    char *buf = NULL;
    int ret;

    do {
        buf = get_buf(buf, &buflen);
        if (buf == NULL || buflen == 0) {
            ret = ENOMEM;
            break;
        }
        ret = getgrnam_r(name, &grp, buf, buflen, &group);
    } while (ret == ERANGE);
    if (ret != 0 || group != &grp) {
        ret = (ret == 0) ? EINVAL : ret;
    } else {
        *gid = group->gr_gid;
    }
    free(buf);
    return ret;
}

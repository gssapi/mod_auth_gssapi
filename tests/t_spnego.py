#!/usr/bin/env python3
# Copyright (C) 2015 - mod_auth_gssapi contributors, see COPYING for license.

import os
from stat import ST_MODE

import requests
from requests_gssapi import HTTPKerberosAuth, OPTIONAL # noqa

if __name__ == '__main__':
    sess = requests.Session()
    url = 'http://%s/spnego/' % os.environ['NSS_WRAPPER_HOSTNAME']
    r = sess.get(url, auth=HTTPKerberosAuth(delegate=True))
    if r.status_code != 200:
        raise ValueError('Spnego failed')

    c = r.cookies
    if not c.get("gssapi_session").startswith("MagBearerToken="):
        raise ValueError('gssapi_session not set')

    data = os.stat(os.environ['DELEGCCACHE'])
    if data[ST_MODE] != 0o100666:
        raise ValueError('Incorrect perm on ccache: %o' % data[ST_MODE])

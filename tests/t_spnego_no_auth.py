#!/usr/bin/python
# Copyright (C) 2015 - mod_auth_gssapi contributors, see COPYING for license.

import os
import requests
from requests_kerberos import HTTPKerberosAuth, OPTIONAL


if __name__ == '__main__':
    sess = requests.Session()
    url = 'http://%s/spnego/' % os.environ['NSS_WRAPPER_HOSTNAME']

    r = sess.get(url)
    if r.status_code != 401:
        raise ValueError('Spnego failed - 401 expected')

    if not (r.headers.get("WWW-Authenticate") and
            r.headers.get("WWW-Authenticate").startswith("Negotiate")):
        raise ValueError('Spnego failed - WWW-Authenticate Negotiate header '
                         'missing')


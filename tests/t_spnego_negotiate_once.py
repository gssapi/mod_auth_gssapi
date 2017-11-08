#!/usr/bin/env python
# Copyright (C) 2015 - mod_auth_gssapi contributors, see COPYING for license.

import os
import requests
from requests_kerberos import HTTPKerberosAuth, OPTIONAL # noqa


if __name__ == '__main__':
    sess = requests.Session()
    url = 'http://%s/spnego_negotiate_once/' % (
        os.environ['NSS_WRAPPER_HOSTNAME'])

    # ensure a 401 with the appropriate WWW-Authenticate header is returned
    # when no auth is provided
    r = sess.get(url)
    if r.status_code != 401:
        raise ValueError('Spnego Negotiate Once failed - 401 expected')
    if not (r.headers.get("WWW-Authenticate") and
            r.headers.get("WWW-Authenticate").startswith("Negotiate")):
        raise ValueError('Spnego Negotiate Once failed - WWW-Authenticate '
                         'Negotiate header missing')

    # test sending a bad Authorization header with GssapiNegotiateOnce enabled
    r = sess.get(url, headers={"Authorization": "Negotiate badvalue"})
    if r.status_code != 401:
        raise ValueError('Spnego Negotiate Once failed - 401 expected')
    if r.headers.get("WWW-Authenticate"):
        raise ValueError('Spnego Negotiate Once failed - WWW-Authenticate '
                         'Negotiate present but GssapiNegotiateOnce is '
                         'enabled')

    # ensure a 200 is returned when valid auth is provided
    r = sess.get(url, auth=HTTPKerberosAuth())
    if r.status_code != 200:
        raise ValueError('Spnego Negotiate Once failed')

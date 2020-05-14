#!/usr/bin/env python
# Copyright (C) 2015 - mod_auth_gssapi contributors, see COPYING for license.

import os

import requests


if __name__ == '__main__':
    url = 'http://%s/nonego/' % (os.environ['NSS_WRAPPER_HOSTNAME'])

    # ensure a 401 with the appropriate WWW-Authenticate header is returned
    # when no auth is provided
    r = requests.get(url)
    if r.status_code != 401:
        raise ValueError('NO Negotiate failed - 401 expected')
    if not (r.headers.get("WWW-Authenticate") and
            r.headers.get("WWW-Authenticate").startswith("Negotiate")):
        raise ValueError('NO Negotiate failed - WWW-Authenticate '
                         'Negotiate header is absent')

    # ensure a 401 with the WWW-Authenticate Negotiate header is absent
    # when the special User-Agent is sent
    r = requests.get(url, headers={'User-Agent': 'NONEGO'})
    if r.status_code != 401:
        raise ValueError('NO Negotiate failed - 401 expected')
    if r.headers.get("WWW-Authenticate") and \
       r.headers.get("WWW-Authenticate").startswith("Negotiate"):
        raise ValueError('NO Negotiate failed - WWW-Authenticate '
                         'Negotiate header is present, should be absent')

#!/usr/bin/env python3
# Copyright (C) 2020 - mod_auth_gssapi contributors, see COPYING for license.

import os
import time

import requests
from requests.auth import HTTPBasicAuth


if __name__ == '__main__':
    s = requests.Session()
    url = 'http://{}/basic_auth_timeout/auth/'.format(
            os.environ['NSS_WRAPPER_HOSTNAME']
    )
    url2 = 'http://{}/basic_auth_timeout/session/'.format(
            os.environ['NSS_WRAPPER_HOSTNAME']
    )

    r = s.get(url, auth=HTTPBasicAuth(os.environ['TIMEOUT_USER'],
                                      os.environ['MAG_USER_PASSWORD']))
    if r.status_code != 200:
        raise ValueError('Basic Auth Failed')

    time.sleep(301)
    r = s.get(url2)
    if r.status_code != 200:
        raise ValueError('Session Auth Failed')

    time.sleep(401)

    r = s.get(url2)
    if r.status_code == 200:
        raise ValueError('Timeout check Failed')

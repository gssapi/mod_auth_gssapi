#!/usr/bin/python
# Copyright (C) 2015 - mod_auth_gssapi contributors, see COPYING for license.

import os
import requests
import sys
from requests.auth import HTTPBasicAuth


if __name__ == '__main__':
    s = requests.Session()

    url = 'http://%s:%s@%s/basic_auth_krb5/' % (os.environ['MAG_USER_NAME'],
                                                os.environ['MAG_USER_PASSWORD'],
                                                os.environ['NSS_WRAPPER_HOSTNAME'])
    r = s.get(url)
    if r.status_code != 200:
        raise ValueError('Basic Auth: Failed Authentication')

    url = 'http://%s:%s@%s/basic_auth_krb5/' % (os.environ['MAG_USER_NAME_2'],
                                                os.environ['MAG_USER_PASSWORD'],
                                                os.environ['NSS_WRAPPER_HOSTNAME'])
    r = s.get(url)
    if r.status_code == 200:
        raise ValueError('Basic Auth: Got Success while expecting Error')
    if not 'GSS ERROR' in r.text:
        raise ValueError('Basic Auth: Expected error variable is missing')

    url = 'http://%s:%s@%s/basic_auth_krb5/' % (os.environ['MAG_USER_NAME_2'],
                                                os.environ['MAG_USER_PASSWORD_2'],
                                                os.environ['NSS_WRAPPER_HOSTNAME'])
    r = s.get(url)
    if r.status_code != 200:
        raise ValueError('Basic Auth: Failed Authentication')

    url = 'http://%s/basic_auth_krb5/' % os.environ['NSS_WRAPPER_HOSTNAME']
    r = s.get(url)
    if r.status_code == 200:
        raise ValueError('Basic Auth: Got Success while expecting Error')

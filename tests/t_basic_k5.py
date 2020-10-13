#!/usr/bin/env python3
# Copyright (C) 2015 - mod_auth_gssapi contributors, see COPYING for license.

import os

import requests
from requests.auth import HTTPBasicAuth


if __name__ == '__main__':
    url = 'http://%s/basic_auth_krb5/' % os.environ['NSS_WRAPPER_HOSTNAME']
    r = requests.get(url, auth=HTTPBasicAuth(os.environ['MAG_USER_NAME'],
                                             os.environ['MAG_USER_PASSWORD']))
    if r.status_code != 200:
        raise ValueError('Basic Auth Failed')

#!/usr/bin/env python
# Copyright (C) 2020 - mod_auth_gssapi contributors, see COPYING for license.

import os

import requests
from requests.auth import HTTPBasicAuth


if __name__ == '__main__':
    url = 'http://%s/keytab_file_check/' % os.environ['NSS_WRAPPER_HOSTNAME']
    r = requests.get(url, auth=HTTPBasicAuth(os.environ['MAG_USER_NAME'],
                                             os.environ['MAG_USER_PASSWORD']))
    if r.status_code != 200:
        raise ValueError('Basic Auth Failed(Keytab File Check)')

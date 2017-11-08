#!/usr/bin/env python
# Copyright (C) 2015 - mod_auth_gssapi contributors, see COPYING for license.

import os
import requests


if __name__ == '__main__':
    s = requests.Session()

    url = 'http://%s:%s@%s/basic_auth_krb5/' % (os.environ['MAG_USER_NAME'],
                                                os.environ['MAG_USER_PASSWORD'],
                                                os.environ['NSS_WRAPPER_HOSTNAME'])
    r = s.get(url)
    if r.status_code != 200:
        raise ValueError('Basic Auth Failed')

    url = 'http://%s:%s@%s/basic_auth_krb5/' % (os.environ['MAG_USER_NAME_2'],
                                                os.environ['MAG_USER_PASSWORD_2'],
                                                os.environ['NSS_WRAPPER_HOSTNAME'])
    r2 = s.get(url)
    if r2.status_code != 200:
        raise ValueError('Basic Auth failed')

    if r.text == r2.text:
         raise ValueError('Basic Auth fatal error')

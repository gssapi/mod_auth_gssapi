#!/usr/bin/python
# Copyright (C) 2015 - mod_auth_gssapi contributors, see COPYING for license.

import os
import requests
from requests.auth import HTTPBasicAuth


if __name__ == '__main__':
    proxy = 'http://%s:%s@%s:%s' % (os.environ['MAG_USER_NAME'],
                                      os.environ['MAG_USER_PASSWORD'],
                                      os.environ['NSS_WRAPPER_HOSTNAME'],
                                      os.environ['WRAP_PROXY_PORT'])
    proxies = { "http": proxy, }
    url = 'http://%s/basic_auth_krb5/' % os.environ['NSS_WRAPPER_HOSTNAME']
    r = requests.get(url, proxies=proxies,
                     auth=HTTPBasicAuth(os.environ['MAG_USER_NAME_2'],
                                        os.environ['MAG_USER_PASSWORD_2']))
    if r.status_code != 200:
        raise ValueError('Basic Proxy Auth Failed')

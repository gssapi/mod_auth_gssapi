#!/usr/bin/env python
# Copyright (C) 2015 - mod_auth_gssapi contributors, see COPYING for license.

import os

import requests
from requests_gssapi import HTTPKerberosAuth, OPTIONAL # noqa


if __name__ == '__main__':
    sess = requests.Session()
    url = 'http://%s/bad_acceptor_name/' % os.environ['NSS_WRAPPER_HOSTNAME']
    r = sess.get(url, auth=HTTPKerberosAuth(delegate=True))
    if r.status_code != 200:
        raise ValueError('Bad Acceptor Name failed')

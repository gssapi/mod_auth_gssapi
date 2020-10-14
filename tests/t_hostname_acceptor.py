#!/usr/bin/env python3
# Copyright (C) 2017 - mod_auth_gssapi contributors, see COPYING for license.

import sys

import requests
from requests_gssapi import HTTPKerberosAuth, OPTIONAL # noqa


if __name__ == '__main__':
    sess = requests.Session()
    url = 'http://{}/{}/'.format(sys.argv[1], sys.argv[2])
    r = sess.get(url, auth=HTTPKerberosAuth(delegate=True))
    if r.status_code != 200:
        raise ValueError('Hostname acceptor ({}) failed'.format(sys.argv[2]))

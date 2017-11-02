#!/usr/bin/env python
# Copyright (C) 2017 - mod_auth_gssapi contributors, see COPYING for license.

import os
import requests
import sys
from stat import ST_MODE
from requests_kerberos import HTTPKerberosAuth, OPTIONAL


if __name__ == '__main__':
    sess = requests.Session()
    url = 'http://%s/hostname_acceptor/' % sys.argv[1]
    r = sess.get(url, auth=HTTPKerberosAuth(delegate=True))
    if r.status_code != 200:
        raise ValueError('Hostname-based acceptor failed')

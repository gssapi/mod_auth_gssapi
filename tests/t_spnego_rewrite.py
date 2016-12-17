#!/usr/bin/python
# Copyright (C) 2015 - mod_auth_gssapi contributors, see COPYING for license.

import os
import requests
from requests_kerberos import HTTPKerberosAuth, OPTIONAL


if __name__ == '__main__':
    sess = requests.Session()
    url = 'http://%s/spnego_rewrite/xxx' % os.environ['NSS_WRAPPER_HOSTNAME']
    r = sess.get(url, auth=HTTPKerberosAuth())

    if r.status_code != 200:
        raise ValueError('Spnego Rewrite failed')

    if r.text.rstrip() != os.environ['MAG_GSS_NAME']:
        raise ValueError('Spnego Rewrite, GSS_NAME check failed')

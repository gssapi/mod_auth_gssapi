#!/usr/bin/env python3
# Copyright (C) 2015 - mod_auth_gssapi contributors, see COPYING for license.

import os

import requests
from requests_gssapi import HTTPKerberosAuth, OPTIONAL # noqa


if __name__ == '__main__':
    sess = requests.Session()
    url = 'http://%s/required_name_attr1/' % os.environ['NSS_WRAPPER_HOSTNAME']
    r = sess.get(url, auth=HTTPKerberosAuth())

    if r.status_code != 200:
        raise ValueError('Required Name Attributes failed')

    sess = requests.Session()
    url = 'http://%s/required_name_attr2/' % os.environ['NSS_WRAPPER_HOSTNAME']
    r = sess.get(url, auth=HTTPKerberosAuth())

    if r.status_code != 200:
        raise ValueError('Required Name Attributes failed')

    sess = requests.Session()
    url = 'http://%s/required_name_attr3/' % os.environ['NSS_WRAPPER_HOSTNAME']
    r = sess.get(url, auth=HTTPKerberosAuth())

    if r.status_code != 200:
        raise ValueError('Required Name Attributes failed')

    sess = requests.Session()
    url = 'http://%s/required_name_attr4/' % os.environ['NSS_WRAPPER_HOSTNAME']
    r = sess.get(url, auth=HTTPKerberosAuth())

    if r.status_code != 403:
        raise ValueError('Required Name Attributes failed')

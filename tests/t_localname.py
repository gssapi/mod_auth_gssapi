#!/usr/bin/env python3
# Copyright (C) 2020 - mod_auth_gssapi contributors, see COPYING for license.

import os
import subprocess
import sys

import gssapi

import requests

from requests_gssapi import HTTPSPNEGOAuth


def use_requests(auth):
    sess = requests.Session()
    url = 'http://%s/gss_localname/' % os.environ['NSS_WRAPPER_HOSTNAME']

    r = sess.get(url, auth=auth)
    if r.status_code != 200:
        raise ValueError('Localname failed')

    if r.text.rstrip() != os.environ['MAG_REMOTE_USER']:
        raise ValueError('Localname, REMOTE_USER check failed')


def use_curl():
    url = 'http://%s/gss_localname/' % os.environ['NSS_WRAPPER_HOSTNAME']
    curl = subprocess.Popen(["curl", "--negotiate", "-u:", url],
                            stdout=subprocess.PIPE)
    curl.wait()
    if curl.returncode != 0:
        raise ValueError('Localname failed')

    line = curl.stdout.read().strip(b' \t\n\r').decode('utf-8')
    if line != os.environ['MAG_REMOTE_USER']:
        raise ValueError('Localname, REMOTE_USER check failed (%s != %s)' % (
                         line, os.environ['MAG_REMOTE_USER']))


if __name__ == '__main__':
    mech_name = None
    if len(sys.argv) > 1:
        mech_name = sys.argv[1]

    mech = None
    if mech_name is not None:
        mech = gssapi.mechs.Mechanism.from_sasl_name(mech_name)

    try:
        auth = HTTPSPNEGOAuth(mech=mech)
        use_requests(auth)
    except TypeError:
        # odler version of requests that does not support mechs
        if mech_name == 'SPNEGO':
            use_curl()
        elif mech_name == 'GS2-KRB5':
            # older request versions use krb5 as the mech by default
            auth = HTTPSPNEGOAuth()
            use_requests(auth)
        else:
            sys.exit(42)  # SKIP

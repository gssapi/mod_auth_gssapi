#!/usr/bin/env python
# Copyright (C) 2015 - mod_auth_gssapi contributors, see COPYING for license.

import os
from base64 import b64encode

import gssapi
import requests


def getAuthToken(target):
    spnego_mech = gssapi.raw.OID.from_int_seq('1.3.6.1.5.5.2')

    name = gssapi.Name('HTTP@%s' % target,
                       gssapi.NameType.hostbased_service)

    ctx = gssapi.SecurityContext(name=name, mech=spnego_mech)
    token = ctx.step()

    return 'Negotiate %s' % b64encode(token).decode()


if __name__ == '__main__':
    s = requests.Session()

    target = os.environ['NSS_WRAPPER_HOSTNAME']
    url = 'http://%s/spnego/' % target

    proxy = 'http://%s:%s' % (target, os.environ['WRAP_PROXY_PORT'])
    proxies = {"http": proxy, }

    s.headers.update({'Proxy-Authorization': getAuthToken(target)})
    s.headers.update({'Authorization': getAuthToken(target)})

    r = s.get(url, proxies=proxies)
    if r.status_code != 200:
        raise ValueError('Spnego Proxy Auth Failed')

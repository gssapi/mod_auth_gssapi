#!/usr/bin/python
# Copyright (C) 2015 - mod_auth_gssapi contributors, see COPYING for license.

import os
import requests
import gssapi
from base64 import b64encode

def getAuthToken(target):
    name = gssapi.Name('HTTP@%s' % target,
                       gssapi.NameType.hostbased_service)
    ctx = gssapi.SecurityContext(name=name)
    token = ctx.step()
    
    return 'Negotiate %s' % b64encode(token)


if __name__ == '__main__':
    s = requests.Session()

    target = os.environ['NSS_WRAPPER_HOSTNAME']
    url = 'http://%s/spnego/' % target

    proxy = 'http://%s:%s' % (target, os.environ['WRAP_PROXY_PORT'])
    proxies = { "http" : proxy, }

    s.headers.update({'Proxy-Authorization': getAuthToken(target)})
    s.headers.update({'Authorization': getAuthToken(target)})

    r = s.get(url, proxies=proxies)
    if r.status_code != 200:
        raise ValueError('Spnego Proxy Auth Failed')

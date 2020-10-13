#!/usr/bin/env python3
# Works with both python2 and python3; please preserve this property

# Copyright (C) 2016 mod_auth_gssapi contributors - See COPYING for (C) terms

# Simple script to generate GssapiSessionKey values

import base64
import os

bits = base64.b64encode(os.urandom(32))
print("GssapiSessionKey key:" + bits.decode('utf-8'))

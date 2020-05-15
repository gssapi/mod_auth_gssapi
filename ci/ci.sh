#!/bin/bash -ex

if [ -f /etc/debian_version ]; then
    export DEBIAN_FRONTEND=noninteractive

    apt-get -q update

    apt-get -yq install $COMPILER pkg-config flake8 virtualenv \
            apache2-bin {apache2,libkrb5,libssl,gss-ntlmssp}-dev \
            python3{,-dev,-requests} lib{socket,nss}-wrapper \
            flex bison krb5-{kdc,admin-server,pkinit} curl libfaketime

    apt-get -yq install python3-requests-gssapi 2>/dev/null || true
elif [ -f /etc/fedora-release ]; then
    dnf -y install $COMPILER python3-{gssapi,requests{,-gssapi},flake8} \
        krb5-{server,workstation,pkinit} curl libfaketime \
        {httpd,krb5,openssl,gssntlmssp}-devel {socket,nss}_wrapper \
        autoconf automake libtool which bison make python3 \
        flex mod_session redhat-rpm-config /usr/bin/virtualenv
else
    echo "Distro not found!"
    false
fi

if [ x$FLAKE == xyes ]; then
    flake8
fi

CFLAGS="-Werror"
if [ x$COMPILER == xclang ]; then
    CFLAGS+=" -Wno-missing-field-initializers"
    CFLAGS+=" -Wno-missing-braces -Wno-cast-align"

    # So this is just a sad hack to get around:
    #     clang-7: error: unknown argument: '-fstack-clash-protection'
    # which doesn't seem to have a solution right now.
    cp=$(which clang)
    mv $cp $cp.real
    cat > $cp <<EOF
#!/usr/bin/env python3
import os
import sys
argv = [a for a in sys.argv if a != "-fstack-clash-protection" \
        and not a.startswith("-specs")]
argv[0] = "${cp}.real"
os.execve(argv[0], argv, {})
EOF
    chmod +x $cp
fi

virtualenv --system-site-packages -p $(which python3) .venv
source .venv/bin/activate
pip install requests{,-gssapi}

scratch=/tmp/build/mod_auth_gssapi-*/_build/sub/testsdir

autoreconf -fiv
./configure # overridden by below, but needs to generate Makefile
DCF="CFLAGS=\"$CFLAGS\" CC=$(which $COMPILER)"
make distcheck DISTCHECK_CONFIGURE_FLAGS="$DCF" ||
    (cat $scratch/tests.log $scratch/httpd/logs/error_log; exit -1)

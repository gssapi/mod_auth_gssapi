#!/bin/bash -ex

if [ -f /etc/debian_version ]; then
    PYTHON=python3
    export DEBIAN_FRONTEND=noninteractive

    apt-get update

    apt-get -y install $COMPILER pkg-config flake8 virtualenv \
            apache2-bin {apache2,libkrb5,libssl,gss-ntlmssp}-dev \
            $PYTHON{,-dev,-requests} lib{socket,nss}-wrapper \
            flex bison krb5-{kdc,admin-server,pkinit} curl

    apt-get -y install $PYTHON-requests-gssapi 2>/dev/null || true

    flake8
elif [ -f /etc/redhat-release ]; then
    DY=yum
    PYTHON=python2
    if [ -f /etc/fedora-release ]; then
        DY=dnf
        PYTHON=python3
    fi

    $DY -y install $COMPILER $PYTHON-{gssapi,requests} \
        krb5-{server,workstation,pkinit} curl \
        {httpd,krb5,openssl,gssntlmssp}-devel {socket,nss}_wrapper \
        autoconf automake libtool which bison make $PYTHON \
        flex mod_session redhat-rpm-config /usr/bin/virtualenv

    $DY -y install python-requests-gssapi 2>/dev/null || true
else
    echo "Distro not found!"
    false
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
#!/usr/bin/env python
import os
import sys
argv = [a for a in sys.argv if a != "-fstack-clash-protection" \
        and not a.startswith("-specs")]
argv[0] = "${cp}.real"
os.execve(argv[0], argv, {})
EOF
    chmod +x $cp
fi

virtualenv --system-site-packages -p $(which $PYTHON) .venv
source .venv/bin/activate
pip install requests{,-gssapi}

scratch=/tmp/build/mod_auth_gssapi-*/_build/sub/testsdir

autoreconf -fiv
./configure # overridden by below, but needs to generate Makefile
make distcheck DISTCHECK_CONFIGURE_FLAGS="CFLAGS=\"$CFLAGS\" CC=$(which $COMPILER)" || (cat $scratch/tests.log $scratch/httpd/logs/error_log; exit -1)

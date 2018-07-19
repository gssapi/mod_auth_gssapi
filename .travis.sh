#!/bin/bash -ex

CFLAGS="-Werror"
if [ x$COMPILER == xclang ]; then
    CFLAGS+=" -Wno-missing-field-initializers"
    CFLAGS+=" -Wno-missing-braces -Wno-cast-align"
fi

if [ -f /etc/debian_version ]; then
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get -y install $COMPILER pkg-config \
                   apache2-bin {apache2,libkrb5,libssl,gss-ntlmssp}-dev \
                   python-{dev,requests,gssapi} lib{socket,nss}-wrapper \
                   flex bison krb5-{kdc,admin-server,pkinit} \
                   flake8 virtualenv
    flake8

    # remove when python-requests-gssapi is packaged in Debian
    virtualenv --system-site-packages .venv
    source .venv/bin/activate
    pip install requests-gssapi
elif [ -f /etc/redhat-release ]; then
    DY=yum
    if [ -f /etc/fedora-release ]; then
        DY=dnf
    fi
    $DY -y install $COMPILER python-gssapi krb5-{server,workstation,pkinit} \
        {httpd,krb5,openssl,gssntlmssp}-devel {socket,nss}_wrapper \
        python-requests autoconf automake libtool which bison make \
        flex mod_session redhat-rpm-config python2-virtualenv

    # remove when we're using f28+
    virtualenv .venv
    source .venv/bin/activate
    pip install requests{,-gssapi}
    if [ x$COMPILER == xclang ]; then
        CFLAGS+=" -Wno-unused-command-line-argument"
    fi
else
    echo "Distro not found!"
    false
fi

autoreconf -fiv
./configure # overridden by below, but needs to generate Makefile
make distcheck DISTCHECK_CONFIGURE_FLAGS="CFLAGS=\"$CFLAGS\" CC=$(which $COMPILER)"

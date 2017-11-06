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
                   flex bison krb5-{kdc,admin-server} python-requests-kerberos
elif [ -f /etc/fedora-release ]; then
    # https://bugzilla.redhat.com/show_bug.cgi?id=1483553 means that this will
    # fail no matter what, but it will properly install the packages.
    dnf -y install $COMPILER python-gssapi krb5-{server,workstation} \
        {httpd,krb5,openssl,gssntlmssp}-devel {socket,nss}_wrapper \
        python-requests{,-kerberos} autoconf automake libtool which bison \
        flex mod_session redhat-rpm-config \
        || true

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

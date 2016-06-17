#!/bin/bash
# Relase-prep script

if [[ $# -eq 0 ]]; then
    echo "Version number is required"
    exit 1
fi
if [[ $# -gt 1 ]]; then
    echo "Only one argument (version) is allowed"
    exit 2
fi

RELEASE=$1
CUR_RELTAG=`git tag -l | tail -1`
NEW_RELTAG=v${RELEASE}

echo "Prepping for release ${RELEASE}"

cat <<EOF > version.m4
m4_define([VERSION_NUMBER], [${RELEASE}])
EOF

git commit version.m4 -s -m "Release ${RELEASE}"

git tag ${NEW_RELTAG}

autoreconf -f -i && ./configure && make DESTDIR=${PWD}/testinst && make dist
if [[ $? -ne 0 ]]; then
    echo "Release prep failed"
    exit 3
fi

sha512sum mod_auth_gssapi-$1.tar.gz > mod_auth_gssapi-$1.tar.gz.shas512sum.txt
git shortlog ${CUR_RELTAG}..${NEW_RELTAG} | sed 's/^\([a-Z]\)\(.*\)/* \1\2/' > shortlog.txt
echo "Release ready to be pushed"

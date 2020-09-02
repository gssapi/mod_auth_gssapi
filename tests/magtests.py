#!/usr/bin/env python
# Copyright (C) 2015 - mod_auth_gssapi contributors, see COPYING for license.

import argparse
import os
import os.path
import random
import shutil
import signal
import subprocess
import sys
import time
import traceback

# check that we can import requests (for use in test scripts)
import requests

import requests_gssapi
del requests
del requests_gssapi


def parse_args():
    parser = argparse.ArgumentParser(
        description='Mod Auth GSSAPI Tests Environment')
    parser.add_argument('--path', default='%s/scratchdir' % os.getcwd(),
                        help="Directory in which tests are run")
    parser.add_argument('--so-dir', default='%s/src/.libs' % os.getcwd(),
                        help="mod_auth_gssapi shared object dirpath")
    return vars(parser.parse_args())


WRAP_HOSTNAME = "kdc.mag.dev"
WRAP_ALIASNAME = "alias.mag.dev"
WRAP_FAILNAME = "fail.mag.dev"
WRAP_IPADDR = '127.0.0.9'
WRAP_HTTP_PORT = '80'
WRAP_PROXY_PORT = '8080'


def setup_wrappers(base):
    pkgcfg = subprocess.Popen(['pkg-config', '--exists', 'socket_wrapper'])
    pkgcfg.wait()
    if pkgcfg.returncode != 0:
        raise ValueError('Socket Wrappers not available')

    pkgcfg = subprocess.Popen(['pkg-config', '--exists', 'nss_wrapper'])
    pkgcfg.wait()
    if pkgcfg.returncode != 0:
        raise ValueError('Socket Wrappers not available')

    wrapdir = os.path.join(base, 'wrapdir')
    if not os.path.exists(wrapdir):
        os.makedirs(wrapdir)

    hosts_file = os.path.join(testdir, 'hosts')
    with open(hosts_file, 'w+') as f:
        f.write('%s %s\n' % (WRAP_IPADDR, WRAP_HOSTNAME))
        f.write('%s %s\n' % (WRAP_IPADDR, WRAP_ALIASNAME))
        f.write('%s %s\n' % (WRAP_IPADDR, WRAP_FAILNAME))

    passwd_file = os.path.join(testdir, 'passwd')
    with open(passwd_file, 'w+') as f:
        f.write('root:x:0:0:root:/root:/bin/sh')
        f.write('maguser:x:1:1:maguser:/maguser:/bin/sh')
        f.write('maguser2:x:2:2:maguser2:/maguser2:/bin/sh')
        f.write('maguser3:x:3:3:maguser3:/maguser3:/bin/sh')
        f.write('timeoutusr:x:4:4:timeoutusr:/timeoutusr:/bin/sh')

    wenv = {'LD_PRELOAD': 'libsocket_wrapper.so libnss_wrapper.so',
            'SOCKET_WRAPPER_DIR': wrapdir,
            'SOCKET_WRAPPER_DEFAULT_IFACE': '9',
            'WRAP_PROXY_PORT': WRAP_PROXY_PORT,
            'NSS_WRAPPER_HOSTNAME': WRAP_HOSTNAME,
            'NSS_WRAPPER_HOSTS': hosts_file,
            'NSS_WRAPPER_PASSWD': passwd_file}
    return wenv


def apply_venv(env):
    env['PATH'] = os.environ.get('PATH', '')
    env['VIRTUAL_ENV'] = os.environ.get('VIRTUAL_ENV', '')
    return env


TESTREALM = "MAG.DEV"
KDC_DBNAME = 'db.file'
KDC_STASH = 'stash.file'
KDC_PASSWORD = 'modauthgssapi'
KRB5_CONF_TEMPLATE = '''
[libdefaults]
  default_realm = {TESTREALM}
  dns_lookup_realm = false
  dns_lookup_kdc = false
  rdns = false
  ticket_lifetime = 24h
  forwardable = yes
  default_ccache_name = FILE://{TESTDIR}/ccaches/krb5_ccache_XXXXXX

[realms]
  {TESTREALM} = {{
    kdc = {WRAP_HOSTNAME}
    pkinit_anchors = FILE:{TESTDIR}/{PKINIT_CA}
  }}

[domain_realm]
  .mag.dev = {TESTREALM}
  mag.dev = {TESTREALM}

[dbmodules]
  {TESTREALM} = {{
    database_name = {KDCDIR}/{KDC_DBNAME}
  }}
'''
KDC_CONF_TEMPLATE = '''
[kdcdefaults]
 kdc_ports = 88
 kdc_tcp_ports = 88
 restrict_anonymous_to_tgt = true
 pkinit_identity = FILE:{TESTDIR}/{PKINIT_KDC_CERT},{TESTDIR}/{PKINIT_KEY}
 pkinit_anchors = FILE:{TESTDIR}/{PKINIT_CA}
 pkinit_indicator = na1
 pkinit_indicator = na2
 pkinit_indicator = na3

[realms]
 {TESTREALM} = {{
  master_key_type = aes256-cts
  max_life = 7d
  max_renewable_life = 14d
  acl_file = {KDCDIR}/kadm5.acl
  dict_file = /usr/share/dict/words
  default_principal_flags = +preauth
  admin_keytab = {TESTREALM}/kadm5.keytab
  key_stash_file = {KDCDIR}/{KDC_STASH}
 }}
[logging]
  kdc = FILE:{KDCLOG}
'''

PKINIT_CA = 'cacert.pem'
PKINIT_KEY = 'key.pem'
PKINIT_USER_REQ = 'user.csr'
PKINIT_USER_CERT = 'user.pem'
PKINIT_KDC_REQ = 'kdccert.csr'
PKINIT_KDC_CERT = 'kdccert.pem'

OPENSSLCNF_TEMPLATE = '''
[req]
prompt = no
distinguished_name = $ENV::O_SUBJECT

[ca]
CN = CA
C = US
OU = Insecure test CA do not use
O = {TESTREALM}

[kdc]
C = US
O = {TESTREALM}
CN = KDC

[user]
C = US
O = {TESTREALM}
CN = maguser3

[exts_ca]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer:always
keyUsage = nonRepudiation,digitalSignature,keyEncipherment,dataEncipherment,keyAgreement,keyCertSign,cRLSign
basicConstraints = critical,CA:TRUE

[components_kdc]
0.component=GeneralString:krbtgt
1.component=GeneralString:{TESTREALM}

[princ_kdc]
nametype=EXPLICIT:0,INTEGER:1
components=EXPLICIT:1,SEQUENCE:components_kdc

[krb5princ_kdc]
realm=EXPLICIT:0,GeneralString:{TESTREALM}
princ=EXPLICIT:1,SEQUENCE:princ_kdc

[exts_kdc]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer:always
keyUsage = nonRepudiation,digitalSignature,keyEncipherment,keyAgreement
basicConstraints = critical,CA:FALSE
subjectAltName = otherName:1.3.6.1.5.2.2;SEQUENCE:krb5princ_kdc
extendedKeyUsage = 1.3.6.1.5.2.3.5

[components_client]
component=GeneralString:maguser3

[princ_client]
nametype=EXPLICIT:0,INTEGER:1
components=EXPLICIT:1,SEQUENCE:components_client

[krb5princ_client]
realm=EXPLICIT:0,GeneralString:{TESTREALM}
princ=EXPLICIT:1,SEQUENCE:princ_client

[exts_client]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer:always
keyUsage = nonRepudiation,digitalSignature,keyEncipherment,keyAgreement
basicConstraints = critical,CA:FALSE
subjectAltName = otherName:1.3.6.1.5.2.2;SEQUENCE:krb5princ_client
extendedKeyUsage = 1.3.6.1.5.2.3.4
''' # noqa


def setup_test_certs(testdir, testenv, logfile):
    opensslcnf = os.path.join(testdir, 'openssl.cnf')
    pkinit_key = os.path.join(testdir, PKINIT_KEY)
    pkinit_ca = os.path.join(testdir, PKINIT_CA)
    pkinit_kdc_req = os.path.join(testdir, PKINIT_KDC_REQ)
    pkinit_user_req = os.path.join(testdir, PKINIT_USER_REQ)
    pkinit_kdc_cert = os.path.join(testdir, PKINIT_KDC_CERT)
    pkinit_user_cert = os.path.join(testdir, PKINIT_USER_CERT)

    text = OPENSSLCNF_TEMPLATE.format(TESTREALM=TESTREALM)
    with open(opensslcnf, 'w+') as f:
        f.write(text)

    cmd = subprocess.Popen(["openssl", "genrsa", "-out", pkinit_key,
                            "2048"], stdout=logfile,
                           stderr=logfile, env=testenv,
                           preexec_fn=os.setsid)
    cmd.wait()
    if cmd.returncode != 0:
        raise ValueError('Generating CA RSA key failed')

    testenv.update({'O_SUBJECT': 'ca'})
    cmd = subprocess.Popen(["openssl", "req", "-config", opensslcnf,
                            "-new", "-x509", "-extensions", "exts_ca",
                            "-set_serial", "1", "-days", "100",
                            "-key", pkinit_key, "-out", pkinit_ca],
                           stdout=logfile, stderr=logfile, env=testenv,
                           preexec_fn=os.setsid)
    cmd.wait()
    if cmd.returncode != 0:
        raise ValueError('Generating CA certificate failed')

    testenv.update({'O_SUBJECT': 'kdc'})
    cmd = subprocess.Popen(["openssl", "req", "-config", opensslcnf,
                            "-new", "-subj", "/CN=kdc",
                            "-key", pkinit_key, "-out", pkinit_kdc_req],
                           stdout=logfile, stderr=logfile, env=testenv,
                           preexec_fn=os.setsid)
    cmd.wait()
    if cmd.returncode != 0:
        raise ValueError('Generating KDC req failed')

    cmd = subprocess.Popen(["openssl", "x509", "-extfile", opensslcnf,
                            "-extensions", "exts_kdc", "-set_serial", "2",
                            "-days", "100", "-req", "-CA", pkinit_ca,
                            "-CAkey", pkinit_key, "-out", pkinit_kdc_cert,
                            "-in", pkinit_kdc_req],
                           stdout=logfile, stderr=logfile, env=testenv,
                           preexec_fn=os.setsid)
    cmd.wait()
    if cmd.returncode != 0:
        raise ValueError('Generating KDC certificate failed')

    testenv.update({'O_SUBJECT': 'user'})
    cmd = subprocess.Popen(["openssl", "req", "-config", opensslcnf,
                            "-new", "-subj", "/CN=user",
                            "-key", pkinit_key, "-out", pkinit_user_req],
                           stdout=logfile, stderr=logfile, env=testenv,
                           preexec_fn=os.setsid)
    cmd.wait()
    if cmd.returncode != 0:
        raise ValueError('Generating client req failed')

    cmd = subprocess.Popen(["openssl", "x509", "-extfile", opensslcnf,
                            "-extensions", "exts_client", "-set_serial", "3",
                            "-days", "100", "-req", "-CA", pkinit_ca,
                            "-CAkey", pkinit_key, "-out", pkinit_user_cert,
                            "-in", pkinit_user_req],
                           stdout=logfile, stderr=logfile, env=testenv,
                           preexec_fn=os.setsid)
    cmd.wait()
    if cmd.returncode != 0:
        raise ValueError('Generating client certificate failed')


def setup_kdc(testdir, wrapenv):
    # setup kerberos environment
    testlog = os.path.join(testdir, 'kerb.log')
    krb5conf = os.path.join(testdir, 'krb5.conf')
    kdcconf = os.path.join(testdir, 'kdc.conf')
    kdcdir = os.path.join(testdir, 'kdc')
    if os.path.exists(kdcdir):
        shutil.rmtree(kdcdir)
    os.makedirs(kdcdir)

    text = KRB5_CONF_TEMPLATE.format(TESTREALM=TESTREALM,
                                     TESTDIR=testdir,
                                     KDCDIR=kdcdir,
                                     KDC_DBNAME=KDC_DBNAME,
                                     WRAP_HOSTNAME=WRAP_HOSTNAME,
                                     PKINIT_CA=PKINIT_CA,
                                     PKINIT_USER_CERT=PKINIT_USER_CERT,
                                     PKINIT_KEY=PKINIT_KEY)
    with open(krb5conf, 'w+') as f:
        f.write(text)

    text = KDC_CONF_TEMPLATE.format(TESTREALM=TESTREALM,
                                    TESTDIR=testdir,
                                    KDCDIR=kdcdir,
                                    KDCLOG=testlog,
                                    KDC_STASH=KDC_STASH,
                                    PKINIT_CA=PKINIT_CA,
                                    PKINIT_KDC_CERT=PKINIT_KDC_CERT,
                                    PKINIT_KEY=PKINIT_KEY)
    with open(kdcconf, 'w+') as f:
        f.write(text)

    kdcenv = wrapenv.copy()
    kdcenv.update({
        'PATH': f'/sbin:/bin:/usr/sbin:/usr/bin:{wrapenv["PATH"]}',
        'KRB5_CONFIG': krb5conf,
        'KRB5_KDC_PROFILE': kdcconf,
        'KRB5_TRACE': os.path.join(testdir, 'krbtrace.log'),
    })

    logfile = open(testlog, 'a')
    ksetup = subprocess.Popen(["kdb5_util", "create", "-W", "-s",
                               "-r", TESTREALM, "-P", KDC_PASSWORD],
                              stdout=logfile, stderr=logfile,
                              env=kdcenv, preexec_fn=os.setsid)
    ksetup.wait()
    if ksetup.returncode != 0:
        raise ValueError('KDC Setup failed')

    setup_test_certs(testdir, kdcenv, logfile)

    kdcproc = subprocess.Popen(['krb5kdc', '-n'],
                               stdout=logfile, stderr=logfile,
                               env=kdcenv, preexec_fn=os.setsid)
    return kdcproc, kdcenv


def kadmin_local(cmd, env, logfile):
    ksetup = subprocess.Popen(["kadmin.local", "-q", cmd],
                              stdout=logfile, stderr=logfile,
                              env=env, preexec_fn=os.setsid)
    ksetup.wait()
    if ksetup.returncode != 0:
        raise ValueError('Kadmin local [%s] failed' % cmd)


USR_NAME = "maguser"
USR_PWD = "magpwd"
USR_NAME_2 = "maguser2"
USR_PWD_2 = "magpwd2"
USR_NAME_3 = "maguser3"
SVC_KTNAME = "httpd/http.keytab"
KEY_TYPE = "aes256-cts-hmac-sha1-96:normal"
USR_NAME_4 = "timeoutusr"


def setup_keys(tesdir, env):
    testlog = os.path.join(testdir, 'kerb.log')
    logfile = open(testlog, 'a')

    svc_name = "HTTP/%s" % WRAP_HOSTNAME
    cmd = "addprinc -randkey -e %s %s" % (KEY_TYPE, svc_name)
    kadmin_local(cmd, env, logfile)

    svc_keytab = os.path.join(testdir, SVC_KTNAME)
    cmd = "ktadd -k %s -e %s %s" % (svc_keytab, KEY_TYPE, svc_name)
    kadmin_local(cmd, env, logfile)

    cmd = "addprinc -pw %s -e %s %s" % (USR_PWD, KEY_TYPE, USR_NAME)
    kadmin_local(cmd, env, logfile)

    cmd = "addprinc -pw %s -e %s %s" % (USR_PWD_2, KEY_TYPE, USR_NAME_2)
    kadmin_local(cmd, env, logfile)

    cmd = "addprinc -pw %s -e %s %s" % (USR_PWD, KEY_TYPE, USR_NAME_4)
    kadmin_local(cmd, env, logfile)

    # alias for multinamed hosts testing
    alias_name = "HTTP/%s" % WRAP_ALIASNAME
    cmd = "addprinc -randkey -e %s %s" % (KEY_TYPE, alias_name)
    kadmin_local(cmd, env, logfile)
    cmd = "ktadd -k %s -e %s %s" % (svc_keytab, KEY_TYPE, alias_name)
    kadmin_local(cmd, env, logfile)

    cmd = "addprinc -nokey -e %s %s" % (KEY_TYPE, USR_NAME_3)
    kadmin_local(cmd, env, logfile)

    keys_env = env.copy()
    keys_env.update({
        "KRB5_KTNAME": svc_keytab,
    })
    return keys_env


def setup_http(testdir, so_dir, wrapenv):
    httpdir = os.path.join(testdir, 'httpd')
    if os.path.exists(httpdir):
        shutil.rmtree(httpdir)
    os.makedirs(httpdir)
    os.mkdir(os.path.join(httpdir, 'conf.d'))
    os.mkdir(os.path.join(httpdir, 'html'))
    os.mkdir(os.path.join(httpdir, 'logs'))
    httpdstdlog = os.path.join(testdir, 'httpd.stdlog')

    distro = "Fedora"
    moddir = "/etc/httpd/modules"
    if not os.path.exists(moddir):
        distro = "Debian"
        moddir = "/usr/lib/apache2/modules"
    if not os.path.exists(moddir):
        raise ValueError("Could not find Apache module directory!")
    os.symlink(moddir, os.path.join(httpdir, 'modules'))

    shutil.copy('%s/mod_auth_gssapi.so' % so_dir, httpdir)

    with open('tests/httpd.conf') as f:
        text = f.read().format(HTTPROOT=httpdir,
                               HTTPNAME=WRAP_HOSTNAME,
                               HTTPADDR=WRAP_IPADDR,
                               PROXYPORT=WRAP_PROXY_PORT,
                               HTTPPORT=WRAP_HTTP_PORT,
                               HOSTNAME=WRAP_HOSTNAME)
    config = os.path.join(httpdir, 'httpd.conf')
    with open(config, 'w+') as f:
        f.write(text)

    shutil.copy('tests/401.html', os.path.join(httpdir, 'html'))

    httpenv = wrapenv.copy()
    httpenv.update({
        'PATH': f'/sbin:/bin:/usr/sbin:/usr/bin:{wrapenv["PATH"]}',
        'MALLOC_CHECK_': '3',
        'MALLOC_PERTURB_': str(random.randint(0, 32767) % 255 + 1),
    })

    httpd = "httpd" if distro == "Fedora" else "apache2"
    log = open(httpdstdlog, 'a')
    httpproc = subprocess.Popen([httpd, '-DFOREGROUND', '-f', config],
                                stdout=log, stderr=log,
                                env=httpenv, preexec_fn=os.setsid)
    return httpproc


def kinit_user(testdir, kdcenv):
    testlog = os.path.join(testdir, 'kinit.log')
    ccache = os.path.join(testdir, 'k5ccache')
    testenv = kdcenv.copy()
    testenv.update({
        'KRB5CCNAME': ccache,
    })

    with (open(testlog, 'a')) as logfile:
        kinit = subprocess.Popen(["kinit", USR_NAME],
                                 stdin=subprocess.PIPE,
                                 stdout=logfile, stderr=logfile,
                                 env=testenv, preexec_fn=os.setsid)
        kinit.communicate(('%s\n' % USR_PWD).encode("utf8"))
        kinit.wait()
        if kinit.returncode != 0:
            raise ValueError('kinit failed')

    return testenv


def kinit_certuser(testdir, kdcenv):
    testlog = os.path.join(testdir, 'kinit.log')
    ccache = os.path.join(testdir, 'k5ccache2')
    pkinit_user_cert = os.path.join(testdir, PKINIT_USER_CERT)
    pkinit_key = os.path.join(testdir, PKINIT_KEY)
    ident = "X509_user_identity=FILE:" + pkinit_user_cert + "," + pkinit_key
    testenv = kdcenv.copy()
    testenv.update({
        'KRB5CCNAME': ccache,
    })
    with (open(testlog, 'a')) as logfile:
        logfile.write('PKINIT for maguser3\n')
        kinit = subprocess.Popen(["kinit", USR_NAME_3, "-X", ident],
                                 stdin=subprocess.PIPE,
                                 stdout=logfile, stderr=logfile,
                                 env=testenv, preexec_fn=os.setsid)
        kinit.wait()
        if kinit.returncode != 0:
            raise ValueError('kinit failed')
    return testenv


def test_spnego_auth(testdir, testenv, logfile):
    spnegodir = os.path.join(testdir, 'httpd', 'html', 'spnego')
    os.mkdir(spnegodir)
    shutil.copy('tests/index.html', spnegodir)
    error_count = 0

    spnego = subprocess.Popen(["tests/t_spnego.py"],
                              stdout=logfile, stderr=logfile,
                              env=testenv, preexec_fn=os.setsid)
    spnego.wait()
    if spnego.returncode != 0:
        sys.stderr.write('SPNEGO: FAILED\n')
        error_count += 1
    else:
        sys.stderr.write('SPNEGO: SUCCESS\n')

    spnego = subprocess.Popen(["tests/t_spnego_proxy.py"],
                              stdout=logfile, stderr=logfile,
                              env=testenv, preexec_fn=os.setsid)
    spnego.wait()
    if spnego.returncode != 0:
        sys.stderr.write('SPNEGO Proxy Auth: FAILED\n')
        error_count += 1
    else:
        sys.stderr.write('SPNEGO Proxy Auth: SUCCESS\n')

    spnego = subprocess.Popen(["tests/t_spnego_no_auth.py"],
                              stdout=logfile, stderr=logfile,
                              env=testenv, preexec_fn=os.setsid)
    spnego.wait()
    if spnego.returncode != 0:
        sys.stderr.write('SPNEGO No Auth: FAILED\n')
        error_count += 1
    else:
        sys.stderr.write('SPNEGO No Auth: SUCCESS\n')

    return error_count


def test_required_name_attr(testdir, testenv, logfile):
    for i in range(1, 5):
        required_name_attr_dir = os.path.join(testdir, 'httpd', 'html',
                                              'required_name_attr'+str(i))
        os.mkdir(required_name_attr_dir)
        shutil.copy('tests/index.html', required_name_attr_dir)

    tattr = subprocess.Popen(["tests/t_required_name_attr.py"],
                             stdout=logfile, stderr=logfile, env=testenv,
                             preexec_fn=os.setsid)
    tattr.wait()
    if tattr.returncode != 0:
        sys.stderr.write('Required Name Attr: FAILED\n')
        return 1
    sys.stderr.write('Required Name Attr: SUCCESS\n')
    return 0


def test_spnego_rewrite(testdir, testenv, logfile):
    spnego_rewrite_dir = os.path.join(testdir, 'httpd', 'html',
                                      'spnego_rewrite')
    os.mkdir(spnego_rewrite_dir)
    shutil.copy('tests/index.html', spnego_rewrite_dir)

    spnego = subprocess.Popen(["tests/t_spnego_rewrite.py"],
                              stdout=logfile, stderr=logfile,
                              env=testenv, preexec_fn=os.setsid)
    spnego.wait()
    if spnego.returncode != 0:
        sys.stderr.write('SPNEGO Rewrite: FAILED\n')
        return 1
    sys.stderr.write('SPNEGO Rewrite: SUCCESS\n')
    return 0


def test_spnego_negotiate_once(testdir, testenv, logfile):
    spnego_negotiate_once_dir = os.path.join(testdir, 'httpd', 'html',
                                             'spnego_negotiate_once')
    os.mkdir(spnego_negotiate_once_dir)
    shutil.copy('tests/index.html', spnego_negotiate_once_dir)

    spnego = subprocess.Popen(["tests/t_spnego_negotiate_once.py"],
                              stdout=logfile, stderr=logfile,
                              env=testenv, preexec_fn=os.setsid)
    spnego.wait()
    if spnego.returncode != 0:
        sys.stderr.write('SPNEGO Negotiate Once: FAILED\n')
        return 1
    sys.stderr.write('SPNEGO Negotiate Once: SUCCESS\n')
    return 0


def test_basic_auth_krb5(testdir, testenv, logfile):
    basicdir = os.path.join(testdir, 'httpd', 'html', 'basic_auth_krb5')
    os.mkdir(basicdir)
    shutil.copy('tests/index.html', basicdir)
    error_count = 0

    basick5 = subprocess.Popen(["tests/t_basic_k5.py"],
                               stdout=logfile, stderr=logfile,
                               env=testenv, preexec_fn=os.setsid)
    basick5.wait()
    if basick5.returncode != 0:
        sys.stderr.write('BASIC-AUTH: FAILED\n')
        error_count += 1
    else:
        sys.stderr.write('BASIC-AUTH: SUCCESS\n')

    basick5 = subprocess.Popen(["tests/t_basic_k5_two_users.py"],
                               stdout=logfile, stderr=logfile,
                               env=testenv, preexec_fn=os.setsid)
    basick5.wait()
    if basick5.returncode != 0:
        sys.stderr.write('BASIC-AUTH Two Users: FAILED\n')
        error_count += 1
    else:
        sys.stderr.write('BASIC-AUTH Two Users: SUCCESS\n')

    basick5 = subprocess.Popen(["tests/t_basic_k5_fail_second.py"],
                               stdout=logfile, stderr=logfile,
                               env=testenv, preexec_fn=os.setsid)
    basick5.wait()
    if basick5.returncode != 0:
        sys.stderr.write('BASIC Fail Second User: FAILED\n')
        error_count += 1
    else:
        sys.stderr.write('BASIC Fail Second User: SUCCESS\n')

    basick5 = subprocess.Popen(["tests/t_basic_proxy.py"],
                               stdout=logfile, stderr=logfile,
                               env=testenv, preexec_fn=os.setsid)
    basick5.wait()
    if basick5.returncode != 0:
        sys.stderr.write('BASIC Proxy Auth: FAILED\n')
        error_count += 1
    else:
        sys.stderr.write('BASIC Proxy Auth: SUCCESS\n')

    return error_count


def test_basic_auth_timeout(testdir, testenv, logfile):
    httpdir = os.path.join(testdir, 'httpd')
    timeoutdir = os.path.join(httpdir, 'html', 'basic_auth_timeout')
    os.mkdir(timeoutdir)
    authdir = os.path.join(timeoutdir, 'auth')
    os.mkdir(authdir)
    sessdir = os.path.join(timeoutdir, 'session')
    os.mkdir(sessdir)
    shutil.copy('tests/index.html', os.path.join(authdir))
    shutil.copy('tests/index.html', os.path.join(sessdir))

    basictout = subprocess.Popen(["tests/t_basic_timeout.py"],
                                 stdout=logfile, stderr=logfile,
                                 env=testenv, preexec_fn=os.setsid)
    basictout.wait()
    if basictout.returncode != 0:
        sys.stderr.write('BASIC Timeout Behavior: FAILED\n')
        return 1
    else:
        sys.stderr.write('BASIC Timeout Behavior: SUCCESS\n')

    return 0


def test_bad_acceptor_name(testdir, testenv, logfile):
    bandir = os.path.join(testdir, 'httpd', 'html', 'bad_acceptor_name')
    os.mkdir(bandir)
    shutil.copy('tests/index.html', bandir)

    ban = subprocess.Popen(["tests/t_bad_acceptor_name.py"],
                           stdout=logfile, stderr=logfile,
                           env=testenv, preexec_fn=os.setsid)
    ban.wait()
    if ban.returncode != 0:
        sys.stderr.write('BAD ACCEPTOR: SUCCESS\n')
        return 0
    sys.stderr.write('BAD ACCEPTOR: FAILED\n')
    return 1


def test_no_negotiate(testdir, testenv, logfile):
    nonego_dir = os.path.join(testdir, 'httpd', 'html', 'nonego')
    os.mkdir(nonego_dir)
    shutil.copy('tests/index.html', nonego_dir)

    spnego = subprocess.Popen(["tests/t_nonego.py"],
                              stdout=logfile, stderr=logfile,
                              env=testenv, preexec_fn=os.setsid)
    spnego.wait()
    if spnego.returncode != 0:
        sys.stderr.write('NO Negotiate: FAILED\n')
        return 1
    sys.stderr.write('NO Negotiate: SUCCESS\n')
    return 0


def test_hostname_acceptor(testdir, testenv, logfile):
    hdir = os.path.join(testdir, 'httpd', 'html', 'hostname_acceptor')
    os.mkdir(hdir)
    shutil.copy('tests/index.html', hdir)

    failed = False
    for (name, fail) in [(WRAP_HOSTNAME, False),
                         (WRAP_ALIASNAME, False),
                         (WRAP_FAILNAME, True)]:
        res = subprocess.Popen(["tests/t_hostname_acceptor.py", name],
                               stdout=logfile, stderr=logfile,
                               env=testenv, preexec_fn=os.setsid)
        res.wait()
        if fail:
            if res.returncode == 0:
                failed = True
        else:
            if res.returncode != 0:
                failed = True
        if failed:
            break

    if failed:
        sys.stderr.write('HOSTNAME ACCEPTOR: FAILED\n')
        return 1
    sys.stderr.write('HOSTNAME ACCEPTOR: SUCCESS\n')
    return 0


def test_gss_localname(testdir, testenv, logfile):
    hdir = os.path.join(testdir, 'httpd', 'html', 'gss_localname')
    os.mkdir(hdir)
    shutil.copy('tests/localname.html', os.path.join(hdir, 'index.html'))
    error_count = 0

    # Make sure spnego is explicitly tested
    spnego = subprocess.Popen(["tests/t_localname.py", "SPNEGO"],
                              stdout=logfile, stderr=logfile,
                              env=testenv, preexec_fn=os.setsid)
    spnego.wait()
    if spnego.returncode != 0:
        sys.stderr.write('LOCALNAME(SPNEGO): FAILED\n')
        error_count += 1
    else:
        sys.stderr.write('LOCALNAME(SPNEGO): SUCCESS\n')

    # and bare krb5 (GS2-KRB5 is the name used by SASL for it)
    krb5 = subprocess.Popen(["tests/t_localname.py", "GS2-KRB5"],
                            stdout=logfile, stderr=logfile,
                            env=testenv, preexec_fn=os.setsid)
    krb5.wait()
    if krb5.returncode != 0:
        if krb5.returncode == 42:
            sys.stderr.write('LOCALNAME(KRB5): SKIPPED\n')
        else:
            sys.stderr.write('LOCALNAME(KRB5): FAILED\n')
            error_count += 1
    else:
        sys.stderr.write('LOCALNAME(KRB5): SUCCESS\n')

    return error_count


def faketime_setup(testenv):
    # Wanted: an architecture- and distro-agnostic way to do this.
    # libfaketime is installed in a place where ld.so won't pick it up by
    # default, so...
    paths = ['/usr/lib64/faketime/libfaketime.so.1',
             '/usr/lib/x86_64-linux-gnu/faketime/libfaketime.so.1']
    libfaketime = None
    for p in paths:
        if os.path.isfile(p):
            libfaketime = p
    if not libfaketime:
        raise NotImplementedError

    # spedup x100
    fakeenv = testenv.copy()
    fakeenv.update({
        'FAKETIME': '+0 x100',
        'LD_PRELOAD': ' '.join((testenv['LD_PRELOAD'], libfaketime)),
    })
    return fakeenv


def http_restart(testdir, so_dir, testenv):
    httpenv = testenv.copy()
    httpenv.update({
        'PATH': f'/sbin:/bin:/usr/sbin:/usr/bin:{testenv["PATH"]}',
        'MALLOC_CHECK_': '3',
        'MALLOC_PERTURB_': str(random.randint(0, 32767) % 255 + 1),
    })

    httpd = "httpd" if os.path.exists("/etc/httpd/modules") else "apache2"
    config = os.path.join(testdir, 'httpd', 'httpd.conf')
    log = open(os.path.join(testdir, 'httpd.stdlog'), 'a')
    httpproc = subprocess.Popen([httpd, '-DFOREGROUND', '-f', config],
                                stdout=log, stderr=log,
                                env=httpenv, preexec_fn=os.setsid)
    return httpproc


def test_mech_name(testdir, testenv, logfile):
    basicdir = os.path.join(testdir, 'httpd', 'html', 'mech_name')
    os.mkdir(basicdir)
    shutil.copy('tests/mech.html', basicdir)

    mname = subprocess.Popen(["tests/t_mech_name.py"],
                             stdout=logfile, stderr=logfile,
                             env=testenv, preexec_fn=os.setsid)
    mname.wait()
    if mname.returncode != 0:
        sys.stderr.write('MECH-NAME: FAILED\n')
        return 1
    sys.stderr.write('MECH-NAME: SUCCESS\n')
    return 0


def test_file_check(testdir, testenv, logfile):
    basicdir = os.path.join(testdir, 'httpd', 'html', 'keytab_file_check')
    os.mkdir(basicdir)
    shutil.copy('tests/index.html', basicdir)

    filec = subprocess.Popen(["tests/t_file_check.py"],
                             stdout=logfile, stderr=logfile,
                             env=testenv, preexec_fn=os.setsid)
    filec.wait()
    if filec.returncode == 0:
        sys.stderr.write('FILE-CHECK: FAILED\n')
        return 1
    sys.stderr.write('FILE-CHECK: SUCCESS\n')
    return 0


if __name__ == '__main__':
    args = parse_args()

    testdir = args['path']
    so_dir = args['so_dir']
    if os.path.exists(testdir):
        shutil.rmtree(testdir)
    os.makedirs(testdir)

    processes = dict()
    logfile = open(os.path.join(testdir, 'tests.log'), 'w')
    # '-1' indicates setup phase
    errs = -1

    try:
        # prepare environment for tests
        wrapenv = apply_venv(setup_wrappers(testdir))

        kdcproc, kdcenv = setup_kdc(testdir, wrapenv)
        processes['KDC(%d)' % kdcproc.pid] = kdcproc

        httpproc = setup_http(testdir, so_dir, kdcenv)
        processes['HTTPD(%d)' % httpproc.pid] = httpproc

        keysenv = setup_keys(testdir, kdcenv)
        testenv = kinit_user(testdir, kdcenv)

        testenv['DELEGCCACHE'] = os.path.join(testdir, 'httpd',
                                              USR_NAME + '@' + TESTREALM)
        # making testing
        errs = 0

        errs += test_spnego_auth(testdir, testenv, logfile)

        testenv['MAG_GSS_NAME'] = USR_NAME + '@' + TESTREALM
        errs += test_spnego_rewrite(testdir, testenv, logfile)

        errs += test_spnego_negotiate_once(testdir, testenv, logfile)

        errs += test_hostname_acceptor(testdir, testenv, logfile)

        errs += test_bad_acceptor_name(testdir, testenv, logfile)

        testenv['MAG_REMOTE_USER'] = USR_NAME
        errs += test_gss_localname(testdir, testenv, logfile)

        rpm_path = "/usr/lib64/krb5/plugins/preauth/pkinit.so"
        deb_path = "/usr/lib/x86_64-linux-gnu/krb5/plugins/preauth/pkinit.so"
        if os.path.exists(rpm_path) or os.path.exists(deb_path):
            testenv = kinit_certuser(testdir, testenv)
            errs += test_required_name_attr(testdir, testenv, logfile)
        else:
            sys.stderr.write("krb5 PKINIT module not found, skipping name "
                             "attribute tests\n")

        testenv = kdcenv.copy()
        testenv.update({
            'MAG_USER_NAME': USR_NAME,
            'MAG_USER_PASSWORD': USR_PWD,
            'MAG_USER_NAME_2': USR_NAME_2,
            'MAG_USER_PASSWORD_2': USR_PWD_2,
        })

        errs += test_basic_auth_krb5(testdir, testenv, logfile)

        errs += test_no_negotiate(testdir, testenv, logfile)

        errs += test_mech_name(testdir, testenv, logfile)

        errs += test_file_check(testdir, testenv, logfile)

        # After this point we need to speed up httpd to test creds timeout
        try:
            fakeenv = faketime_setup(kdcenv)
            timeenv = fakeenv.copy()
            timeenv.update({
                'TIMEOUT_USER': USR_NAME_4,
                'MAG_USER_PASSWORD': USR_PWD,
            })
            curporc = httpproc
            pid = processes['HTTPD(%d)' % httpproc.pid].pid
            os.killpg(pid, signal.SIGTERM)
            time.sleep(1)
            del processes['HTTPD(%d)' % httpproc.pid]
            httpproc = http_restart(testdir, so_dir, timeenv)
            processes['HTTPD(%d)' % httpproc.pid] = httpproc

            errs += test_basic_auth_timeout(testdir, timeenv, logfile)
        except NotImplementedError:
            sys.stderr.write('BASIC Timeout Behavior: SKIPPED\n')

    except Exception:
        traceback.print_exc()
    finally:
        for name in processes:
            logfile.write("Killing %s\n" % name)
            os.killpg(processes[name].pid, signal.SIGTERM)
        exit(errs)

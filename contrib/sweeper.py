#!/usr/bin/env python3
# Works with both python2 and python3; please preserve this property

# Copyright (C) 2016 mod_auth_gssapi contributors - See COPYING for (C) terms

# If one uses both sessions and unique ccache names, then the filesystem will
# become littered with ccache files unless the accessed application cleans
# them up itself.  This script will minimize ccache file proliferation by
# removing any ccaches that have expired from the filesystem, and serves as an
# example of how this cleaning can be performed.

# gssproxy note: in order to sweep credentials, the sweeper needs to connect
# to gssproxy as if it were mod_auth_gssapi.  In the configuration provided
# with mod_auth_gssapi (80-httpd.conf), this just consists of matching the
# gssproxy uid - so run it as the appropriate user (i.e., apache).  Custom
# configurations require careful consideration of how to match the sweeper
# connection to the correct service in gssproxy; this script is just an
# example.  This script will not attempt to contact gssproxy unless -g is
# passed.

import argparse
import os
import stat
import time

# try importing this first to provide a more useful error message
import gssapi
del gssapi
try:
    from gssapi.raw import acquire_cred_from
except ImportError:
    print("Your GSSAPI does not provide cred store extension; exiting!")
    exit(1)


# process file as a ccache and indicate whether it is expired
def should_delete(fname, t):
    try:
        # skip directories and other non-files
        st = os.stat(fname)
        if not stat.S_ISREG(st.st_mode):
            return False

        # ignore files that are newer than 30 minutes
        if t - st.st_mtime < 30 * 60:
            return False

        creds = acquire_cred_from({b"ccache": fname.encode("UTF-8")})
    except FileNotFoundError:
        # someone else did the work for us
        return False
    except Exception as e:
        print("Not deleting %s due to error %s" % (fname, e))
        return False

    return creds.lifetime == 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Sweep expired ccaches")
    parser.add_argument("-g", dest="gssproxy", action="store_true",
                        help="is gssproxy in use (default: no)")
    parser.add_argument("dirs", nargs='+')
    args = parser.parse_args()

    if args.gssproxy:
        os.environ["GSS_USE_PROXY"] = "yes"
        os.environ["GSSPROXY_BEHAVIOR"] = "REMOTE_FIRST"

    print("System looks okay; running sweeper...")

    t = time.time()

    for basedir in args.dirs:
        os.chdir(basedir)
        print("Sweeping %s" % basedir)

        for fname in os.listdir(basedir):
            if should_delete(fname, t):
                os.unlink(fname)

    print("Sweeper finished successfully!")
    exit(0)

#!/usr/bin/env python
# Works with both python2 and python3; please preserve this property

# Copyright (C) 2016 mod_auth_gssapi contributors - See COPYING for (C) terms

# If one uses both sessions and unique ccache names, then the filesystem will
# become littered with ccache files unless the accessed application cleans
# them up itself.  This script will minimize ccache file proliferation by
# removing any ccaches that have expired from the filesystem, and serves as an
# example of how this cleaning can be performed.

import gssapi
import os
import re
import stat
import sys
import time

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
    dirs = sys.argv[1:]
    if len(dirs) < 1:
        print("Usage: %s dir1 [dir2...]" % sys.argv[0])
        exit(1)

    print("System looks okay; running sweeper...")

    t = time.time()

    for basedir in dirs:
        os.chdir(basedir)
        print("Sweeping %s" % basedir)

        for fname in os.listdir(basedir):
            if should_delete(fname, t):
                os.unlink(fname)

    print("Sweeper finished successfully!")
    exit(0)

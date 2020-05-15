#!/bin/bash -ex

COMPILER=${COMPILER:-gcc}
FLAKE=${FLAKE:-no}

docker run \
       -v $(pwd):/tmp/build \
       -w /tmp/build \
       -e COMPILER=$COMPILER \
       -e FLAKE=$FLAKE \
       $DISTRO /bin/bash -ex ./ci/ci.sh

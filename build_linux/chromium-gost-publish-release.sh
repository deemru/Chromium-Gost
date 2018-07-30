#!/bin/sh

cd $(dirname $0)
. ./chromium-gost-env.sh
export PATH=$DEPOT_TOOLS_PATH:$PATH

#github-release release --user deemru --repo chromium-gost --tag $CHROMIUM_TAG --draft
github-release upload --user deemru --repo chromium-gost --tag $CHROMIUM_TAG --name chromium-gost-${CHROMIUM_TAG}-linux-amd64.deb --file chromium-gost-${CHROMIUM_TAG}-linux-amd64.deb
github-release upload --user deemru --repo chromium-gost --tag $CHROMIUM_TAG --name chromium-gost-${CHROMIUM_TAG}-linux-amd64.rpm --file chromium-gost-${CHROMIUM_TAG}-linux-amd64.rpm

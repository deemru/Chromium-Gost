#!/bin/sh

cd $(dirname $0)
. ./chromium-gost-env.sh
export PATH=$DEPOT_TOOLS_PATH:$PATH

#github-release release --user deemru --repo chromium-gost --tag $CHROMIUM_TAG --draft
github-release upload --user deemru --repo chromium-gost --tag $CHROMIUM_TAG --name chromium-gost-$CHROMIUM_TAG-x64-beta.deb --file chromium-gost-$CHROMIUM_TAG-x64-beta.deb
github-release upload --user deemru --repo chromium-gost --tag $CHROMIUM_TAG --name chromium-gost-$CHROMIUM_TAG-x64-beta.rpm --file chromium-gost-$CHROMIUM_TAG-x64-beta.rpm

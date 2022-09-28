#!/bin/sh

cd $(dirname $0)
. ./chromium-gost-env.sh

cd $CHROMIUM_PATH/out/RELEASE
#github-release release --user deemru --repo chromium-gost --tag $CHROMIUM_TAG --draft
github-release upload --user deemru --repo chromium-gost --tag $CHROMIUM_TAG --name chromium-gost-$CHROMIUM_TAG-macos-amd64.tar.bz2 --file chromium-gost-$CHROMIUM_TAG-macos-amd64.signed.tar.bz2

#!/bin/sh

cd $(dirname $0)
. ./chromium-gost-env.sh

#github-release release --user deemru --repo chromium-gost --tag $CHROMIUM_TAG --draft
github-release upload --user deemru --repo chromium-gost --tag $CHROMIUM_TAG --name chromium-gost-${CHROMIUM_TAG}-linux-arm64.deb --file chromium-gost-${CHROMIUM_TAG}-linux-arm64.deb
github-release upload --user deemru --repo chromium-gost --tag $CHROMIUM_TAG --name chromium-gost-${CHROMIUM_TAG}-linux-arm64.rpm --file chromium-gost-${CHROMIUM_TAG}-linux-arm64.rpm

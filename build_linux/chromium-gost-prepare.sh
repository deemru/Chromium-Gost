#!/bin/sh

cd $(dirname $0)
. ./chromium-gost-env.sh
export PATH=$DEPOT_TOOLS_PATH:$PATH

cd $BORINGSSL_PATH || exit
git checkout -f master
git reset --hard

cd $CHROMIUM_PATH || exit
git fetch --tags
git checkout -b GOSTSSL-$CHROMIUM_TAG tags/$CHROMIUM_TAG
git checkout -f GOSTSSL-$CHROMIUM_TAG
gclient sync --with_branch_heads
git am --3way --ignore-space-change < $CHROMIUM_GOST_REPO/patch/chromium.patch || exit
cp -f $CHROMIUM_GOST_REPO/extra/exit_0.sh chrome/installer/linux/common/repo.cron
cp -f $CHROMIUM_GOST_REPO/extra/exit_0.sh chrome/installer/linux/common/rpmrepo.cron

cp -f $CHROMIUM_GOST_REPO/extra/product_logo/*.png chrome/app/theme/chromium/
cp -f $CHROMIUM_GOST_REPO/extra/product_logo/product_logo_16.png chrome/app/theme/default_100_percent/chromium/product_logo_16.png
cp -f $CHROMIUM_GOST_REPO/extra/product_logo/product_logo_32.png chrome/app/theme/default_100_percent/chromium/product_logo_32.png
cp -f $CHROMIUM_GOST_REPO/extra/product_logo/product_logo_32.png chrome/app/theme/default_200_percent/chromium/product_logo_16.png
cp -f $CHROMIUM_GOST_REPO/extra/product_logo/product_logo_64.png chrome/app/theme/default_200_percent/chromium/product_logo_32.png
cp -f $CHROMIUM_GOST_REPO/extra/product_logo/product_logo_32.xpm chrome/app/theme/chromium/linux/product_logo_32.xpm

cd $BORINGSSL_PATH
git checkout -b GOSTSSL-$CHROMIUM_TAG
git checkout -f GOSTSSL-$CHROMIUM_TAG
git am --3way --ignore-space-change < $CHROMIUM_GOST_REPO/patch/boringssl.patch || exit

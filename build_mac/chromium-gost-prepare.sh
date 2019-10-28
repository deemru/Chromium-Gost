#!/bin/sh

cd $(dirname $0)
git submodule init
git submodule update
. ./chromium-gost-env.sh
export PATH=$DEPOT_TOOLS_PATH:$PATH
export GOST_BRANCH=GOSTSSL-$CHROMIUM_TAG

cd $CHROMIUM_PATH/.git || exit
cd $BORINGSSL_PATH/.git || exit

cd $BORINGSSL_PATH
git reset HEAD~ --hard

cd $CHROMIUM_PATH
git reset HEAD~ --hard
git fetch --tags
git checkout -b $GOST_BRANCH tags/$CHROMIUM_TAG
git checkout -f $GOST_BRANCH
gclient sync --with_branch_heads -D
git am --3way --ignore-space-change < $CHROMIUM_GOST_REPO/patch/chromium.patch || exit
cp -f $CHROMIUM_GOST_REPO/extra/exit_0.sh chrome/installer/linux/common/repo.cron
cp -f $CHROMIUM_GOST_REPO/extra/exit_0.sh chrome/installer/linux/common/rpmrepo.cron

cp -f $CHROMIUM_GOST_REPO/extra/app.icns chrome/app/theme/chromium/mac/app.icns
cp -f $CHROMIUM_GOST_REPO/extra/product_logo/*.png chrome/app/theme/chromium/
cp -f $CHROMIUM_GOST_REPO/extra/product_logo/product_logo_16.png chrome/app/theme/default_100_percent/chromium/product_logo_16.png
cp -f $CHROMIUM_GOST_REPO/extra/product_logo/product_logo_32.png chrome/app/theme/default_100_percent/chromium/product_logo_32.png
cp -f $CHROMIUM_GOST_REPO/extra/product_logo/product_logo_32.png chrome/app/theme/default_200_percent/chromium/product_logo_16.png
cp -f $CHROMIUM_GOST_REPO/extra/product_logo/product_logo_64.png chrome/app/theme/default_200_percent/chromium/product_logo_32.png
cp -f $CHROMIUM_GOST_REPO/extra/product_logo/product_logo_32.xpm chrome/app/theme/chromium/linux/product_logo_32.xpm

cp -f $CHROMIUM_GOST_REPO/src/gostssl.cpp third_party/boringssl/gostssl.cpp
cp -f $CHROMIUM_GOST_REPO/src/msspi/src/msspi.cpp third_party/boringssl/msspi.cpp
cp -f $CHROMIUM_GOST_REPO/src/msspi/src/msspi.h third_party/boringssl/msspi.h

cp -f $CHROMIUM_GOST_REPO/src/msspi/third_party/cprocsp/include/CSP_SChannel.h third_party/boringssl/src/include/CSP_SChannel.h
cp -f $CHROMIUM_GOST_REPO/src/msspi/third_party/cprocsp/include/CSP_Sspi.h third_party/boringssl/src/include/CSP_Sspi.h
cp -f $CHROMIUM_GOST_REPO/src/msspi/third_party/cprocsp/include/CSP_WinBase.h third_party/boringssl/src/include/CSP_WinBase.h
cp -f $CHROMIUM_GOST_REPO/src/msspi/third_party/cprocsp/include/CSP_WinCrypt.h third_party/boringssl/src/include/CSP_WinCrypt.h
cp -f $CHROMIUM_GOST_REPO/src/msspi/third_party/cprocsp/include/CSP_WinDef.h third_party/boringssl/src/include/CSP_WinDef.h
cp -f $CHROMIUM_GOST_REPO/src/msspi/third_party/cprocsp/include/CSP_WinError.h third_party/boringssl/src/include/CSP_WinError.h
cp -f $CHROMIUM_GOST_REPO/src/msspi/third_party/cprocsp/include/WinCryptEx.h third_party/boringssl/src/include/WinCryptEx.h

cd $BORINGSSL_PATH
git checkout -b $GOST_BRANCH
git checkout -f $GOST_BRANCH
git am --3way --ignore-space-change < $CHROMIUM_GOST_REPO/patch/boringssl.patch || exit

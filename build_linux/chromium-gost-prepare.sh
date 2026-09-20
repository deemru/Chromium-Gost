#!/bin/sh

cd $(dirname $0)
git submodule update --init --recursive --depth 1
. ./chromium-gost-env.sh

export GOST_BRANCH=GOSTSSL-$CHROMIUM_TAG

cd $CHROMIUM_PATH/.git || exit
cd $BORINGSSL_PATH/.git || exit
cd $SEARCH_ENGINES_PATH/.git || exit

cd $BORINGSSL_PATH
git rebase --abort 2>/dev/null
git checkout --detach HEAD
git reset HEAD --hard && git clean -fd

cd $SEARCH_ENGINES_PATH
git rebase --abort 2>/dev/null
git checkout --detach HEAD
git reset HEAD --hard && git clean -fd

cd $CHROMIUM_PATH
git reset HEAD --hard && git clean -fd
git fetch --depth=1 origin tag $CHROMIUM_TAG --no-tags
git checkout -f -b temp tags/$CHROMIUM_TAG
git show-ref --quiet refs/heads/$GOST_BRANCH && git branch -D $GOST_BRANCH
git checkout -f -b $GOST_BRANCH tags/$CHROMIUM_TAG
git branch -D temp
gclient sync --force --reset --upstream -D --with_branch_heads
git am --3way --ignore-space-change < $CHROMIUM_GOST_REPO/patch/extra/no-glic.patch || exit
git am --3way --ignore-space-change < $CHROMIUM_GOST_REPO/patch/extra/extensions-manifestv2_ifdef.patch || exit
git am --3way --ignore-space-change < $CHROMIUM_GOST_REPO/patch/chromium.patch || exit

perl -pi -e "s/Chromium/Chromium-Gost/g" chrome/app/chromium_strings.grd
perl -pi -e "s/Chromium/Chromium-Gost/g" chrome/app/resources/chromium_strings*.xtb
cp -f $CHROMIUM_GOST_REPO/extra/exit_0.sh chrome/installer/linux/common/repo.cron
cp -f $CHROMIUM_GOST_REPO/extra/exit_0.sh chrome/installer/linux/common/rpmrepo.cron

cp -f $CHROMIUM_GOST_REPO/extra/product_logo/*.png chrome/app/theme/chromium/
cp -f $CHROMIUM_GOST_REPO/extra/product_logo/*.png chrome/app/theme/chromium/linux/
cp -f $CHROMIUM_GOST_REPO/extra/product_logo/product_logo_16.png chrome/app/theme/default_100_percent/chromium/product_logo_16.png
cp -f $CHROMIUM_GOST_REPO/extra/product_logo/product_logo_32.png chrome/app/theme/default_100_percent/chromium/product_logo_32.png
cp -f $CHROMIUM_GOST_REPO/extra/product_logo/product_logo_32.png chrome/app/theme/default_200_percent/chromium/product_logo_16.png
cp -f $CHROMIUM_GOST_REPO/extra/product_logo/product_logo_64.png chrome/app/theme/default_200_percent/chromium/product_logo_32.png
cp -f $CHROMIUM_GOST_REPO/extra/product_logo/product_logo_32.xpm chrome/app/theme/chromium/linux/product_logo_32.xpm

cp -f $CHROMIUM_GOST_REPO/extra/favicon_ntp_16.png chrome/app/theme/default_100_percent/common/favicon_ntp.png
cp -f $CHROMIUM_GOST_REPO/extra/favicon_ntp_32.png chrome/app/theme/default_200_percent/common/favicon_ntp.png

cp -f $CHROMIUM_GOST_REPO/extra/colored_header.svg chrome/browser/resources/new_tab_page/icons/colored_header.svg
cp -f $CHROMIUM_GOST_REPO/extra/chromium-gost.svg chrome/browser/resources/new_tab_page/icons/google_logo.svg

cp -Rf $CHROMIUM_GOST_REPO/extra/extensions chrome/browser/resources/bundled_extensions
cp -Rf $CHROMIUM_GOST_REPO/extra/bundled_ca chrome/browser/resources/bundled_ca

cp -f $CHROMIUM_GOST_REPO/src/gostssl.cpp third_party/boringssl/gostssl.cpp
cp -f $CHROMIUM_GOST_REPO/src/msspi/src/msspi.cpp third_party/boringssl/msspi.cpp
cp -f $CHROMIUM_GOST_REPO/src/msspi/src/msspi.h third_party/boringssl/msspi.h
cp -f $CHROMIUM_GOST_REPO/src/msspi/src/capix.hpp third_party/boringssl/capix.hpp

cp -f $CHROMIUM_GOST_REPO/src/msspi/third_party/cprocsp/include/*.h third_party/boringssl/src/include/
cp -Rf $CHROMIUM_GOST_REPO/src/msspi/third_party/cprocsp/include/cpcsp third_party/boringssl/src/include/

cd $BORINGSSL_PATH
git checkout -f -b temp
git show-ref --quiet refs/heads/$GOST_BRANCH && git branch -D $GOST_BRANCH
git checkout -f -b $GOST_BRANCH
git branch -D temp
git am --3way --ignore-space-change < $CHROMIUM_GOST_REPO/patch/boringssl.patch || exit

cd $SEARCH_ENGINES_PATH
git checkout -f -b temp
git show-ref --quiet refs/heads/$GOST_BRANCH && git branch -D $GOST_BRANCH
git checkout -f -b $GOST_BRANCH
git branch -D temp
git am --3way --ignore-space-change < $CHROMIUM_GOST_REPO/patch/search_engines_data.patch || exit

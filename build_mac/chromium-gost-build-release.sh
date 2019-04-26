#!/bin/sh

cd $(dirname $0)
. ./chromium-gost-env.sh
export PATH=$DEPOT_TOOLS_PATH:$PATH

cd $CHROMIUM_PATH/out/RELEASE
unlink *.tar.bz2
if [ -f gostssl.so ]; then unlink gostssl.so; fi
if [ -d Chromium.app ]; then rm -rf Chromium.app; fi
if [ -d Chromium-Gost.app ]; then rm -rf Chromium-Gost.app; fi

cd $(dirname $0)
./chromium-gost-build-gostssl.sh
mv gostssl.so $CHROMIUM_PATH/out/RELEASE/gostssl.so

cd $CHROMIUM_PATH
gn gen out/RELEASE --args="is_debug=false is_official_build=true ffmpeg_branding=\"Chrome\" proprietary_codecs=true $CHROMIUM_PRIVATE_ARGS"
ninja -C out/RELEASE chrome

cd out/RELEASE

mv -f Chromium.app/Contents/MacOS/Chromium Chromium.app/Contents/MacOS/Chromium-Gost
cp -f gostssl.so Chromium.app/Contents/MacOS/gostssl.so

echo "#!/bin/bash" > Chromium.app/Contents/MacOS/Chromium
echo "cd \"\${0%/*}\" && ./Chromium-Gost" >> Chromium.app/Contents/MacOS/Chromium
chmod 755 Chromium.app/Contents/MacOS/Chromium

mv -f Chromium.app/ Chromium-Gost.app/
tar -jcvf chromium-gost-$CHROMIUM_TAG-macos-amd64.tar.bz2 Chromium-Gost.app

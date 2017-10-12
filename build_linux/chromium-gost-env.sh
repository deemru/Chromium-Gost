export CHROMIUM_TAG=61.0.3163.120
export CHROMIUM_PATH=/c/chromium/src
export BORINGSSL_PATH=$CHROMIUM_PATH/third_party/boringssl/src
export DEPOT_TOOLS_PATH=/c/depot_tools/
export CHROMIUM_GOST_REPO=$(pwd)/..
export CHROMIUM_PRIVATE_ARGS= 
if [ -f ./chromium-gost-env-private.sh ]; then . ./chromium-gost-env-private.sh; fi
if [ -f ~/chromium-gost-env-private.sh ]; then . ~/chromium-gost-env-private.sh; fi

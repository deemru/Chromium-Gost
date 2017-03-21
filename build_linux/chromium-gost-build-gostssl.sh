#!/bin/sh

cd $(dirname $0)
. ./chromium-gost-env.sh
g++ -Wall -Wl,--no-as-needed -std=c++11 -fPIC -shared -g -O2 -Werror -Wno-unused-function -ldl \
    -L/opt/cprocsp/lib/amd64 -lcapi10 -lcapi20 \
    -I$BORINGSSL_PATH/ssl -I$BORINGSSL_PATH/include -I../src/msspi/third_party/cprocsp/include -I../src/msspi/src \
    ../src/gostssl.cpp ../src/msspi/src/msspi.cpp -o gostssl.so

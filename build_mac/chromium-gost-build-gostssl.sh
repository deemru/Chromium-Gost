#!/bin/sh

cd $(dirname $0)
. ./chromium-gost-env.sh
g++ -Wall -std=c++11 -fPIC -shared -O2 -Werror -Wno-unused-function -ldl \
    -L/opt/cprocsp/lib/ -lcapi10 -lcapi20 \
    -I$BORINGSSL_PATH/ssl -I$BORINGSSL_PATH/include -I../src/msspi/third_party/cprocsp/include -I../src/msspi/src \
    ../src/gostssl.cpp ../src/msspi/src/msspi.cpp -o gostssl.so

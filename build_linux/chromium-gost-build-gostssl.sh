#!/bin/sh

cd $(dirname $0)
. ./chromium-gost-env.sh
g++ -Wall -Wl,--no-as-needed -std=c++11 -fPIC -shared -g -O2 -Werror -Wno-unused-function -I$BORINGSSL_PATH/ssl -I$BORINGSSL_PATH/include -I../src/msspi/third_party/cprocsp/include -I../src/msspi/src ../src/gostssl.cpp -o gostssl.so

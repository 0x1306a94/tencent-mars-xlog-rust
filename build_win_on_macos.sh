#!/bin/bash 

set -e

WIN_TARGET=x86_64-pc-windows-gnu
OUT_NAME=tencent-mars-xlog-util

# rustup target add x86_64-pc-windows-gnu
# brew install mingw-w64

CUR_DIR=$PWD

function useage() {
    echo "Useage:"
    echo ""
    echo "  ./build.sh --out dir"
    exit 0
}

if [ ! -n "$1" ]; then
    useage
elif [ ! -n "$2" ]; then
    useage
elif [ "$1" == "--out" ]; then

    rustup target add $WIN_TARGET

    cargo build --release --target=$WIN_TARGET

    mkdir -p $2
    echo $CUR_DIR
    cp ./target/$WIN_TARGET/release/$OUT_NAME.exe $2/$OUT_NAME.exe
    cd $2
    zip -q -o "${OUT_NAME}-win-x86_64-binaries.zip" $OUT_NAME.exe
    cd $CUR_DIR

fi


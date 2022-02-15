#!/bin/bash 

set -e

MAC_X86_TARGET=x86_64-apple-darwin
MAC_ARM64_TARGET=aarch64-apple-darwin
OUT_NAME=tencent-mars-xlog-util

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

    rustup target add $MAC_X86_TARGET
    rustup target add $MAC_ARM64_TARGET

    cargo build --release --target=$MAC_X86_TARGET
    cargo build --release --target=$MAC_ARM64_TARGET

    mkdir -p $2
    lipo -create -output $2/$OUT_NAME ./target/$MAC_X86_TARGET/release/$OUT_NAME ./target/$MAC_ARM64_TARGET/release/$OUT_NAME
    cd $2
    zip -q -o "${OUT_NAME}-universal-binaries.zip" $OUT_NAME
    cd $CUR_DIR
fi


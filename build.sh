#!/bin/bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"
mkdir -p build

SDK_PATH="$(xcrun --sdk iphoneos --show-sdk-path)"
echo "Using SDK: $SDK_PATH"

xcrun --sdk iphoneos clang++ \
  -arch arm64 \
  -miphoneos-version-min=15.0 \
  -fobjc-arc \
  -fvisibility=hidden \
  -O2 \
  -dynamiclib \
  RemoteAuth.mm \
  -framework UIKit \
  -framework Foundation \
  -framework Security \
  -framework QuartzCore \
  -framework ImageIO \
  -framework CoreGraphics \
  -Wl,-install_name,@rpath/RemoteAuth.dylib \
  -Wl,-dead_strip \
  -Wl,-sectcreate,__DATA,__eaicon,icon.gif \
  -o build/RemoteAuth.dylib

codesign --remove-signature build/RemoteAuth.dylib 2>/dev/null || true

file build/RemoteAuth.dylib
otool -L build/RemoteAuth.dylib
strings build/RemoteAuth.dylib | grep "REMOTE-AUTH-IPV4-V2"
otool -l build/RemoteAuth.dylib | grep -A4 "sectname __eaicon" || true

cd build
shasum -a 256 RemoteAuth.dylib | awk '{print toupper($1)}' > RemoteAuth.dylib.sha256.txt
ditto -c -k --sequesterRsrc --keepParent RemoteAuth.dylib RemoteAuth.dylib.zip

#!/usr/bin/env bash
# Build with MinGW-w64 (x86_64-w64-mingw32-g++). Produces steam_api64.dll.
set -e
x86_64-w64-mingw32-g++ -shared -O2 -std=c++17 -static -static-libgcc -static-libstdc++ \
  dllmain.cpp steam_api64.def -o steam_api64.dll \
  -Wl,--enable-stdcall-fixup
echo "Built steam_api64.dll"

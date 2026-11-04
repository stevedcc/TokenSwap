#!/usr/bin/env bash
# Publishes yk-spike as NativeAOT into ./out and fails if the build warns about trimming/AOT (IL2xxx/IL3xxx).
set -euo pipefail
cd "$(dirname "$0")"
# Linux: Yubico.NativeShims' static library links -lpcsclite. Without pcsc-lite-devel there is no libpcsclite.so, so
# link against the runtime library (libpcsclite.so.1, from pcsc-lite-libs) through a local link instead.
if [ "$(uname)" = Linux ]; then
  mkdir -p linklib
  for d in /usr/lib64 /usr/lib/x86_64-linux-gnu /usr/lib/aarch64-linux-gnu /usr/lib; do
    if [ -e "$d/libpcsclite.so.1" ]; then ln -sfn "$d/libpcsclite.so.1" linklib/libpcsclite.so; break; fi
  done
fi
log="$(mktemp)"
dotnet publish -c Release -o out -nologo 2>&1 | tee "$log"
if grep -E 'warning IL(2|3)[0-9]{3}' "$log" > out/aot-warnings.txt; then
  echo "AOT/trim warnings (also in out/aot-warnings.txt):"; cat out/aot-warnings.txt; rm -f "$log"; exit 1
fi
rm -f "$log"; : > out/aot-warnings.txt
echo "published: $(pwd)/out/yk-spike"

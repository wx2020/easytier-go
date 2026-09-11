#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
ffi_dir=$root/ffi
go_bin=${GO:-go}
if ! command -v "$go_bin" >/dev/null 2>&1 && [ -x /usr/lib/go-1.24/bin/go ]; then
    go_bin=/usr/lib/go-1.24/bin/go
fi
tmp_dir=$(mktemp -d)
trap 'rm -rf "$tmp_dir"' EXIT

"$go_bin" -C "$root" build -buildmode=c-shared -o "$tmp_dir/libeasytierffi.so" ./ffi
${CC:-cc} -std=c11 -Wall -Wextra -Werror \
    -I"$ffi_dir" "$ffi_dir/testdata/smoke_test.c" \
    -L"$tmp_dir" -Wl,-rpath,"$tmp_dir" -leasytierffi \
    -o "$tmp_dir/ffi-smoke"
"$tmp_dir/ffi-smoke"

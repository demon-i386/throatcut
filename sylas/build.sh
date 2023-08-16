#!/bin/bash
RUSTFLAGS="-C debuginfo=0 -C strip=symbols -C debug-assertions=no -C panic=abort -C target-feature=-crt-static -C relocation-model=pic -C opt-level=z -C lto=fat --remap-path-prefix $HOME=~" cargo +nightly xwin build --target x86_64-pc-windows-msvc --release -Z build-std=std,panic_abort -Z build-std-features=panic_immediate_abort

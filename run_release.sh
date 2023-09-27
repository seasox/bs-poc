#!/bin/sh
PATTERN=2e27f5c4-4941-4907-8964-2b86d9745120
#PATTERN=fe557207-465b-4cc4-8979-b9646bdca83b

cargo build --release && \
RUST_LOG=info sudo -E taskset -c 1 target/release/bs_poc --config=esprimo-d757_i5-6400_gskill-F4-2133C15-16GIS.json --load-json=fuzz-summary-230921.json --pattern=$PATTERN --hammer-mode=rsa --elevated-priority

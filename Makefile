#!/bin/sh

CONFIG=esprimo-d757_i5-6400_gskill-F4-2133C15-16GIS.json 

FUZZ_CONF=config/fuzz-summary_small.json
PATTERN=31a3b147-c1b4-4e15-8dec-d586a93f4fed
MAPPING=9a9fc4d8-0edb-43f3-9e6f-ffe7670b20bf

all:
	cargo build --release

bait_alloc: all
	RUST_LOG=info sudo -E taskset -c 1 target/release/bait_alloc --config=${CONFIG} --load-json=${FUZZ_CONF} --pattern=${PATTERN} --mapping=${MAPPING}

bs_poc: all
	RUST_LOG=info sudo -E taskset -c 1 target/release/bs_poc --config=${CONFIG} --load-json=${FUZZ_CONF} --pattern=${PATTERN} --mapping=${MAPPING} --hammer-mode=mem-check --elevated-priority

testing: all
	RUST_LOG=info target/release/testing --config=${CONFIG} --load-json=${FUZZ_CONF} --pattern=${PATTERN} --mapping=${MAPPING}


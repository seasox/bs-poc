#!/bin/sh

CONFIG=config/esprimo-d757_i5-6400_gskill-F4-2133C15-16GIS.json 

# FUZZ_CONF=config/fuzz-summary_small.json
# PATTERN=31a3b147-c1b4-4e15-8dec-d586a93f4fed
# MAPPING=9a9fc4d8-0edb-43f3-9e6f-ffe7670b20bf
# [+] Sweeping pattern 835de010-4e2f-468b-85a9-a1f9db351ae8 with mapping 715b602f-1ad9-45a6-9119-b71fb3002b48 over 256 MB, equiv. to 1024 rows, with each 10 repetitions.
FUZZ_CONF=config/fuzz-summary_25mb.json
PATTERN=835de010-4e2f-468b-85a9-a1f9db351ae8
MAPPING=715b602f-1ad9-45a6-9119-b71fb3002b48

BS_FLAGS =--config=${CONFIG}
BS_FLAGS+=--load-json=${FUZZ_CONF}
BS_FLAGS+=--pattern=${PATTERN}
#BS_FLAGS+=--mapping=${MAPPING}

LOG_LEVEL=info

LOGGER=RUST_LOG=${LOG_LEVEL}

SUDO=sudo -E taskset -c 1 

all:
	cargo build --release

bait_alloc: all
	${LOGGER} ${SUDO} target/release/bait_alloc ${BS_FLAGS}

bs_poc: all
	${LOGGER} ${SUDO} target/release/bs_poc ${BS_FLAGS} --hammer-mode=mem-check --elevated-priority

bs_poc-dummy: all
	${LOGGER} ${SUDO} target/release/bs_poc ${BS_FLAGS} --hammer-mode=mem-check --elevated-priority --dummy-hammerer

testing: all
	${LOGGER} target/release/testing ${BS_FLAGS}


clean:
	cargo clean --release

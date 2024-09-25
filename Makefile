#!/bin/sh

CONFIG=config/esprimo-d757_i5-6400_gskill-F4-2133C15-16GIS.json 

# FUZZ_CONF=config/fuzz-summary_small.json
# PATTERN=31a3b147-c1b4-4e15-8dec-d586a93f4fed
# MAPPING=9a9fc4d8-0edb-43f3-9e6f-ffe7670b20bf
FUZZ_CONF=config/fuzz-summary.json
PATTERN=39ad622b-3bfe-4161-b860-dad5f3e6dd68
#MAPPING=4d16a3db-c991-419a-b6fe-3a7f41113a8e

#ALLOC_STRATEGY=hugepage-rnd
#ALLOC_STRATEGY=co-co
#ALLOC_STRATEGY=buddy-info
ALLOC_STRATEGY=mmap

CONSEC_CHECK=bank-timing

LOG_LEVEL=info

PROFILE=release

#########################
#    END config block   #
#########################

BS_FLAGS =--config=${CONFIG}
BS_FLAGS+=--load-json=${FUZZ_CONF}
BS_FLAGS+=--alloc-strategy=${ALLOC_STRATEGY}
BS_FLAGS+=--consec-check=${CONSEC_CHECK}

ifneq ($(PATTERN),)
BS_FLAGS+=--pattern=${PATTERN}
endif

ifneq ($(MAPPING),)
BS_FLAGS+=--mapping=${MAPPING}
endif

ifeq ($(PROFILE),release)
	CARGO_FLAGS=--release
endif

LOGGER=RUST_LOG=${LOG_LEVEL}

SUDO=sudo -E taskset -c 1 

all:
	cargo build ${CARGO_FLAGS}

hammer: all run_hammer

run_hammer:
	${LOGGER} ${SUDO} target/${PROFILE}/bait_alloc ${BS_FLAGS}

bs_poc: all
	${LOGGER} ${SUDO} target/${PROFILE}/bs_poc ${BS_FLAGS} --hammer-mode=mem-check --elevated-priority

bs_poc-dummy: all
	${LOGGER} ${SUDO} target/${PROFILE}/bs_poc ${BS_FLAGS} --hammer-mode=mem-check --elevated-priority --dummy-hammerer

testing: all
	${LOGGER} target/${PROFILE}/testing ${BS_FLAGS}


clean:
	cargo clean ${CARGO_FLAGS}

hammer_jit.o.objdump: hammer_jit.o
	objdump -b binary -m i386:x86-64 -D hammer_jit.o > hammer_jit.o.objdump

# Shorthand target to rebuild all READMEs in all subdirectories containing a mod.rs file
readme:
	for dir in $$(find src -type f -name mod.rs -exec dirname {} \;); do \
		cargo readme --input $$dir/mod.rs > $$dir/README.md --no-title; \
	done
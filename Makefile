#!/bin/sh

CONFIG=config/esprimo-d757_i5-6400_gskill-F4-2133C15-16GIS.json 

# FUZZ_CONF=config/fuzz-summary_small.json
# PATTERN=31a3b147-c1b4-4e15-8dec-d586a93f4fed
# MAPPING=9a9fc4d8-0edb-43f3-9e6f-ffe7670b20bf
FUZZ_CONF=config/fuzz-summary.json
PATTERN=39ad622b-3bfe-4161-b860-dad5f3e6dd68
#MAPPING=4d16a3db-c991-419a-b6fe-3a7f41113a8e

ALLOC_STRATEGY?=pfn

CONSEC_CHECK=bank-timing

LOG_LEVEL=info

PROFILE=release

ALLOCATOR?=pfn
HAMMERER?=blacksmith
TIMEOUT?=1

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

CARGO_FLAGS=--profile=${PROFILE}

LOGGER=RUST_LOG=${LOG_LEVEL}

SUDO=sudo -E taskset -c 1 

all:
	make -C victims
	cargo build ${CARGO_FLAGS}

hammer: all run_hammer

run_dummy: all
	RUST_BACKTRACE=1 RUST_LOG=info sudo -E taskset -c 1 target/${PROFILE}/hammer --alloc-strategy ${ALLOCATOR} --timeout 1 --attempts 50 --profiling-rounds 10 --reproducibility-threshold 0.8 --hammerer ${HAMMERER} sphincs-plus victims/stack-dummy/stack

run_bench: all
	RUST_BACKTRACE=1 RUST_LOG=info sudo -E taskset -c 1 target/${PROFILE}/bench --alloc-strategy ${ALLOCATOR} --timeout 1 --attempts 50 --profiling-rounds 10 --reproducibility-threshold 0.8 --hammerer ${HAMMERER} sphincs-plus victims/stack-dummy/stack


clean:
	make -C victims clean
	cargo clean ${CARGO_FLAGS}

hammer_jit.o.objdump: hammer_jit.o
	objdump -b binary -m i386:x86-64 -D hammer_jit.o > hammer_jit.o.objdump

# Shorthand target to rebuild all READMEs in all subdirectories containing a mod.rs file
readme:
	cargo readme --no-title > README.md
	for dir in $$(find src -type f -name mod.rs -exec dirname {} \;); do \
		echo "# Module $$dir" > $$dir/README.md; \
		cargo readme --input $$dir/mod.rs >> $$dir/README.md --no-title; \
	done

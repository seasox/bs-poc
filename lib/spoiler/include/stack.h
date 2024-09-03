#include <stdio.h>
#include <sys/statvfs.h>
#include <stdint.h>			// uint64_t
#include <stdlib.h>			// For malloc
#include <string.h>			// For memset
#include <time.h>
#include <fcntl.h>			// For O_RDONLY in get_physical_addr fn 
#include <unistd.h>			// For pread in get_physical_addr fn, for usleep
#include <sys/mman.h>
#include <stdbool.h>		// For bool
#include <sys/stat.h>
#include <errno.h>
#include <sched.h>
#include <sys/wait.h>
#include <regex.h>

typedef struct
{
	uint64_t address;
	uint64_t value;
} StackEntry;

int read_stack(int pid, StackEntry **stack_entries);
uint64_t find_integer_in_stack(StackEntry *stack_entries, int num_entries, uint64_t target_value);
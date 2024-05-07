#include "../include/misc.h"
#include "../include/drama.h"


int ret_created = false;


int getCurrentCore() {
    int core_id = -1; // Default to -1 to indicate failure.

#if defined(__linux__) || defined(__unix__) || defined(_POSIX_VERSION)
    // On POSIX-compliant systems, you can use sched_getcpu().
    core_id = sched_getcpu();
    if (core_id == -1) {
        perror("sched_getcpu failed");
    }
#elif defined(_WIN32)
    // Windows systems use GetCurrentProcessorNumber().
    core_id = (int)GetCurrentProcessorNumber();
#else
    #error "Unsupported platform"
#endif
	printf("Running on core %d\n", core_id);
    return core_id;
}


// Taken from https://github.com/IAIK/flipfloyd
uint64_t get_physical_addr(uint64_t virtual_addr)
{
	if(is_root()){
		static int g_pagemap_fd = -1;
		uint64_t value;

		// open the pagemap
		if (g_pagemap_fd == -1)
		{
			g_pagemap_fd = open("/proc/self/pagemap", O_RDONLY);
		}
		if (g_pagemap_fd == -1)
			return 0;

		// read physical address
		off_t offset = (virtual_addr / 4096) * sizeof(value);
		int got = pread(g_pagemap_fd, &value, sizeof(value), offset);
		if (got != 8)
			return 0;

		// Check the "page present" flag.
		if (!(value & (1ULL << 63)))
			return 0;

		// return physical address
		uint64_t frame_num = value & ((1ULL << 55) - 1);
		return (frame_num * 4096) | (virtual_addr & (4095));
	}
	else{
		return 0;
	}
}

// Function that checks if we are running as root
int is_root()
{
	if (getuid() != 0)
	{
		return 0;
	}
	return 1;
}

uint64_t get_physical_addr_pid(uint64_t virtual_addr, pid_t pid)
{
	if(is_root()){
		int pagemap_fd = -1;
		char pagemap_file[64];
		snprintf(pagemap_file, sizeof(pagemap_file), "/proc/%d/pagemap", pid);

		pagemap_fd = open(pagemap_file, O_RDONLY);
		if (pagemap_fd == -1)
		{
			perror("open pagemap_file");
			return 0;
		}

		uint64_t value;
		off_t offset = (virtual_addr / PAGE_SIZE) * sizeof(value);
		if (pread(pagemap_fd, &value, sizeof(value), offset) != sizeof(value))
		{
			perror("pread");
			return 0;
		}

		if (!(value & (1ULL << 63)))
		{
			return 0;
		}

		uint64_t frame_num = value & ((1ULL << 55) - 1);
		return (frame_num * PAGE_SIZE) | (virtual_addr & (PAGE_SIZE - 1));
	}
	else{
		return 0;
	}
}

void print_addr_space(struct addr_space *as)
{
	int i;
	for (i = 0; i < as->length; i++)
	{
		printf("v-addr: %p p-addr: %lx\n", as->memory_addresses[i], get_physical_addr((uint64_t)as->memory_addresses[i]));
	}
}


int detectMemType()
{
	if(is_root()){
		FILE *command;
		char out[1035] = {32};

		command = popen("/usr/bin/sudo -S lshw | grep DDR", "r");
		if (command == NULL)
		{
			printf("Failed to run command\n");
			exit(1);
		}
		while (fgets(out, sizeof(out), command) != NULL)
		{
			// Capture the output of the program here
		}
		pclose(command);

		if (out[34] == 52)
		{ // 52 is the ascii value for 4
			printf("DDR4 detected\n\n");
			return 1;
		}
		else if (out[34] == 51)
		{ // 51 is the ascii value for 3
			printf("DDR3 detected\n\n");
			return 0;
		}
		else
		{
			printf("DDR type could not be detected. Running with DDR4...\n\n");
			return 1;
		}
	}
	else{
		printf("DDR type could not be detected (not root). Running with DDR4...\n\n");
		return 1;
	}
}

// Function to intentionally cause a segmentation fault
void trigger_segfault() {
    int *ptr = NULL;
    *ptr = 1; // Writing to a null pointer causes a segmentation fault
}


int get_current_cpu_core() {
    FILE *fp;
    int cpu_core = -1;
    char buffer[1024];

    fp = fopen("/proc/self/stat", "r");
    if (!fp) {
        perror("fopen");
        return -1; // Failed to open the file
    }

    if (fgets(buffer, sizeof(buffer), fp) != NULL) {
        // Attempt to read the core number; this field is 39th in the list in /proc/self/stat
        char *token;
        int i = 0;
        for (token = strtok(buffer, " "); token != NULL; token = strtok(NULL, " ")) {
            if (++i == 39) {
                cpu_core = atoi(token);
                break;
            }
        }
    }
    fclose(fp);
    return cpu_core;
}

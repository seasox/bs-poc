#include "../include/misc.h"
#include "../include/spoiler.h"
#include "../include/rowconflict.h"
#include "../include/drama.h"
#include "../include/ptcont.h"
#include "../include/process_handling.h"
#include "../include/stack.h"
#include <signal.h>

#define HAMMER_ONCE 0
#define HAMMER_MANY 1

// Create an interrupt handler for SIGINT
void sigintHandler(int sig_num)
{
	exit(130);
}

// Main function
int main(int argc, char *argv[])
{
	// Register signal handler for SIGINT
	signal(SIGINT, sigintHandler);
	setvbuf(stdout, NULL, _IONBF, 0); // turn off buffering for stdout

	int DDR_type = 4; // detectMemType();

	if (!is_root())
	{
		printf("Running without root privilages - This is fine, but physical addresses and other privilaged information will not be logged...\n\n");
	}
	int core = getCurrentCore();
	int mem = detectMemType();

	for (int i = 0; i < 100; i++)
	{
		// system("echo 1 | sudo tee /proc/sys/vm/compact_memory");
		system("echo 123456 | /usr/bin/sudo -S sh -c \"echo 1 >> /proc/sys/vm/compact_memory\"");
		system("echo 0 | sudo tee /proc/sys/kernel/randomize_va_space");
		// system("echo 3 | sudo tee /proc/sys/vm/drop_caches");

		srand((unsigned int)time(NULL));

		printf("Allocating %ld pages of memory\n", PAGE_COUNT);
		uint8_t *search_buffer = mmap(NULL, PAGE_COUNT * PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_POPULATE | MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);

		struct addr_space *cont_memory = auto_spoiler(search_buffer);
		// struct addr_space *cont_memory = spoiler(search_buffer);
		struct addr_space *cont_bank = rowconflict(cont_memory);
		// struct addr_space *cont_bank = getContinuousDrama(search_buffer);

		printf("Cont mem: %d\n", cont_memory->length);

		profileDDR4(cont_bank);
		munmap(search_buffer, PAGE_COUNT * PAGE_SIZE);
	}

	return 1;
}

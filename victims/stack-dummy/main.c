#include <emmintrin.h> // For _mm_clflush
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <stdint.h>
#include <fcntl.h>
#include <stdlib.h>
#include <errno.h>
#include <pthread.h>

#include <signal.h>

#include "memutils.h"

#define NROUNDS 10

#define BUFSIZE 4096

#define PAGE_SIZE 4096 // Define the page size (typically 4 KB)
#define CL_SIZE 64     // Define the cache line size (typically 64 bytes)
#define PAGEMAP_ENTRY_SIZE 8 // Each pagemap entry is 8 bytes

void sigusr1_handler(int signum) {
	fprintf(stderr, "Received SIGUSR1, continuing...\n");
}

int main(int argc, char **argv) {
	__attribute__ ((aligned(4096))) unsigned char buf[BUFSIZE] = {};

	setbuf(stdout, NULL);
	setbuf(stderr, NULL);

	uint64_t phy = get_physical_address(buf);
	fprintf(stderr, "%lx\n", phy);

	signal(SIGUSR1, sigusr1_handler);

	unsigned char pattern[2] = {0b10101010, 0b01010101};
	int fd = mtrr_open();
	if (fd < 0) {
		fprintf(stderr, "Failed to open /dev/mtrr\n");
		return 1;
	}
	uint64_t phys = get_physical_address(buf);
	if (mtrr_page_uncachable(fd, phys) < 0) {
		fprintf(stderr, "Failed to set page uncachable\n");
	}
	for (unsigned int i = 0;; i = (i+1)&1) {
		memset(buf, pattern[i], BUFSIZE);
		MEMUTILS_PRINT_OFFSET(buf, BUFSIZE);
		fprintf(stderr, "Waiting for SIGUSR1\n");
		printf("SIGUSR1\n");
		pause();
		// waiting for SIGUSR1
		MEMUTILS_PRINT_OFFSET(buf, BUFSIZE);
		for (int j = 0; j < BUFSIZE; ++j) {
			if (buf[j] != pattern[i]) {
				printf("buf[%d] = %02x;", j, buf[j]);
			}
		}
		printf("\n");
		// todo inspect asm
	}
	mtrr_close(fd);
	return 0;
}


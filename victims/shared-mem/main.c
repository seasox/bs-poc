#include <emmintrin.h> // For _mm_clflush
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <stdint.h>
#include <fcntl.h>
#include <stdlib.h>
#include <errno.h>
#include <pthread.h>
#include <linux/mman.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <signal.h>

#include "memutils.h"

#define NROUNDS 10


#define PAGE_SIZE 4096 // Define the page size (typically 4 KB)
#define CL_SIZE 64     // Define the cache line size (typically 64 bytes)
#define PAGEMAP_ENTRY_SIZE 8 // Each pagemap entry is 8 bytes

void sigusr1_handler(int signum) {
	fprintf(stderr, "Received SIGUSR1, continuing...\n");
}

#define ONE_GB ((off_t)(1<<30))
#define BUFSIZE ((off_t)4*ONE_GB)

#define BASE_ADDR ((void*)0x2000000000)

#define USE_SHM

int main(int argc, char **argv) {
	setbuf(stdout, NULL);
	setbuf(stderr, NULL);

	if (argc < 4) {
		fprintf(stderr, "Usage: %s <ignored> <ignored> <target_addr>\n", argv[0]);
		return 1;
	}

	for (int i = 0; i < argc; ++i) {
		fprintf(stderr, "argv[%d]=%s\n", i, argv[i]);
	}

	uint8_t *target_addr = (uint8_t*)strtoul(argv[3], NULL, 0);

	if ((uintptr_t)target_addr - (uintptr_t)BASE_ADDR > BUFSIZE) {
		fprintf(stderr, "target_addr is out of bounds: %lu > %lu\n", 
			(uintptr_t)target_addr - (uintptr_t)BASE_ADDR, BUFSIZE);
		return 1;
	}

#ifdef USE_SHM
	int fd = shm_open("HAMMER_SHM", O_RDONLY, S_IRUSR | S_IWUSR);
#else
# ifdef USE_HUGEPAGE
	int fd = open("/dev/hugepages/hammer_huge", O_RDONLY, S_IRUSR);
# endif
#endif
	if (fd < 0) {
		perror("open");
		return 1;
	}
	uint8_t *buf = mmap(BASE_ADDR, BUFSIZE, PROT_READ, MAP_SHARED_VALIDATE | MAP_POPULATE, fd, 0);
	close(fd);

	if (buf == MAP_FAILED) {
		perror("mmap");
		return 1;
	}

	uint64_t phys = get_physical_address(buf);
	fprintf(stderr, "phys(buf)=0x%lx\n", phys);
	// Ensure the buffer is populated
	for (off_t offset = 0; offset < BUFSIZE; offset += PAGE_SIZE) {
		uint8_t temp = buf[offset];
		_mm_clflush(&temp);
	}
	_mm_mfence();
	if (buf != BASE_ADDR) {
		fprintf(stderr, "mmap returned unexpected address: %p\n", buf);
		return 1;
	}

	phys = get_physical_address((void*)target_addr);
	fprintf(stderr, "phys(target_addr)=0x%lx\n", phys);

	signal(SIGUSR1, sigusr1_handler);

	fd = mtrr_open();
	if (fd < 0) {
		perror("mtrr_open");
		return 1;
	}
	//mtrr_page_uncachable(fd, (uintptr_t)target_addr);
	
	while (1) {
		//*target_addr = ~(*target_addr);
		_mm_clflush(target_addr);
		_mm_mfence();
		MEMUTILS_PRINT_OFFSET(target_addr, 1);
		MEMUTILS_PRINT_OFFSET(target_addr, 1);
		_mm_clflush(target_addr);
		fprintf(stderr, "Waiting for SIGUSR1\n");
		printf("SIGUSR1\n");
		pause();
		// waiting for signal...
		_mm_mfence();
		MEMUTILS_PRINT_OFFSET(target_addr, 1);
		time_t current_time;
		char time_str[100];
		time(&current_time);
		strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", localtime(&current_time));
		printf("%s: %02x", time_str, *target_addr);
		printf("\n");
	}
	close(fd);
	return 0;
}


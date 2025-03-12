#include <emmintrin.h> // For _mm_clflush
#include <cstring>
#include <unistd.h>
#include <stdio.h>
#include <stdint.h>
#include <fcntl.h>
#include <stdlib.h>
#include <errno.h>
#include <pthread.h>

#include <signal.h>

#define NROUNDS 10

#define BUFSIZE 8192

#define PAGE_SIZE 4096 // Define the page size (typically 4 KB)
#define PAGEMAP_ENTRY_SIZE 8 // Each pagemap entry is 8 bytes

// Function to get PFN from a virtual address
uint64_t get_pfn_from_vaddr(uint64_t vaddr) {
    uint64_t pfn = 0;
    uint64_t page_offset = vaddr / PAGE_SIZE;
    uint64_t pagemap_entry = 0;
    char pagemap_path[64];
    
    // Open the /proc/self/pagemap file
    snprintf(pagemap_path, sizeof(pagemap_path), "/proc/self/pagemap");
    int pagemap_fd = open(pagemap_path, O_RDONLY);
    if (pagemap_fd == -1) {
        perror("Failed to open /proc/self/pagemap");
        return -1;
    }

    // Seek to the pagemap entry corresponding to the virtual page
    off_t offset = page_offset * PAGEMAP_ENTRY_SIZE;
    if (lseek(pagemap_fd, offset, SEEK_SET) == (off_t)-1) {
        perror("Failed to seek in /proc/self/pagemap");
        close(pagemap_fd);
        return -1;
    }

    // Read the pagemap entry for the virtual address
    if (read(pagemap_fd, &pagemap_entry, PAGEMAP_ENTRY_SIZE) != PAGEMAP_ENTRY_SIZE) {
        perror("Failed to read pagemap entry");
        close(pagemap_fd);
        return -1;
    }

    // Close the pagemap file
    close(pagemap_fd);

    // Check if the page is present in memory
    if (!(pagemap_entry & (1ULL << 63))) {
        fprintf(stderr, "Page not present in memory\n");
        return -1;
    }

    // Extract the PFN from the pagemap entry (bits 0-54)
    pfn = pagemap_entry & ((1ULL << 55) - 1);
    return pfn;
}

struct ReadBufArgs {
	unsigned char *buf;
	size_t bufsize;
};

void* read_buffer(void *pargs) {
	unsigned char *buf = ((struct ReadBufArgs*)pargs)->buf;
	size_t bufsize = ((struct ReadBufArgs*)pargs)->bufsize;
	while (true) {
		for (size_t i = 0; i < bufsize; ++i) {
			volatile int x;
			asm("mov %1, %0" : "=r"(x) : "m"(buf[i]));
			_mm_clflush(&buf[i]);
		}
	}
	return NULL;
}

int main(int argc, char **argv) {
	unsigned char buf[BUFSIZE] = {};

	setbuf(stdout, NULL);
	setbuf(stderr, NULL);

	uint64_t phy = get_pfn_from_vaddr((uint64_t)buf);
	fprintf(stderr, "%lx\n", phy);

	// launch thread reading and flushing buf
	//pthread_t thread_id;
	//struct ReadBufArgs args = {
	//	.buf = buf,
	//	.bufsize = BUFSIZE
	//};
	//pthread_create(&thread_id, NULL, read_buffer, &args);
	//printf("pattern:\n");
	//fflush(stdout);
	//unsigned char pattern = getchar();
	unsigned char pattern[2] = {0b10101010, 0b01010101};
	for (unsigned int i = 0;; i = (i+1)&1) {
		fprintf(stderr, "i=%d, pattern: 0x%02x\n", i, pattern[i]);
		memset(buf, pattern[i], BUFSIZE);
		_mm_mfence();
		for (int j = 0; j < BUFSIZE; j += 64) {
			_mm_clflush(buf + j);
		}
		_mm_mfence();
		for (int r = 0; r < NROUNDS; ++r) {
			for (int j = 0; j < BUFSIZE; j += 64) {
				_mm_clflush(buf + j);
			}
			_mm_mfence();
			fprintf(stderr, "Going to SIGSTOP\n");
			//alternative to SIGSTOP/SIGCONT: shared memory page
			raise(SIGSTOP);
			// waiting for SIGCONT
			fprintf(stderr, "Continuing\n");
			fprintf(stderr, "Round %d\n", r);
			_mm_mfence();
			for (int j = 0; j < BUFSIZE; j += 64) {
				_mm_clflush(buf + j);
			}
			_mm_mfence();
			for (int j = 0; j < BUFSIZE; ++j) {
				printf("%02x", buf[j]);
			}
			printf("\n");
			// todo inspect asm
		}
	}
	//pthread_cancel(thread_id);
	return 0;
}


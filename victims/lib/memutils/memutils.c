// memutils.c
#define _GNU_SOURCE
#include "memutils.h"
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <sched.h>
#include <asm/mtrr.h>
#include <sys/ioctl.h>

#define PAGE_SIZE 4096
#define PAGE_SHIFT 12

uint32_t fault_id = UINT32_MAX;

// Read the physical address from pagemap
uint64_t get_physical_address(void *virtual_address) {
    // Open the pagemap file for the current process
    int pagemap_fd = open("/proc/self/pagemap", O_RDONLY);
    if (pagemap_fd == -1) {
        perror("Failed to open /proc/self/pagemap");
        return (uint64_t)-1;
    }

    // Calculate the pagemap index for the given virtual address
    uint64_t virtual_page_index = (uint64_t)virtual_address >> PAGE_SHIFT;
    off_t offset = (off_t)(virtual_page_index * sizeof(uint64_t));

    // Seek to the pagemap entry
    if (lseek(pagemap_fd, offset, SEEK_SET) == (off_t)-1) {
        perror("Failed to seek in /proc/self/pagemap");
        close(pagemap_fd);
        return (uint64_t)-1;
    }

    // Read the pagemap entry
    uint64_t pagemap_entry;
    if (read(pagemap_fd, &pagemap_entry, sizeof(pagemap_entry)) != sizeof(pagemap_entry)) {
        perror("Failed to read /proc/self/pagemap");
        close(pagemap_fd);
        return (uint64_t)-1;
    }

    close(pagemap_fd);

    // Check if the page is present in memory
    if (!(pagemap_entry & (1ULL << 63))) {
        fprintf(stderr, "Page not present in memory\n");
        return (uint64_t)-1;
    }

    // Extract the physical page number from the pagemap entry
    uint64_t physical_page_number = pagemap_entry & ((1ULL << 55) - 1);
    return (physical_page_number << PAGE_SHIFT) | ((uint64_t)virtual_address & (PAGE_SIZE - 1));
}

// Calculate the offset in pages for the given virtual address
ssize_t get_stack_offset(void *virtual_address) {
    // Get the start of the stack region from /proc/self/maps
    FILE *maps_file = fopen("/proc/self/maps", "r");
    if (!maps_file) {
        perror("Failed to open /proc/self/maps");
        return -1;
    }

    uintptr_t stack_start = 0;
    uintptr_t stack_end = 0;

    char line[256];
    while (fgets(line, sizeof(line), maps_file)) {
        if (strstr(line, "[stack]")) {
            sscanf(line, "%lx-%lx", &stack_start, &stack_end);
            break;
        }
    }

    fclose(maps_file);

    if (stack_start == 0) {
        fprintf(stderr, "Failed to find stack region\n");
        return -1;
    }

    if ((uintptr_t)virtual_address < stack_start || (uintptr_t)virtual_address >= stack_end) {
        //fprintf(stderr, "Address is not within the stack region\n");
        return -1;
    }

    // Calculate the offset in pages
    return (ssize_t)(((uintptr_t)virtual_address - stack_start) / PAGE_SIZE);
}

int mtrr_open(void) {
    int fd = open("/proc/mtrr", O_WRONLY);
    if (fd < 0) {
        perror("open");
    }
    return fd;
}

int mtrr_page_uncachable(int fd, uint64_t phys) {
    struct mtrr_sentry mtrr;
    
    // Set up the MTRR entry structure
    mtrr.base = phys & ~(PAGE_SIZE-1);
    mtrr.size = PAGE_SIZE;
    mtrr.type = MTRR_TYPE_UNCACHABLE;

    // Use ioctl to add the MTRR entry
    int regnum = ioctl(fd, MTRRIOC_ADD_ENTRY, &mtrr);
    if (regnum < 0) {
        perror("ioctl");
        return -1;
    }
    return 0;
}

void mtrr_close(int fd) {
    close(fd);
}

__attribute__((noinline))
unsigned long long measure_access(void *ptr, unsigned int measure_rounds) {
    unsigned long long start, end;
    unsigned int aux;
    volatile uint8_t y;

    __asm__ volatile ("mfence" ::: "memory");
    __asm__ volatile ("cpuid" ::: "rax", "rbx", "rcx", "rdx", "memory"); // Serialize
    __asm__ volatile ("rdtscp" : "=a" (start), "=d" (aux) :: "rcx", "memory"); // Read timestamp
    __asm__ volatile ("lfence"); // Ensure load doesn't execute before timestamp
    for (unsigned int i = 0; i < measure_rounds; ++i) {
        __asm__ volatile ("mov (%1), %0" : "=r" (y) : "r" (ptr) : "memory");
    }
    __asm__ volatile ("lfence" ::: "memory");
    __asm__ volatile ("rdtscp" : "=a" (end), "=d" (aux) :: "rcx", "memory");
    __asm__ volatile ("mfence" ::: "memory");
    
    return (end - start) / measure_rounds;
}

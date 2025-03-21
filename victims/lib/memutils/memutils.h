// memutils.h
#ifndef MEMUTILS_H
#define MEMUTILS_H

#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>

#include <stdio.h>

#define FLUSH(ptr) \
    __asm__ volatile("clflush (%0); mfence" :: "r"((ptr)) : "memory")


#define MEMUTILS_PRINT_OFFSET(ptr, size) \
    fprintf(stderr, #ptr "=%p,offset=%ld,time=%llu,size=%d\n", (void*)(ptr), get_stack_offset((ptr)), measure_access((ptr)), (size))

extern uint32_t fault_id;

// Function to get the physical address of a virtual address
uint64_t get_physical_address(void *virtual_address);

// Function to calculate the offset in pages for the given virtual address
ssize_t get_stack_offset(void *virtual_address);

__attribute__((noinline))
unsigned long long measure_access(void *ptr);

int mtrr_open(void);
int mtrr_page_uncachable(int fd, uint64_t phys);
void mtrr_close(int fd);

#endif // MEMUTILS_H

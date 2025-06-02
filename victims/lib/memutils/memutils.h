// memutils.h
#ifndef MEMUTILS_H
#define MEMUTILS_H

#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>

#include <stdio.h>

#define FLUSH(ptr) \
    __asm__ volatile("clflush (%0); mfence" :: "r"((ptr)) : "memory")

#define MEMUTILS_PRINT_OFFSET(ptr, size) MEMUTILS_PRINT_OFFSET_LABELLED("", ptr, size)
    
#define MEMUTILS_PRINT_OFFSET_LABELLED(label, ptr, size) \
    fprintf(stderr, label "," #ptr "=%p,offset=%ld,phys=0x%lx,time=%llu,size=%ld,tsc=%lu\n", (void*)(ptr), get_stack_offset((ptr)), get_physical_address((ptr)), measure_access((ptr), 1), (long)(size), get_cycle_count())

extern uint32_t fault_id;

// Function to get the physical address of a virtual address
uint64_t get_physical_address(void *virtual_address);

// Function to calculate the offset in pages for the given virtual address
ssize_t get_stack_offset(void *virtual_address);

__attribute__((noinline))
unsigned long long measure_access(void *ptr, unsigned int num_accesses);

int mtrr_open(void);
int mtrr_page_uncachable(int fd, uint64_t phys);
void mtrr_close(int fd);

/* Inline function to read the 64-bit cycle counter */
static inline uint64_t get_cycle_count(void) {
    uint32_t lo, hi;
    __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
}
#endif // MEMUTILS_H

#include "../include/misc.h"


void flush_cache_line(void* p) {
    asm volatile("clflush (%0)" : : "r"(p) : "memory");
}

void hammer_single(uint64_t _memory) {
    volatile uint64_t *ptr = (volatile uint64_t*)_memory;
    
    // Flush the cache line containing the memory address _memory.
    flush_cache_line((void*)ptr);
    
    // Access the value at the memory address to simulate the load operation.
    // This doesn't exactly replicate moving the value into a specific register like r12 in assembly,
    // but it ensures the memory access.
    volatile uint64_t dummy = *ptr;
    
    // Use dummy to avoid unused variable warnings. This is a common practice when
    // a variable is needed only for its side effects.
    (void)dummy;

    return;
}

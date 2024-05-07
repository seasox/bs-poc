
#include "../include/ptcont.h"
#include "../include/misc.h"
#include "../include/drama.h"

struct addr_pair {
    uint64_t phys_addr;
    uint8_t *virt_addr;
};

// Comparison function for qsort
int compare_phys_addr(const void *a, const void *b) {
    uint64_t addr_a = ((struct addr_pair *)a)->phys_addr;
    uint64_t addr_b = ((struct addr_pair *)b)->phys_addr;
    return (addr_a > addr_b) - (addr_a < addr_b);
}

struct addr_space *ptcont(uint8_t *buffer) {
    struct addr_pair addr_pairs[PAGE_COUNT];
    struct addr_space *ret = malloc(sizeof(struct addr_space));
    ret->memory_addresses = malloc(sizeof(uint8_t *) * PAGE_COUNT);
    ret->length = PAGE_COUNT;

    for (int k = 0; k < PAGE_COUNT; k++) {
        uint64_t virt = (uint64_t)&buffer[k * PAGE_SIZE];
        uint64_t phys = get_physical_addr(virt);
        addr_pairs[k].phys_addr = phys & ~0xFFF; // Zero out the last 12 bits
        addr_pairs[k].virt_addr = &buffer[k * PAGE_SIZE];
    }

    // Sort the addr_pairs array based on physical addresses
    qsort(addr_pairs, PAGE_COUNT, sizeof(struct addr_pair), compare_phys_addr);

    // Populate the return structure with sorted virtual addresses
    for (int i = 0; i < PAGE_COUNT; i++) {
        ret->memory_addresses[i] = addr_pairs[i].virt_addr;
    }
    log_ptcont(ret);
    return ret;
}


void log_ptcont(struct addr_space *return_bank) {
    const char* directory = "memory_profiling";
    const char* filename = "memory_profiling/logs/ptcont.csv";

    // Check if the directory exists, if not create it
    struct stat st = {0};
    if (stat(directory, &st) == -1) {
        if (mkdir(directory, 0700) == -1) {
            perror("Error creating directory");
            return;
        }
    }

    // Attempt to open the file, creating it if it doesn't exist
    FILE *bank_file = fopen(filename, "w");
    if (!bank_file) {
        perror("Error opening Row Conflict log");
        return;
    }

    // Write the header to the file
    fprintf(bank_file, "vaddr,physaddr,bank,row\n");

    // Loop through the addresses in return_bank and log the details
    for (int i = 0; i < return_bank->length; i++) {
        uint64_t phys_addr = get_physical_addr((uint64_t)return_bank->memory_addresses[i]);
        int bank = phys_2_dram(phys_addr).bank;
        int row = phys_2_dram(phys_addr).row;
        fprintf(bank_file, "0x%lx,0x%lx,%d,%d\n", (uint64_t)return_bank->memory_addresses[i], phys_addr, bank, row);
    }

    // If root, change file permissions to make it writable by non-root
    if (getuid() == 0) {
        if (chmod(filename, 0664) == -1) { // Adjusted permissions to read & write by owner and group, read by others
            perror("Error setting file permissions");
        }
    }

    // Close the file
    fclose(bank_file);
}
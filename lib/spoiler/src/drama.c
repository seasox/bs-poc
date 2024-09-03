#include "../include/drama.h"
#include "../include/misc.h"

DRAMLayout     g_mem_layout = {{{0x2040,0x44000,0x88000,0x110000,0x220000}, 5}, 0xffffc0000, ((1<<13)-1)}; // works on Mayhem system


uint64_t get_dram_row(uint64_t p_addr)
{
	return (p_addr & g_mem_layout.
		row_mask) >> __builtin_ctzl(g_mem_layout.row_mask); // __builtin_ctzl(g_mem_layout.row_mask) = 18 bits
}

uint64_t get_dram_col(uint64_t p_addr)
{
	return (p_addr & g_mem_layout.
		col_mask) >> __builtin_ctzl(g_mem_layout.col_mask);
}

DRAMAddr phys_2_dram(uint64_t p_addr)
{

	DRAMAddr res = { 0, 0, 0 };
	for (int i = 0; i < g_mem_layout.h_fns.len; i++) {
		res.bank |=
		    (__builtin_parityl(p_addr & g_mem_layout.h_fns.lst[i]) <<
		     i);
	}

	res.row = get_dram_row(p_addr);
	res.col = get_dram_col(p_addr);

	return res;
}


// Comparator function to sort by bank
int compare_by_bank(const void *a, const void *b) {
    const AddrMapping *addr1 = a;
    const AddrMapping *addr2 = b;
    if (addr1->dram_addr.bank < addr2->dram_addr.bank) return -1;
    if (addr1->dram_addr.bank > addr2->dram_addr.bank) return 1;
    return 0;
}


// Comparator function for sorting
int compare_by_row(const void *a, const void *b) {
    const AddrMapping *addr1 = a;
    const AddrMapping *addr2 = b;
    if (addr1->dram_addr.row < addr2->dram_addr.row) return -1;
    if (addr1->dram_addr.row > addr2->dram_addr.row) return 1;
    return 0;
}

// return array containing start and end of a physically contiguous memory region
struct addr_space *getContinuousDrama(uint8_t *buffer) {
    AddrMapping mappings[PAGE_COUNT];

    // Populate mappings
    for (int k = 0; k < PAGE_COUNT; k++) {
        mappings[k].phys_addr = get_physical_addr((uint64_t)&buffer[k * PAGE_SIZE]) & 0xfffff000;
        mappings[k].virt_addr = (uint64_t)&buffer[k * PAGE_SIZE];
        mappings[k].dram_addr = phys_2_dram(mappings[k].phys_addr);
		// printf("vaddr: %p, paddr: %p, bank: %d, row: %d\n", mappings[k].virt_addr, mappings[k].phys_addr, mappings[k].dram_addr.bank, mappings[k].dram_addr.row);
    }

    qsort(mappings, PAGE_COUNT, sizeof(AddrMapping), compare_by_bank);

    // Then, sort each bank group by row
    int start = 0;
    for (int i = 1; i <= PAGE_COUNT; i++) {
        if (i == PAGE_COUNT || mappings[i].dram_addr.bank != mappings[start].dram_addr.bank) {
            qsort(mappings + start, i - start, sizeof(AddrMapping), compare_by_row);
            start = i;
        }
    }

    struct addr_space *ret = malloc(sizeof(struct addr_space));
	if (ret == NULL) {
		// Handle allocation failure
		return NULL; // or some error handling
	}
    ret->memory_addresses = NULL;
    ret->length = 0;

	int max_length = 0, max_start = 0;
	int current_length = 1, current_start = 0;
	uint64_t current_bank = mappings[0].dram_addr.bank;

	for (int k = 1; k < PAGE_COUNT; k++) {
		// Check for continuous rows (same or increment by 1) in the same bank
		if (mappings[k].dram_addr.bank == current_bank &&
			(mappings[k].dram_addr.row == mappings[k - 1].dram_addr.row ||
			mappings[k].dram_addr.row == mappings[k - 1].dram_addr.row + 1)) {
			current_length++;
		} else {
			// Check if the current sequence is the longest so far
			if (current_length > max_length) {
				max_length = current_length;
				max_start = current_start;
			}
			current_length = 1;
			current_start = k;
			current_bank = mappings[k].dram_addr.bank;
		}
	}

	// Check for a continuous chunk including the last element
	if (current_length > max_length) {
		max_length = current_length;
		max_start = current_start;
	}

	// Allocate and set memory_addresses
	if (max_length > 0) {
		ret->memory_addresses = malloc(max_length * sizeof(uint8_t*));
		ret->length = max_length;
		for (int i = 0; i < max_length; i++) {
			ret->memory_addresses[i] = (uint8_t *)mappings[max_start + i].virt_addr;
		}
	} else {
		ret->memory_addresses = NULL;
		ret->length = 0;
	}


	// print all physical addresses in mappings
    // Populate mappings
    for (int k = 0; k < PAGE_COUNT; k++) {
		// printf("vaddr: %p, paddr: %p, bank: %d, row: %d\n", mappings[k].virt_addr, mappings[k].phys_addr, mappings[k].dram_addr.bank, mappings[k].dram_addr.row);
    }
	
	// Check and print if ret is not empty
    if (ret->length < 0) {
    //     printf("Found a continuous chunk with length: %d\n", ret->length);
    //     printf("First address in the chunk: %p\n", ret->memory_addresses[0]);
    //     // Optionally, print more details or other addresses
    // } else {
        printf("No continuous chunk found.\n");
    }
	log_drama(ret);
    return ret;
}

void log_drama(struct addr_space *return_bank) {
    const char* directory = "memory_profiling";
    const char* filename = "memory_profiling/logs/drama.csv";

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
        perror("Error opening Drama Log file");
        return;
    }

    // Write the header to the file
    fprintf(bank_file, "vaddr,physaddr,bank,row\n");

	printf("return_bank->length: %d\n", return_bank->length);

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
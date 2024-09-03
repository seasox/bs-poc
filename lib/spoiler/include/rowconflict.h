#include <stdint.h>			// uint64_t"

struct addr_space* rowconflict(struct addr_space * continuous_buffer);
int getIndex(uint64_t addr, uint8_t *myBank, int bankLength);
int get_index_of_address(uint64_t current_flippy, struct addr_space *myBank);
void log_rowconflict(struct addr_space *return_bank);
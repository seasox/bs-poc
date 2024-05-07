#include <stdint.h>			// uint64_t



// DRAMA definitions from TRRespass
typedef struct {
	/* bank is a simplified addressing of <ch,dimm,rk,bg,bk>
	   where all this will eventually map to a specific bank */
	uint64_t bank;
	uint64_t row;
	uint64_t col;
} DRAMAddr;

#define HASH_FN_CNT 6
typedef struct {
	uint64_t lst[HASH_FN_CNT];
	uint64_t len;
} AddrFns;

typedef struct {
	AddrFns h_fns;
	uint64_t row_mask;
	uint64_t col_mask;
} DRAMLayout;

typedef struct {
    DRAMAddr dram_addr;
    uint64_t phys_addr;
    uint64_t virt_addr;
} AddrMapping;


// From TRRespass/DRAMA
uint64_t get_dram_row(uint64_t p_addr);
uint64_t get_dram_col(uint64_t p_addr);
DRAMAddr phys_2_dram(uint64_t p_addr);
struct addr_space *getContinuousDrama(uint8_t *buffer);
void log_drama(struct addr_space *return_bank);
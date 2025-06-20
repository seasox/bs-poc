#include <stddef.h> // size_t
#include <stdint.h> // uint64_t
struct addr_space *spoiler(uint8_t *buffer);
void process_buff(struct addr_space *buff, uint64_t *measurementBuffer);
void log_spoiler(uint8_t *buffer, uint64_t *measurementBuffer, uint64_t *diffBuffer);
uint64_t *extract_diffBuffer(uint8_t *buffer, uint64_t profile_size, uint64_t *size);
uint64_t *kmeans(uint64_t *data, int n, int k, int max_iterations, uint64_t *clusters);
struct addr_space *auto_spoiler(uint8_t *buffer, size_t buf_size);

uint8_t **memory_addresses(const struct addr_space *addr);
int length(const struct addr_space *addr);

struct measurement *spoiler_measure(uint8_t *write, size_t write_buf_size, uint8_t *read);
void spoiler_free(struct measurement *m);

const uint64_t *measurements(const struct measurement *m);
const uint64_t *diffs(const struct measurement *m);

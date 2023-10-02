#include <stddef.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define PAGE_SIZE 4096
#define CANDIDATE_INDEX 2048
#define DETECTION_WINDOW_SIZE 10
#define ROUNDS 100

static inline uint64_t rdtsc(void) /*__attribute__((always_inline))*/;

static inline uint64_t rdtsc(void) {
    uint64_t val;
    unsigned int h, l;

    asm volatile("rdtsc" : "=a" (l), "=d" (h));

    return ((uint32_t)l)|(((uint64_t)h)<<32);
}

int alg1(const unsigned int page_count, const unsigned int window_size, /* OUT */ uint16_t **measures) {
    if (measures == NULL) {
        return 1;
    }
    size_t buf_len = page_count * PAGE_SIZE/4;
    uint32_t *buf = malloc(sizeof(uint32_t) * buf_len);
    memset(buf, 0, buf_len);
    if (buf == NULL || measures == NULL) {
        perror("malloc");
        return -1;
    }
    for (size_t p = window_size; p < page_count; ++p) {
        size_t total = 0;
        for (size_t r = 0; r < ROUNDS; ++r) {   
            // store
            for (int i = window_size; i >= 0; --i) {
                buf[(p-i) * 1024] = 0;
            }
            buf[p * 1024] = 0;

            // measure loads
            uint64_t before = rdtsc();
            uint32_t val = buf[CANDIDATE_INDEX]; // todo check if 20 LSB phys eq if peak
            uint64_t after = val;
            after += rdtsc();
            total += after - before - val;
        }
        (*measures)[p] = total / ROUNDS;
    }

    return 0;
}

int main(char **argv, int argc) {
    unsigned int page_count = 5000;
    uint16_t *measures = malloc(page_count * sizeof(uint16_t));
    memset(measures, 0, page_count);
    int ret = alg1(page_count, 64, &measures);
    if (ret != 0)
        return ret;
    for (int i = 0; i < page_count; ++i) {
        printf("%u\n", measures[i]);
    }
    return 0;
}
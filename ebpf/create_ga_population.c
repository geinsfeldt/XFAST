#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include <string.h>
#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "xdp_miniga.h"

// Initializes a population of individuals in a BPF map
int init_population(const char *map_path, int pop_size, int feature_bits) {

    int map_fd = bpf_obj_get(map_path);
    if (map_fd < 0) {
        perror("Error opening population map");
        return 1;
    }

    int feature_bytes = (feature_bits + 7) / 8;

    srand(time(NULL));  // Random seed based on current time

    for (uint32_t i = 0; i < (uint32_t)pop_size; i++) {
        struct individual ind = {0};
        for (int j = 0; j < feature_bytes; j++) {
            ind.genes[j] = rand() % 256;  // Random byte value
        }

        // Clear extra bits if feature_bits is not a multiple of 8
        int extra_bits = (feature_bytes * 8) - feature_bits;
        if (extra_bits > 0) {
            uint8_t mask = 0xFF << extra_bits;
            ind.genes[feature_bytes - 1] &= ~mask;
        }

        if (bpf_map_update_elem(map_fd, &i, &ind, BPF_ANY) != 0) {
            perror("Error updating population map");
            return 1;
        }
    }

    printf("Initialized population with %d individuals, %d bits each.\n", pop_size, feature_bits);
    return 0;
}

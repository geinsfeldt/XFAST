#include "xdp_common.h"
#include <stdbool.h>
#ifndef __XDP_MINIGA_H
#define __XDP_MINIGA_H

// Define constants for the genetic algorithm
#define POPULATION_MAP_PATH "/sys/fs/bpf/population"
#define METADATA_MAP_PATH "/sys/fs/bpf/meta_map"
#define MAX_THRESHOLD_MAP_PATH "/sys/fs/bpf/feature_threshold_max"
#define MIN_THRESHOLD_MAP_PATH "/sys/fs/bpf/feature_threshold_min"
#define FITNESS_MAP_PATH "/sys/fs/bpf/fitness_map"
#define HIT_MAP_PATH "/sys/fs/bpf/feature_hit_map"
#define PROB_CROSSOVER 80  // Crossover probability (0 a 100)
#define PROB_MUTATION 10   // Mutation probability (0 a 100)
#define POPULATION_SIZE 32
#define FITNESS_TARGET 98 // Target fitness score for the genetic algorithm
#define MAX_GENERATIONS 300 // Maximum number of generations for the genetic algorithm
#define NUMBER_FEATURES 21
#define GENE_BYTES ((NUMBER_FEATURES + 7) / 8)
#define FEATURE_WEIGHT 3 // Weight for number of features in the fitness function

struct individual {
    __u8 genes[GENE_BYTES]; // each gene is 1 bit, so we need bytes to store them
};

struct threshold_config {
    __u32 feature_idx;
    __u64 min;
    __u64 max;
};

struct metadata {
    __u32 generation;
    bool done_selection;
    bool done_crossover;
    bool done_mutation;
    bool stop;
    __u32 elite1, elite2;
    __u32 elite1_score, elite2_score;
};

#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <arpa/inet.h>
#include <time.h>
#include "uthash.h"

#include "xdp_common.h"
#include "xdp_miniga.h"
#include "create_ga_population.c"

// Delets existing BPF maps
static void map_delete() 
{
    if (unlink(FLOW_MAP_PATH) == 0) {
		printf("Flow map unpinned and deleted.\n");
    }
    if (unlink(FEATURE_CONFIG_MAP_PATH) == 0) {
        printf("Config map unpinned and deleted.\n");
    }
    if (unlink(METADATA_MAP_PATH) == 0) {
        printf("Metadata map unpinned and deleted.\n");
    }
    if (unlink(POPULATION_MAP_PATH) == 0) {
        printf("Population map unpinned and deleted.\n");
    }
    if (unlink(MIN_THRESHOLD_MAP_PATH) == 0) {
        printf("Min threshold map unpinned and deleted.\n");
    }
    if (unlink(MAX_THRESHOLD_MAP_PATH) == 0) {
        printf("Max threshold map unpinned and deleted.\n");
    }
    if (unlink(FITNESS_MAP_PATH) == 0) {
        printf("Fitness map unpinned and deleted.\n");
    }
    if (unlink(HIT_MAP_PATH) == 0) {
        printf("Hit map unpinned and deleted.\n");
    }
    if (unlink(XDP_TIMES_MAP_PATH) == 0) {
        printf("XDP times map unpinned and deleted.\n");
    }
}

// Print flow statistics
void print_flow_stats(struct flow_key *key, struct flow_stats *stats) {
    
    char src_ip[INET6_ADDRSTRLEN], dst_ip[INET6_ADDRSTRLEN];
    
    if (key->ip_version == 4) {
        inet_ntop(AF_INET, &key->src_ip.v4, src_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &key->dst_ip.v4, dst_ip, INET_ADDRSTRLEN);
    } else {
        inet_ntop(AF_INET6, &key->src_ip.v6, src_ip, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &key->dst_ip.v6, dst_ip, INET6_ADDRSTRLEN);
    }

    printf("Flow: %s:%d -> %s:%d (IPv%d, Proto: %d)\n", 
            src_ip, ntohs(key->src_port), dst_ip, ntohs(key->dst_port),
            key->ip_version, key->protocol);
    printf("  Packets: %llu\n", stats->packets);
    printf("  Bytes: %llu\n", stats->bytes);
    printf("  Duration: %.3f seconds\n", (double) stats->duration / FEATURE_PRECISION);
    printf("  Packets per second: %.3f\n", (double) stats->pps / FEATURE_PRECISION);
    printf("  Bytes per second: %.3f\n", (double) stats->bps / FEATURE_PRECISION);
    printf("  Inter arrivel time: %.3f\n", (double) stats->iat / FEATURE_PRECISION);
    printf("  Max packet length: %llu\n", stats->max_pkt_len);
    printf("  Min packet length: %llu\n", stats->min_pkt_len);
    printf("  Max packet per second: %.3f\n", (double) stats->max_pps / FEATURE_PRECISION);
    printf("  Min packet per second: %.3f\n", (double) stats->min_pps / FEATURE_PRECISION);
    printf("  Max bytes per second: %.3f\n", (double) stats->max_bps / FEATURE_PRECISION);
    printf("  Min bytes per second: %.3f\n", (double) stats->min_bps / FEATURE_PRECISION);
    printf("  Max inter arrivel time: %.3f\n", (double) stats->max_iat / FEATURE_PRECISION);
    printf("  Min inter arrivel time: %.3f\n", (double) stats->min_iat / FEATURE_PRECISION);
    printf("  Count pps: %.3f\n", (double) stats->count_pps);
    printf("  Count bps: %.3f\n", (double) stats->count_bps);
    printf("  Count iat: %.3f\n", (double) stats->count_iat);
    printf("  Average packet per second: %.3f\n", (double) stats->avg_pps / FEATURE_PRECISION);
    printf("  Average bytes per second: %.3f\n", (double) stats->avg_bps / FEATURE_PRECISION);
    printf("  Average number of bytes: %.3f\n", (double) stats->avg_bpp / FEATURE_PRECISION);
    printf("  Average inter arrivel time: %.3f\n", (double) stats->avg_iat / FEATURE_PRECISION);
    printf("  Variance packet per second: %.3f\n", (double) stats->var_pps / FEATURE_PRECISION);
    printf("  Variance bytes per second: %.3f\n", (double) stats->var_bps / FEATURE_PRECISION);
    printf("  Variance inter arrivel time: %.3f\n", (double) stats->var_iat / FEATURE_PRECISION);

    printf("\n");
}

int main(int argc, char **argv) {
    struct bpf_object *obj;
    int map_fd;
    int map_features_fd;
    int map_metadata_fd;
    __u32 key = 0;
    __u32 feature_mask = FEATURE_MASK;
	char *dev_name = argv[1];
    int err;
	int ifindex;
	int prog_fd;

    // Opens BPF object file
    obj = bpf_object__open("xdp_kern_feature_extract.o");
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "ERROR: opening BPF object file failed\n");
        return 1;
    }

	// Clear existing BPF maps
	map_delete();

	// Load BPF program to kernel
    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "ERROR: loading BPF object file failed\n");
        return 1;
    }

	// Search for the XDP program in the BPF object
	struct bpf_program *prog = bpf_object__find_program_by_name(obj, "xdp_flow_stats");
	if (!prog) {
		fprintf(stderr, "Error finding BPF program in object\n");
		bpf_object__close(obj);
		return 1;
	}

	// Get the file descriptor for the BPF program
	prog_fd = bpf_program__fd(prog);
	if (prog_fd < 0) {
		fprintf(stderr, "Error getting file descriptor for BPF program\n");
		bpf_object__close(obj);
		return 1;
	}

    // Get the interface index from the device name
	ifindex = if_nametoindex(dev_name);
	if (!ifindex) {
		fprintf(stderr, "ERROR: unknown interface %s\n", dev_name);
		return 1;
	}
	
    // Conects the XDP program to the interface
	err = bpf_xdp_attach(ifindex, prog_fd, 0, NULL);
	if (err) {
		fprintf(stderr, "ERROR: attaching XDP program to interface failed\n");
		return 1;
	}

    // Get the file descriptor for the features_config map
    map_features_fd = bpf_object__find_map_fd_by_name(obj, "features_config");
    if (map_features_fd < 0) {
        fprintf(stderr, "ERROR: finding features_config in obj file failed\n");
        return 1;
    }

    // Define the features to extract and their precision
    struct features_config default_config = {
        .features = FEATURE_MASK,
        .precision = FEATURE_PRECISION,
        .timeout = INACTIVE_THRESHOLD,
        .run_selection = true,
        .sampling_rate_ns = 0,
    };

    // Update the feature configuration map with given config
    if (bpf_map_update_elem(map_features_fd, &key, &default_config, BPF_ANY)) {
        fprintf(stderr, "ERROR: updating features_config in obj file failed\n");
        return 1;
    }

    // Get the file descriptor for the metadata map
    map_metadata_fd = bpf_object__find_map_fd_by_name(obj, "meta_map");
    if (map_metadata_fd < 0) {
        fprintf(stderr, "ERROR: finding metadata in obj file failed\n");
        return 1;
    }

    // Define the features to extract and their precision
    struct metadata default_metadata = {
        .generation = 0,
        .done_selection = false,
        .done_crossover = false,
        .done_mutation = false,
        .stop = false,
        .elite1 = 0,
        .elite2 = 0,
        .elite1_score = 0,
        .elite2_score = 0,
    };

    // Start the metadata map with given values
    if (bpf_map_update_elem(map_metadata_fd, &key, &default_metadata, BPF_ANY)) {
        fprintf(stderr, "ERROR: updating metadata in obj file failed\n");
        return 1;
    }

    int fd_min = bpf_obj_get(MIN_THRESHOLD_MAP_PATH);
    int fd_max = bpf_obj_get(MAX_THRESHOLD_MAP_PATH);

    if (fd_min < 0 || fd_max < 0) {
        perror("Error openning thresholds maps");
        return 1;
    }

    // Thresholds for each feature (min and max values)
    // Units: packets, bytes, nanoseconds, bps, etc.
    struct threshold_config thresholds[] = {
        {0, 1, 75},                // FEATURE_PACKETS: number of packets per flow
        {1, 0, 10600},             // FEATURE_BYTES: total bytes per flow (64B to 5MB)
        {2, 0, 2900},              // FEATURE_MAX_PKT_LEN: max packet size (Ethernet)
        {3, 0, 85},                // FEATURE_MIN_PKT_LEN: min packet size
        {4, 100000, 118000000000}, // FEATURE_DURATION: 1ms to 60s (nanoseconds)
        {5, 0.03, 19000},          // FEATURE_PPS: packets per second
        {6, 0, 75000},             // FEATURE_BPS: bytes per second (1KB/s to 10MB/s)
        {7, 0, 500000000},         // FEATURE_IAT: inter-arrival time (1µs to 0.5s)
        {8, 0, 19000},             // FEATURE_MAX_PPS: maximum packets per second
        {9, 0, 10},                // FEATURE_MIN_PPS: minimum packets per second
        {10, 0, 75000},            // FEATURE_MAX_BPS: max bytes per second
        {11, 0, 10},               // FEATURE_MIN_BPS: min bytes per second
        {12, 0, 70000000},         // FEATURE_MAX_IAT: max inter-arrival time
        {13, 0, 60000000},         // FEATURE_MIN_IAT: min inter-arrival time
        {14, 0, 4000},             // FEATURE_AVG_PPS: average packets per second
        {15, 0, 10000},            // FEATURE_AVG_BPS: average bytes per second
        {16, 0, 700},              // FEATURE_AVG_BPP: average bytes per packet
        {17, 0, 64000000},         // FEATURE_AVG_IAT: average inter-arrival time
        {18, 0, 560000000000000},  // FEATURE_VAR_PPS: variance of PPS
        {19, 0, 560000000000000},  // FEATURE_VAR_BPS: variance of BPS
        {20, 0, 560000000000000},  // FEATURE_VAR_IAT: variance of IAT
    };

    for (int i = 0; i < sizeof(thresholds) / sizeof(thresholds[0]); i++) {
        __u32 idx = thresholds[i].feature_idx;
        __u64 min = thresholds[i].min;
        __u64 max = thresholds[i].max;

        if (bpf_map_update_elem(fd_min, &idx, &min, 0) != 0) {
            perror("Error updating min threshold map");
        }

        if (bpf_map_update_elem(fd_max, &idx, &max, 0) != 0) {
            perror("Error updating max threshold map");
        }
    }

    // Populate the population map with individuals
    init_population(POPULATION_MAP_PATH, POPULATION_SIZE, NUMBER_FEATURES);

    // Get the file descriptor of the prog_array map
    int prog_array_fd = bpf_object__find_map_fd_by_name(obj, "prog_array");
    if (prog_array_fd < 0) {
        fprintf(stderr, "ERROR: finding prog_array in obj file failed\n");
        return 1;
    }

    // Map program sections to their indices
    struct {
        const char *name;
        __u32 index;
    } programs[] = {
        {"xdp_selection", 1},  // PROG_SELECTION
        {"xdp_crossover", 2},  // PROG_CROSSOVER
        {"xdp_mutation",  3},  // PROG_MUTATION
    };

    for (int i = 0; i < sizeof(programs)/sizeof(programs[0]); i++) {
        struct bpf_program *prog = bpf_object__find_program_by_name(obj, programs[i].name);
        if (!prog) {
            fprintf(stderr, "ERROR: program '%s' not found\n", programs[i].name);
            return 1;
        }

        int prog_fd = bpf_program__fd(prog);
        if (prog_fd < 0) {
            fprintf(stderr, "ERROR: getting fd for program '%s'\n", programs[i].name);
            return 1;
        }

        // Update prog_array at given index with the program fd
        if (bpf_map_update_elem(prog_array_fd, &programs[i].index, &prog_fd, BPF_ANY) < 0) {
            fprintf(stderr, "ERROR: updating prog_array for '%s'\n", programs[i].name);
            return 1;
        }

        printf("Tail call program '%s' mapped to index %u\n", programs[i].name, programs[i].index);
    }


    // Get the file descriptor for the flow_map
    map_fd = bpf_object__find_map_fd_by_name(obj, "flow_map");
    if (map_fd < 0) {
        fprintf(stderr, "ERROR: finding flow_map in obj file failed\n");
        return 1;
    }

    printf("Map FD: %d\n", map_fd);

    time_t start_time = time(NULL);  // Record program start time
    bool feature_selection_enabled = false;

    // Principal loop to read and print flow statistics
    while (1) {
        struct flow_key keys[MAX_ENTRIES];
        struct flow_stats values[MAX_ENTRIES];
        __u32 key_size = sizeof(struct flow_key);
        __u32 value_size = sizeof(struct flow_stats);
        __u32 num_entries = MAX_ENTRIES;
        void *prev_key = NULL;

        // Enable feature selection after N seconds
        
        if (!feature_selection_enabled && difftime(time(NULL), start_time) >= 10) {
            default_config.run_selection = true;
            if (bpf_map_update_elem(map_features_fd, &key, &default_config, BPF_ANY)) {
                fprintf(stderr, "ERROR: enabling feature selection failed\n");
            } else {
                printf("Feature selection activated after 10 seconds.\n");
                feature_selection_enabled = true;
            }
        }

        // Check if the map is empty
        err = bpf_map_get_next_key(map_fd, prev_key, &keys[0]);
        if (err) {
            if (errno == ENOENT) {
                printf("Map is empty\n");
            } else {
                fprintf(stderr, "Error getting first key: %d (%s)\n", err, strerror(errno));
            }
            sleep(1);
            continue;
        }

        // For each entry in the map, look up the flow statistics
        for (int i = 0; i < MAX_ENTRIES; i++) {

            // Get value for the current key in flow_map
            err = bpf_map_lookup_elem(map_fd, &keys[i], &values[i]);
            if (err) {
                if (errno == ENOENT) {
                    break;  // No more entries
                } else {
                    fprintf(stderr, "Error looking up element %d: %d (%s)\n", i, err, strerror(errno));
                    break;
                }
            }

            // Print the flow statistics
            print_flow_stats(&keys[i], &values[i]);

            prev_key = &keys[i];

            // Check if there are more entries in the map
            err = bpf_map_get_next_key(map_fd, prev_key, &keys[i+1]);
            if (err) {
                if (errno == ENOENT) {
                    break;  // No more entries
                } else {
                    fprintf(stderr, "Error getting next key: %d (%s)\n", err, strerror(errno));
                    break;
                }
            }
        }

        sleep(1);  // Update every second
    }
    
    return 0;
}

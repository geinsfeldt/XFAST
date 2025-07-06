#include "uthash.h"
#ifndef __XDP_COMMON_H
#define __XDP_COMMON_H

// Define global constants configurations for feature extraction
#define NS_TO_SECOND 1000000000 // Conversion factor from nanoseconds to seconds
#define INACTIVE_THRESHOLD 300000000000
#define MAX_ENTRIES 10000
#define FLOW_MAP_PATH "/sys/fs/bpf/flow_map"
#define FEATURE_CONFIG_MAP_PATH "/sys/fs/bpf/features_config"
#define XDP_TIMES_MAP_PATH "/sys/fs/bpf/xdp_times_map"
#define FEATURE_MASK 0b00000000000100110011000011111111
#define FEATURE_PRECISION 1000

// Define union of IPv4 and IPv6 addresses
union ip_addr {
    __be32 v4;
    __be32 v6[4];
};

// Define the struct that identifies the flow
struct flow_key {
    union ip_addr src_ip;
    union ip_addr dst_ip;
    __be16 src_port;
    __be16 dst_port;
    __u8 protocol;
    __u8 ip_version;
};

// Define the struct to configure features
struct features_config {
    __u32 features;
    __u32 sampling_rate_ns;
    __u64 precision;
    __u64 timeout;
    bool run_selection;
};

// Define the features of the flow
#define FEATURE_PACKETS (1 << 0)
#define FEATURE_BYTES (1 << 1)
#define FEATURE_MAX_PKT_LEN (1 << 2)
#define FEATURE_MIN_PKT_LEN (1 << 3)
#define FEATURE_DURATION (1 << 4)
#define FEATURE_PPS (1 << 5)
#define FEATURE_BPS (1 << 6)
#define FEATURE_IAT (1 << 7)
#define FEATURE_MAX_PPS (1 << 8)
#define FEATURE_MIN_PPS (1 << 9)
#define FEATURE_MAX_BPS (1 << 10)
#define FEATURE_MIN_BPS (1 << 11)
#define FEATURE_MAX_IAT (1 << 12)
#define FEATURE_MIN_IAT (1 << 13)
#define FEATURE_AVG_PPS (1 << 14)
#define FEATURE_AVG_BPS (1 << 15)
#define FEATURE_AVG_BPP (1 << 16)
#define FEATURE_AVG_IAT (1 << 17)
#define FEATURE_VAR_PPS (1 << 18)
#define FEATURE_VAR_BPS (1 << 19)
#define FEATURE_VAR_IAT (1 << 20)

// Define the struct with the flow features data
struct flow_stats {
    __u64 packets;
    __u64 bytes;
    __u64 start_time; // auxiliar to duration
    __u64 last_time; // auxiliar to inter arrivel time
    __u64 max_pkt_len;
    __u64 min_pkt_len;
    __u64 duration;
    __u64 pps;
    __u64 bps;
    __u64 iat;
    __u64 max_pps;
    __u64 min_pps;
    __u64 max_bps;
    __u64 min_bps;
    __u64 max_iat;
    __u64 min_iat;
    __u64 count_pps; // auxiliar to average
    __u64 count_bps; // auxiliar to average
    __u64 count_iat; // auxiliar to average
    __u64 avg_pps;
    __u64 avg_bps;
    __u64 avg_bpp;
    __u64 avg_iat;
    __u64 m2_pps; // auxiliar to variance
    __u64 m2_bps; // auxiliar to variance
    __u64 m2_iat; // auxiliar to variance
    __u64 var_pps;
    __u64 var_bps;
    __u64 var_iat;
};

struct exec_stats {
    __u64 cnt;
    __u64 sum_ns;
    __u64 exec_start_ns;
};

#endif

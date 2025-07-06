#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <arpa/inet.h> 
#include <stdbool.h>

#include "xdp_common.h"
#include "xdp_miniga.h"

// Program Index
#define PROG_SELECTION 1
#define PROG_CROSSOVER 2
#define PROG_MUTATION 3

enum proc_status {
    PROC_OK = 0,
    PROC_ERR = 1,
};

// Define map with flows data
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, struct flow_key);
    __type(value, struct flow_stats);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} flow_map SEC(".maps");

// Define map with configurations
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct features_config);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} features_config SEC(".maps");

// Population map
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, POPULATION_SIZE);
    __type(key, __u32);
    __type(value, struct individual);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} population SEC(".maps");

// Metadata map
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct metadata);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} meta_map SEC(".maps");

// Fitness map
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, POPULATION_SIZE);
    __type(key, __u32);
    __type(value, __u64);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} fitness_map SEC(".maps");

// Hit threshold map for features
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, NUMBER_FEATURES);
    __type(key, __u32);
    __type(value, __u32);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} feature_hit_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, NUMBER_FEATURES);
    __type(key, __u32);
    __type(value, __u64);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} feature_threshold_min SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, NUMBER_FEATURES);
    __type(key, __u32);
    __type(value, __u64);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} feature_threshold_max SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct exec_stats);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} xdp_times_map SEC(".maps");

// Program array for tail calls
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 5);
    __type(key, __u32);
    __type(value, __u32);
} prog_array SEC(".maps");

static __always_inline int get_gene(const struct individual *ind, __u32 idx) {
    if (idx >= NUMBER_FEATURES)
        return 0;

    __u32 byte = idx / 8;
    __u32 bit = idx % 8;

    if (byte < GENE_BYTES) {
        if (byte == 0)
            return (ind->genes[0] >> bit) & 0x1;
        else if (byte == 1)
            return (ind->genes[1] >> bit) & 0x1;
        else if (byte == 2)
            return (ind->genes[2] >> bit) & 0x1;
    }

    return 0;
}

static __always_inline void set_gene(struct individual *ind, __u32 idx, int value) {
    if (idx >= NUMBER_FEATURES)
        return;

    __u32 byte = idx / 8;
    __u32 bit = idx % 8;

    if (byte < GENE_BYTES) {
        if (byte == 0) {
            if (value)
                ind->genes[0] |= (1 << bit);
            else
                ind->genes[0] &= ~(1 << bit);
        } else if (byte == 1) {
            if (value)
                ind->genes[1] |= (1 << bit);
            else
                ind->genes[1] &= ~(1 << bit);
        } else if (byte == 2) {
            if (value)
                ind->genes[2] |= (1 << bit);
            else
                ind->genes[2] &= ~(1 << bit);
        }
    }
}

static __always_inline void flip_gene(struct individual *ind, __u32 idx) {
    if (idx >= NUMBER_FEATURES)
        return;

    __u32 byte = idx / 8;
    __u32 bit = idx % 8;

    // Verify if the byte index is within bounds
    if (byte < GENE_BYTES) {
        // Access the specific byte and flip the bit
        if (byte == 0) {
            ind->genes[0] ^= (1 << bit);
        } else if (byte == 1) {
            ind->genes[1] ^= (1 << bit);
        } else if (byte == 2) {
            ind->genes[2] ^= (1 << bit);
        }
    }
}

// Check features thresholds for hits
static __always_inline void check_feature_thresholds(struct flow_stats *stats) {
    if (!stats) return;

    __u64 val = 0;

    #pragma unroll
    for (int i = 0; i < NUMBER_FEATURES; i++) {
        __u32 key = i;
        switch (key) {
            case FEATURE_PACKETS:      val = stats->packets; break;
            case FEATURE_BYTES:        val = stats->bytes; break;
            case FEATURE_MAX_PKT_LEN:  val = stats->max_pkt_len; break;
            case FEATURE_MIN_PKT_LEN:  val = stats->min_pkt_len; break;
            case FEATURE_DURATION:     val = stats->duration; break;
            case FEATURE_PPS:          val = stats->pps; break;
            case FEATURE_BPS:          val = stats->bps; break;
            case FEATURE_IAT:          val = stats->iat; break;
            case FEATURE_MAX_PPS:      val = stats->max_pps; break;
            case FEATURE_MIN_PPS:      val = stats->min_pps; break;
            case FEATURE_MAX_BPS:      val = stats->max_bps; break;
            case FEATURE_MIN_BPS:      val = stats->min_bps; break;
            case FEATURE_MAX_IAT:      val = stats->max_iat; break;
            case FEATURE_MIN_IAT:      val = stats->min_iat; break;
            case FEATURE_AVG_PPS:      val = stats->avg_pps; break;
            case FEATURE_AVG_BPS:      val = stats->avg_bps; break;
            case FEATURE_AVG_BPP:      val = stats->avg_bpp; break;
            case FEATURE_AVG_IAT:      val = stats->avg_iat; break;
            case FEATURE_VAR_PPS:      val = stats->var_pps; break;
            case FEATURE_VAR_BPS:      val = stats->var_bps; break;
            case FEATURE_VAR_IAT:      val = stats->var_iat; break;
        }

        __u64 *min_val = bpf_map_lookup_elem(&feature_threshold_min, &key);
        __u64 *max_val = bpf_map_lookup_elem(&feature_threshold_max, &key);
        
        if (!min_val || !max_val) continue;

        if (val < *min_val || val > *max_val) {
            __u32 *hit = bpf_map_lookup_elem(&feature_hit_map, &key);
            if (hit) __sync_fetch_and_add(hit, 1);
        }
    }
}

// Process packet extracting and calculating features
static __always_inline enum proc_status process_ip(struct xdp_md *ctx, struct flow_key *flow,
     __u8 ip_version, struct features_config *config) {

    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    __u64 pkt_len = data_end - data;
    __u64 last_arrivel;
    __s64 delta_pps = 0, delta_bps = 0, delta_iat = 0;
    __s64 spps = 0, sbps = 0, siat = 0;
    __u64 now = bpf_ktime_get_ns();

    flow->ip_version = ip_version;

    // Case IPv4
    if (ip_version == 4) {
        // Check if packet have header IPv4
        struct iphdr *ip = (void *)(eth + 1);
        if ((void *)(ip + 1) > data_end) {
            bpf_printk("error ipv4 header");
            return PROC_ERR;
        }

        // Extract header info
        flow->src_ip.v4 = ip->saddr;
        flow->dst_ip.v4 = ip->daddr;
        flow->protocol = ip->protocol;

        // Case protocol TCP
        if (ip->protocol == 6) {
            // Check ik packet have TCP header
            struct tcphdr *tcp = (void *)(ip + 1);
            if ((void *)(tcp + 1) > data_end) {
                bpf_printk("error ipv4 tcp header");
                return PROC_ERR;
            }
            // Extract ports info
            flow->src_port = tcp->source;
            flow->dst_port = tcp->dest;
        // Case protocol UDP
        } else if (ip->protocol == 17) {
            // Check ik packet have UDP header
            struct udphdr *udp = (void *)(ip + 1);
            if ((void *)(udp + 1) > data_end) {
                bpf_printk("error ipv4 udp header");
                return PROC_ERR;
            }
            // Extract ports info
            flow->src_port = udp->source;
            flow->dst_port = udp->dest;
        // Case other protocol
        } else {
            bpf_printk("error ipv4 transport protocol");
            return PROC_ERR;
        }
    // Case IPv6
    } else if (ip_version == 6) {
        // Check if packet have IPv6 header
        struct ipv6hdr *ip6 = (void *)(eth + 1);
        if ((void *)(ip6 + 1) > data_end) {
            bpf_printk("error ipv6 header");
            return PROC_ERR;
        }
        // Extract header info
        __builtin_memcpy(flow->src_ip.v6, ip6->saddr.in6_u.u6_addr32, sizeof(flow->src_ip.v6));
        __builtin_memcpy(flow->dst_ip.v6, ip6->daddr.in6_u.u6_addr32, sizeof(flow->dst_ip.v6));
        flow->protocol = ip6->nexthdr;

        // Case protocol TCP
        if (ip6->nexthdr == 6) {
            // Check ik packet have TCP header
            struct tcphdr *tcp = (void *)(ip6 + 1);
            if ((void *)(tcp + 1) > data_end) {
                bpf_printk("error ipv6 tcp header");
                return PROC_ERR;
            }
            // Extract ports info
            flow->src_port = tcp->source;
            flow->dst_port = tcp->dest;
        // Case protocol UDP
        } else if (ip6->nexthdr == 17) {
            // Check ik packet have UDP header
            struct udphdr *udp = (void *)(ip6 + 1);
            if ((void *)(udp + 1) > data_end) {
                bpf_printk("error ipv6 udp header");
                return PROC_ERR;
            }
            // Extract ports info
            flow->src_port = udp->source;
            flow->dst_port = udp->dest;
        // Case other protocol
        } else {
            bpf_printk("error ipv6 transport protocol");
            return PROC_ERR;
        }
    } else {
        bpf_printk("error network protocol");
        return PROC_ERR;
    }

    // Search if flow exists in the map
    struct flow_stats *stats, new_stats = {};
    stats = bpf_map_lookup_elem(&flow_map, flow);
    __u32 feats = config->features;

    // Sampling based on configuration in nanoseconds
    if (config->sampling_rate_ns > 0 && stats) {
        if ((now - stats->last_time) < config->sampling_rate_ns) {
            bpf_printk("not sampling this packet");
            return PROC_ERR;
        }
    }

    // Case flow already exists, update
    if (stats && ((now - stats->last_time) < config->timeout)) {
        last_arrivel = stats->last_time;
        stats->last_time = now;

        // PACKETS
        if (feats & FEATURE_PACKETS) {
            __sync_fetch_and_add(&stats->packets, 1);
        }
        // BYTES
        if (feats & FEATURE_BYTES) {
            __sync_fetch_and_add(&stats->bytes, pkt_len);
        }
        // MAXIMUM PACKET LENGTH
        if (feats & FEATURE_MAX_PKT_LEN) {
            if (pkt_len > stats->max_pkt_len)
                stats->max_pkt_len = pkt_len;
        }
        // MINIMUM PACKET LENGTH
        if (feats & FEATURE_MIN_PKT_LEN) {
            if (pkt_len < stats->min_pkt_len)
                stats->min_pkt_len = pkt_len;
        }
        // DURATION in seconds scalled by PRECISION
        if (feats & FEATURE_DURATION) {
            stats->duration = (now - stats->start_time) * config->precision / NS_TO_SECOND;
        }
        // PACKETS PER SECOND scalled by PRECISION
        if ((feats & FEATURE_PPS) && stats->duration > 0) {
            stats->pps = (stats->packets * config->precision) / stats->duration;
        }
        // BYTES PER SECOND scalled by PRECISION
        if ((feats & FEATURE_BPS) && stats->duration > 0) {
            stats->bps = (stats->bytes * config->precision) / stats->duration;
        }
        // INTER ARRIVEL TIME in seconds scalled by PRECISION
        if (feats & FEATURE_IAT) {
            stats->iat = (now - last_arrivel) * config->precision / NS_TO_SECOND;
        }
        // MAXIMUM PACKETS PER SECOND scalled by PRECISION
        if ((feats & FEATURE_MAX_PPS) && (feats & FEATURE_PPS)) {
            if (stats->pps > stats->max_pps)
                stats->max_pps = stats->pps;
        }
        // MINIMUM PACKETS PER SECOND scalled by PRECISION
        if ((feats & FEATURE_MIN_PPS) && (feats & FEATURE_PPS)) {
            if (stats->pps < stats->min_pps || stats->min_pps == 0)
                stats->min_pps = stats->pps;
        }
        // MAXIMUM BYTES PER SECOND scalled by PRECISION
        if ((feats & FEATURE_MAX_BPS) && (feats & FEATURE_BPS)) {
            if (stats->bps > stats->max_bps)
                stats->max_bps = stats->bps;
        }
        // MINIMUM BYTES PER SECOND scalled by PRECISION
        if ((feats & FEATURE_MIN_BPS) && (feats & FEATURE_BPS)) {
            if (stats->bps < stats->min_bps || stats->min_bps == 0)
                stats->min_bps = stats->bps;
        }
        // MAXIMUM INTER ARRIVEL TIME scalled by PRECISION
        if ((feats & FEATURE_MAX_IAT) && (feats & FEATURE_IAT)) {
            if (stats->iat > stats->max_iat)
                stats->max_iat = stats->iat;
        }
        // MINIMUM INTER ARRIVEL TIME scalled by PRECISION
        if ((feats & FEATURE_MIN_IAT) && (feats & FEATURE_IAT)) {
            if (stats->iat < stats->min_iat || stats->min_iat == 0)
                stats->min_iat = stats->iat;
        }
        // AVERAGE PACKETS PER SECOND scalled by PRECISION
        if ((feats & FEATURE_AVG_PPS) && (feats & FEATURE_PPS)) {
            stats->count_pps++;
            __u64 old_avg_pps = stats->avg_pps;
            stats->avg_pps = (old_avg_pps * (stats->count_pps - 1) + stats->pps) / stats->count_pps;
        }
        // AVERAGE BYTES PER SECOND scalled by PRECISION
        if ((feats & FEATURE_AVG_BPS) && (feats & FEATURE_BPS)) {
            stats->count_bps++;
            __u64 old_avg_bps = stats->avg_bps;
            stats->avg_bps = (old_avg_bps * (stats->count_bps - 1) + stats->bps) / stats->count_bps;
        }
        // AVERAGE BYTES PER PACKET scalled by PRECISION
        if ((feats & FEATURE_AVG_BPP) && (feats & FEATURE_BYTES) && (feats & FEATURE_PACKETS)) {
            stats->avg_bpp =  (__s64) (stats->bytes * config->precision) / stats->packets;
        }
        // AVERAGE INTER ARRIVEL TIME scalled by PRECISION
        if ((feats & FEATURE_AVG_IAT) && (feats & FEATURE_IAT)) {
            stats->count_iat++;
            __u64 old_avg_iat = stats->avg_iat;
            stats->avg_iat = (old_avg_iat * (stats->count_iat - 1) + stats->iat) / stats->count_iat;
        }
        //  VARIANCE PACKETS PER SECOND scalled by PRECISION
        if ((feats & FEATURE_VAR_PPS) && (feats & FEATURE_AVG_PPS) && stats->count_pps > 1) {
            __s64 diff = (__s64) stats->pps - stats->avg_pps;
            stats->m2_pps += diff * diff;
            stats->var_pps = stats->m2_pps / stats->count_pps;
        }
        //  VARIANCE BYTES PER SECOND scalled by PRECISION
        if ((feats & FEATURE_VAR_BPS) && (feats & FEATURE_AVG_BPS) && stats->count_bps > 1) {
            __s64 diff = (__s64) stats->bps - stats->avg_bps;
            stats->m2_bps += diff * diff;
            stats->var_bps = stats->m2_bps / stats->count_bps;
        }
        //  VARIANCE INTER ARRIVEL TIME scalled by PRECISION
        if ((feats & FEATURE_VAR_IAT) && (feats & FEATURE_AVG_IAT) && stats->count_iat > 1) {
            __s64 diff = (__s64) stats->iat - stats->avg_iat;
            stats->m2_iat += diff * diff;
            stats->var_iat = stats->m2_iat / stats->count_iat;
        }

        // Check if features hit thresholds for fitness
        check_feature_thresholds(stats);

    // Case flow not exists in the map or timeout, create new 
    } else {
        new_stats.start_time = now;
        new_stats.last_time = now;

        // PACKETS
        if (feats & FEATURE_PACKETS) {
            new_stats.packets = 1;
        }
        // BYTES
        if (feats & FEATURE_BYTES) {
            new_stats.bytes = pkt_len;
        }
        // MAXIMUM PACKET LENGTH
        if (feats & FEATURE_MAX_PKT_LEN) {
            new_stats.max_pkt_len = pkt_len;
        }
        // MINIMUM PACKET LENGTH
        if (feats & FEATURE_MIN_PKT_LEN) {
            new_stats.min_pkt_len = pkt_len;
        }
        // DURATION in seconds
        if (feats & FEATURE_DURATION) {
            new_stats.duration = 0;
        }
        // PACKETS PER SECOND
        if (feats & FEATURE_PPS) {
            new_stats.pps = 0;
            new_stats.count_pps = 0;
        }
        // BYTES PER SECOND
        if (feats & FEATURE_BPS) {
            new_stats.bps = 0;
            new_stats.count_bps = 0;
        }
        // INTER ARRIVEL TIME in seconds
        if (feats & FEATURE_IAT) {
            new_stats.iat = 0;
            new_stats.count_iat = 0;
        }
        // MAXIMUM PACKET PER SECOND
        if (feats & FEATURE_MAX_PPS) {
            new_stats.max_pps = 0;
        }
        // MINIMUM PACKET PER SECOND
        if (feats & FEATURE_MIN_PPS) {
            new_stats.min_pps = 0;
        }
        // MAXIMUM BYTES PER SECOND
        if (feats & FEATURE_MAX_BPS) {
            new_stats.max_bps = 0;
        }
        // MINIMUM BYTES PER SECOND
        if (feats & FEATURE_MIN_BPS) {
            new_stats.min_bps = 0;
        }
        // MAXIMUM INTER ARRIVEL TIME
        if ((feats & FEATURE_MAX_IAT)) {
             new_stats.max_iat = 0;
        }
        // MINIMUM INTER ARRIVEL TIME
        if ((feats & FEATURE_MIN_IAT) ) {
            new_stats.min_iat = 0;
        }
        // AVERAGE PACKET PER SECOND
        if (feats & FEATURE_AVG_PPS) {
            new_stats.avg_pps = 0;
        }
        // AVERAGE BYTES PER SECOND
        if (feats & FEATURE_AVG_BPS) {
            new_stats.avg_bps = 0;
        }
        // AVERAGE BYTES PER PACKET
        if ((feats & FEATURE_AVG_BPP) && (feats & FEATURE_BYTES) && (feats & FEATURE_PACKETS)) {
            new_stats.avg_bpp = pkt_len;
        }
        // AVERAGE INTER ARRIVEL TIME
        if (feats & FEATURE_AVG_IAT) {
            new_stats.avg_iat = 0;
        }
        // VARIANCE PACKETS PER SECOND
        if (feats & FEATURE_VAR_PPS) {  
            new_stats.m2_pps = 0;
            new_stats.var_pps = 0;
        }
        // VARIANCE BYTES PER SECOND
        if (feats & FEATURE_VAR_BPS) {
            new_stats.m2_bps = 0;
            new_stats.var_bps = 0;
        }
        // VARIANCE INTER ARRIVEL TIME
        if (feats & FEATURE_VAR_IAT) {
            new_stats.m2_iat = 0;
            new_stats.var_iat = 0;
        }

        bpf_map_update_elem(&flow_map, flow, &new_stats, BPF_ANY);
    }

    return PROC_OK;
}

// Get execution time and update stats
static __always_inline void get_exec_time() {
    __u32 k = 0;
    struct exec_stats *s = bpf_map_lookup_elem(&xdp_times_map, &k);
    if (!s)
        return;

    __u64 now = bpf_ktime_get_ns();

    if (s->exec_start_ns) {
        __u64 delta = now - s->exec_start_ns;
        __sync_fetch_and_add(&s->cnt, 1);
        __sync_fetch_and_add(&s->sum_ns, delta);
    }

    s->exec_start_ns = now;
}

// --- Program 0: Feature Extraction ---
SEC("xdp")
int xdp_flow_stats(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    struct features_config *config;
    __u32 key = 0;
    enum proc_status st;
    __u64 start = bpf_ktime_get_ns();

    struct exec_stats *exec = bpf_map_lookup_elem(&xdp_times_map, &key);
    if (exec)
        exec->exec_start_ns = start;

    // Check if packet is ate least bigger than Ethernet header
    if (data + sizeof(*eth) > data_end) {
        bpf_printk("error ethernet header");
        return XDP_PASS;
    }

    // Get features config map
    config = bpf_map_lookup_elem(&features_config, &key);

    // Case features map not found or all features disabled
    if (!config || config->features == 0) {
        bpf_printk("error configuration");
        return XDP_PASS;
    }

    struct flow_key flow = {};

    // Extract features
    if (eth->h_proto == htons(ETH_P_IP))
        st = process_ip(ctx, &flow, 4, config); // Process IPv4 packet
    else if (eth->h_proto == htons(ETH_P_IPV6))
        st = process_ip(ctx, &flow, 6, config); // Process IPv6 packet
    else
        st = PROC_ERR;

    // Check if process IP returned error
    if (st != PROC_OK) {
        return XDP_PASS;
    }

    // Disable feature selection
    if (!config->run_selection) {
        get_exec_time();
        return XDP_PASS;
    }

    // Tail call to next step
     __u32 idx = 0;
    struct metadata *meta = bpf_map_lookup_elem(&meta_map, &idx);

    if (!meta || meta->stop) {
        get_exec_time();
        return XDP_PASS;
    }

    get_exec_time();

    if (!meta->done_selection) {
        bpf_tail_call(ctx, &prog_array, PROG_SELECTION);
    } else if (!meta->done_crossover) {
        bpf_tail_call(ctx, &prog_array, PROG_CROSSOVER);
    } else if (!meta->done_mutation) {
        bpf_tail_call(ctx, &prog_array, PROG_MUTATION);
    }

    bpf_printk("error feature extraction");
    return XDP_PASS;
}

// --- Program 1: Selection ---
SEC("xdp")
int xdp_selection(struct xdp_md *ctx) {
    __u32 idx = 0;
    struct metadata *meta = bpf_map_lookup_elem(&meta_map, &idx);
    if (!meta) return XDP_PASS;

    #pragma unroll
    for (int i = 0; i < POPULATION_SIZE; i++) {
        __u32 key_i = i;
        struct individual *ind = bpf_map_lookup_elem(&population, &key_i);
        if (!ind) continue;

        __u64 fitness = 0;
        __u32 active_features = 0;
        __u64 total_hits = 0;
        __u64 score = 0;

        // Calculate fitness based on active features and their hits
        #pragma unroll
        for (int j = 0; j < NUMBER_FEATURES; j++) {
            __u32 key_j = j;
            __u32 *hits = bpf_map_lookup_elem(&feature_hit_map, &key_j);
            __u32 h = hits ? *hits : 0;

            total_hits += h;

            if (get_gene(ind, key_j)) {
                score += h;
                active_features++;
            }
        }

        if (total_hits == 0) {
            total_hits = 1; // Avoid division by zero
        }

        // Penalize for number of active features
        fitness = (score * FEATURE_PRECISION) / total_hits 
            + (FEATURE_WEIGHT * FEATURE_PRECISION) / (active_features + 1);

        bpf_map_update_elem(&fitness_map, &key_i, &fitness, BPF_ANY);

        // Update elite individuals
        if (fitness > meta->elite1_score) {
            meta->elite2 = meta->elite1;
            meta->elite2_score = meta->elite1_score;
            meta->elite1 = key_i;
            meta->elite1_score = fitness;
        } else if (fitness > meta->elite2_score && key_i != meta->elite1) {
            meta->elite2 = key_i;
            meta->elite2_score = fitness;
        }
    }

    // Stop condition: if elite1 score reaches target or max generations reached 
    if (meta->elite1_score >= FITNESS_TARGET || meta->generation >= MAX_GENERATIONS) {
        meta->stop = true;
        get_exec_time();
        return XDP_PASS;
    }

    meta->done_selection = true;
    get_exec_time();
    return XDP_PASS;
}

// --- Program 2: Crossover ---
SEC("xdp")
int xdp_crossover(struct xdp_md *ctx) {
    __u32 idx = 0;
    struct metadata *meta = bpf_map_lookup_elem(&meta_map, &idx);
    if (!meta) return XDP_PASS;

    __u64 time = bpf_ktime_get_ns();

    #pragma unroll
    for (int i = 0; i < POPULATION_SIZE; i++) {
        __u32 key_i = i;

        // Prevent crossover for elite individuals
        if (key_i == meta->elite1 || key_i == meta->elite2) continue; 
        
        // Probability of crossover
        if ((time + key_i) % 100 >= PROB_CROSSOVER) continue;

        struct individual *child = bpf_map_lookup_elem(&population, &key_i);
        if (!child) continue;

        // Choose parents randomly different from child and each other
        __u32 p1_idx = (time + key_i * 31) % POPULATION_SIZE;
        __u32 p2_idx = (time + key_i * 17) % POPULATION_SIZE;
        if (p1_idx == p2_idx || p1_idx == key_i || p2_idx == key_i) continue;

        struct individual *parent1 = bpf_map_lookup_elem(&population, &p1_idx);
        struct individual *parent2 = bpf_map_lookup_elem(&population, &p2_idx);
        if (!parent1 || !parent2) continue;

        // Crossover with a random crossover point
        __u32 crossover_point = (time + key_i) % NUMBER_FEATURES;

        #pragma unroll
        for (int j = 0; j < NUMBER_FEATURES; j++) {
            __u32 key_j = j;
            // Choose gene from parent1 or parent2 based on crossover point
            int gene = (key_j < crossover_point) ? get_gene(parent1, key_j) : get_gene(parent2, key_j);
            set_gene(child, key_j, gene);
        }
    }

    meta->done_crossover = true;
    get_exec_time();
    return XDP_PASS;
}

// --- Program 3: Mutation ---
SEC("xdp")
int xdp_mutation(struct xdp_md *ctx) {
    __u32 idx = 0;
    struct metadata *meta = bpf_map_lookup_elem(&meta_map, &idx);
    if (!meta) return XDP_PASS;

    __u64 time = bpf_ktime_get_ns();

    #pragma unroll
    for (int i = 0; i < POPULATION_SIZE; i++) {
        __u32 key = i;

        // Skip elites and apply mutation probability
        if (key == meta->elite1 || key == meta->elite2) continue;

        // Probability of mutation
        if ((time + key) % 100 >= PROB_MUTATION) continue;

        struct individual *ind = bpf_map_lookup_elem(&population, &key);
        if (!ind) continue;

        // Randomly flip a gene
        __u32 rand_idx = (time + key) % NUMBER_FEATURES;
        flip_gene(ind, rand_idx);
    }

    meta->generation++;
    meta->done_selection = false;
    meta->done_crossover = false;
    meta->done_mutation = false;
    meta->elite1_score = 0;
    meta->elite2_score = 0;
    get_exec_time();
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
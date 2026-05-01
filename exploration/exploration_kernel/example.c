#include <bpf_helpers.h>

// ============================================================================
// Maps
// ============================================================================
DEFINE_BPF_MAP(order_count_map, ARRAY, int, uint64_t, 11)
DEFINE_BPF_MAP(file_open_count, HASH, uint64_t, uint64_t, 4096)
DEFINE_BPF_MAP(alloc_start_map, HASH, uint64_t, uint64_t, 1024)
DEFINE_BPF_MAP(latency_max_map, ARRAY, int, uint64_t, 1)
DEFINE_BPF_MAP(launch_tgid_map, ARRAY, int, uint32_t, 1)

// ============================================================================
// Tracepoint arg structs
// ============================================================================
struct page_alloc_args {
    unsigned long long ignore;
    unsigned long pfn;
    unsigned int order;
    unsigned int gfp_flags;
    int migratetype;
};

struct raw_syscalls_sys_enter_args {
    unsigned long long ignore;
    long id;
    unsigned long args[6];
};

struct raw_syscalls_sys_exit_args {
    unsigned long long ignore;
    long id;
    long ret;
};

// ============================================================================
// pt_regs for kprobes
// ============================================================================
struct pt_regs {
    uint64_t regs[31];
    uint64_t sp;
    uint64_t pc;
    uint64_t pstate;
};

// ============================================================================
// Program 1: page allocation count by order
// ============================================================================
DEFINE_BPF_PROG("tracepoint/kmem/mm_page_alloc", AID_ROOT, AID_ROOT, tp_mm_page_alloc)
(struct page_alloc_args *args) {
    int key = (int)args->order;
    if (key < 0 || key >= 11) return 0;

    uint64_t *count = bpf_order_count_map_lookup_elem(&key);
    if (count) {
        __sync_fetch_and_add(count, 1);
    } else {
        uint64_t init_val = 1;
        bpf_order_count_map_update_elem(&key, &init_val, BPF_ANY);
    }
    return 0;
}

// ============================================================================
// Program 2: track openat/openat2 calls per process
// ============================================================================
DEFINE_BPF_PROG("tracepoint/raw_syscalls/sys_enter", AID_ROOT, AID_ROOT, tp_sys_enter)
(struct raw_syscalls_sys_enter_args *args) {
    if (args->id != 56 && args->id != 437) return 1;

    uint64_t pid_tgid = bpf_get_current_pid_tgid();
    uint32_t tgid = (uint32_t)(pid_tgid >> 32);

    int launch_key = 0;
    uint32_t *launch_tgid = bpf_launch_tgid_map_lookup_elem(&launch_key);
    if (launch_tgid && *launch_tgid == 0) {
        bpf_launch_tgid_map_update_elem(&launch_key, &tgid, BPF_ANY);
    }

    uint64_t *count = bpf_file_open_count_lookup_elem(&pid_tgid);
    if (count) {
        __sync_fetch_and_add(count, 1);
    } else {
        uint64_t one = 1;
        bpf_file_open_count_update_elem(&pid_tgid, &one, BPF_ANY);
    }
    return 1;
}

// ============================================================================
// Program 3: sys_exit (placeholder, just verify it loads)
// ============================================================================
DEFINE_BPF_PROG("tracepoint/raw_syscalls/sys_exit", AID_ROOT, AID_ROOT, tp_sys_exit)
(struct raw_syscalls_sys_exit_args *args) {
    return 1;
}

// ============================================================================
// Program 4: kprobe entry on __alloc_pages — record start time
// ============================================================================
DEFINE_BPF_PROG("kprobe/__alloc_pages", AID_ROOT, AID_ROOT, kprobe_alloc_entry)
(struct pt_regs *ctx) {
    uint64_t pid_tgid = bpf_get_current_pid_tgid();
    uint64_t ts = bpf_ktime_get_ns();
    bpf_alloc_start_map_update_elem(&pid_tgid, &ts, BPF_ANY);
    return 0;
}

// ============================================================================
// Program 5: kretprobe exit on __alloc_pages — compute latency, track max
// ============================================================================
DEFINE_BPF_PROG("kretprobe/__alloc_pages", AID_ROOT, AID_ROOT, kretprobe_alloc_exit)
(struct pt_regs *ctx) {
    uint64_t pid_tgid = bpf_get_current_pid_tgid();
    uint64_t *start_ts = bpf_alloc_start_map_lookup_elem(&pid_tgid);
    if (!start_ts) return 0;

    uint64_t end_ns = bpf_ktime_get_ns();
    uint64_t latency = end_ns - *start_ts;
    bpf_alloc_start_map_delete_elem(&pid_tgid);

    int key = 0;
    uint64_t *max_ns = bpf_latency_max_map_lookup_elem(&key);
    if (max_ns && latency > *max_ns) {
        *max_ns = latency;
    }
    return 0;
}

LICENSE("GPL");
#include <bpf_helpers.h>

// ---------------------------------------------------------------------------
// Structs must be declared BEFORE the DEFINE_BPF_MAP macros that use them
// ---------------------------------------------------------------------------

struct order_stats {
    uint64_t count;
    uint64_t total_ns;
    uint64_t min_ns;
    uint64_t max_ns;
};

struct inflight_alloc {
    uint64_t start_ns;
    uint32_t order;
};

// ---------------------------------------------------------------------------
// Maps — declared after structs are fully defined
// ---------------------------------------------------------------------------

DEFINE_BPF_MAP(latency_map,  ARRAY, int,      struct order_stats,    11)
DEFINE_BPF_MAP(inflight_map, HASH,  uint64_t, struct inflight_alloc, 4096)

// ---------------------------------------------------------------------------
// ARM64 pt_regs — manual definition, bpf_tracing.h not available here
// On ARM64: x0=arg1 (gfp_mask), x1=arg2 (order)
// ---------------------------------------------------------------------------
struct pt_regs {
    uint64_t regs[31];
    uint64_t sp;
    uint64_t pc;
    uint64_t pstate;
};

#define ARG2(ctx) ((ctx)->regs[1])

// ---------------------------------------------------------------------------
// kprobe on __alloc_pages — fires when allocation STARTS
// ---------------------------------------------------------------------------
DEFINE_BPF_PROG("kprobe/__alloc_pages", AID_ROOT, AID_ROOT, kprobe_alloc_pages_entry)
(struct pt_regs *ctx) {
    uint64_t pid_tgid = bpf_get_current_pid_tgid();

    struct inflight_alloc val = {};
    val.start_ns = bpf_ktime_get_ns();
    val.order    = (uint32_t)ARG2(ctx);

    if (val.order >= 11) val.order = 10;

    bpf_inflight_map_update_elem(&pid_tgid, &val, BPF_ANY);
    return 0;
}

// ---------------------------------------------------------------------------
// Tracepoint kmem/mm_page_alloc — fires when allocation COMPLETES
// ---------------------------------------------------------------------------
struct page_alloc_args {
    unsigned long long ignore;
    unsigned long      pfn;
    unsigned int       order;
    unsigned int       gfp_flags;
    int                migratetype;
};

DEFINE_BPF_PROG("tracepoint/kmem/mm_page_alloc", AID_ROOT, AID_ROOT, tp_mm_page_alloc)
(struct page_alloc_args *args) {
    uint64_t pid_tgid = bpf_get_current_pid_tgid();

    struct inflight_alloc *inflight = bpf_inflight_map_lookup_elem(&pid_tgid);
    if (!inflight) return 0;

    uint64_t end_ns   = bpf_ktime_get_ns();
    uint64_t start_ns = inflight->start_ns;

    bpf_inflight_map_delete_elem(&pid_tgid);

    if (end_ns <= start_ns) return 0;
    uint64_t latency = end_ns - start_ns;
    if (latency > 1000000000ULL) return 0;  // discard > 1 second

    int key = (int)args->order;
    if (key < 0 || key >= 11) return 0;

    struct order_stats *s = bpf_latency_map_lookup_elem(&key);
    if (!s) return 0;

    __sync_fetch_and_add(&s->count,    1);
    __sync_fetch_and_add(&s->total_ns, latency);

    if (s->min_ns == 0 || latency < s->min_ns) s->min_ns = latency;
    if (latency > s->max_ns)                    s->max_ns = latency;

    return 0;
}

LICENSE("GPL");
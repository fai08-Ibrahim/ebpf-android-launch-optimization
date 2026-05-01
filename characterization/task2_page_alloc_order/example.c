#include <bpf_helpers.h>

// Histogram map: key = allocation order (0..10), value = count
// Using Android's DEFINE_BPF_MAP macro — required by this toolchain
DEFINE_BPF_MAP(order_count_map, ARRAY, int, uint64_t, 11)

// Tracepoint argument structure for kmem:mm_page_alloc
// Verify field names on device with:
//   adb shell cat /sys/kernel/tracing/events/kmem/mm_page_alloc/format
struct page_alloc_args {
    unsigned long long ignore;  // common fields — skip
    unsigned long pfn;          // page frame number
    unsigned int order;         // allocation order (0=1 page, 1=2 pages, etc.)
    unsigned int gfp_flags;     // GFP flags
    int migratetype;            // migration type
};

// Attach to tracepoint: kmem:mm_page_alloc
DEFINE_BPF_PROG("tracepoint/kmem/mm_page_alloc", AID_ROOT, AID_ROOT, tp_mm_page_alloc)
(struct page_alloc_args *args) {
    int key = (int)args->order;

    // Clamp to valid range — keeps the verifier happy
    if (key < 0 || key >= 11) return 0;

    uint64_t *count = bpf_order_count_map_lookup_elem(&key);
    if (count) {
        __sync_fetch_and_add(count, 1);  // atomic increment
    } else {
        uint64_t init_val = 1;
        bpf_order_count_map_update_elem(&key, &init_val, BPF_ANY);
    }

    return 0;
}

LICENSE("GPL");
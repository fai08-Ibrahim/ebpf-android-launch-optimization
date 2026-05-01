#include <iostream>
#include <fcntl.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/bpf.h>
#include <linux/perf_event.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>

const char* BPF_PROG_TRACEPOINT = "/sys/fs/bpf/prog_example_tracepoint_kmem_mm_page_alloc";
const char* BPF_PROG_KPROBE     = "/sys/fs/bpf/prog_example_kprobe___alloc_pages";
const char* BPF_MAP_LATENCY     = "/sys/fs/bpf/map_example_latency_map";
const char* BPF_MAP_INFLIGHT    = "/sys/fs/bpf/map_example_inflight_map";

static const int MAX_ORDER       = 11;
static const int MONITOR_SECONDS = 3;

// Must match struct in example.c
struct order_stats {
    uint64_t count;
    uint64_t total_ns;
    uint64_t min_ns;
    uint64_t max_ns;
};

// -------------------------------------------------------------------------
// BPF syscall helpers
// -------------------------------------------------------------------------

int bpf_lookup_elem(int fd, const void* key, void* value) {
    bpf_attr attr = {};
    attr.map_fd = fd;
    attr.key    = reinterpret_cast<uintptr_t>(key);
    attr.value  = reinterpret_cast<uintptr_t>(value);
    return syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, &attr, sizeof(attr));
}

int bpf_update_elem(int fd, const void* key, const void* value, uint64_t flags) {
    bpf_attr attr = {};
    attr.map_fd = fd;
    attr.key    = reinterpret_cast<uintptr_t>(key);
    attr.value  = reinterpret_cast<uintptr_t>(value);
    attr.flags  = flags;
    return syscall(__NR_bpf, BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
}

int bpf_obj_get_rw(const char* path) {
    bpf_attr attr = {};
    attr.pathname   = reinterpret_cast<uintptr_t>(path);
    attr.file_flags = 0;  // read-write
    return syscall(__NR_bpf, BPF_OBJ_GET, &attr, sizeof(attr));
}

int bpf_obj_get_ro(const char* path) {
    bpf_attr attr = {};
    attr.pathname   = reinterpret_cast<uintptr_t>(path);
    attr.file_flags = BPF_F_RDONLY;
    return syscall(__NR_bpf, BPF_OBJ_GET, &attr, sizeof(attr));
}

static int read_tracepoint_id(const char* category, const char* name) {
    char path[256];
    snprintf(path, sizeof(path),
             "/sys/kernel/tracing/events/%s/%s/id", category, name);
    FILE* fp = fopen(path, "r");
    if (!fp) {
        snprintf(path, sizeof(path),
                 "/sys/kernel/debug/tracing/events/%s/%s/id", category, name);
        fp = fopen(path, "r");
        if (!fp) return -1;
    }
    int id = -1;
    if (fscanf(fp, "%d", &id) != 1) id = -1;
    fclose(fp);
    return id;
}

int bpf_attach_tracepoint(int prog_fd, const char* category, const char* name) {
    int tracepoint_id = read_tracepoint_id(category, name);
    if (tracepoint_id < 0) return -1;

    perf_event_attr attr = {};
    attr.size          = sizeof(attr);
    attr.type          = PERF_TYPE_TRACEPOINT;
    attr.config        = static_cast<uint64_t>(tracepoint_id);
    attr.sample_period = 1;
    attr.wakeup_events = 1;

    int perf_fd = syscall(__NR_perf_event_open, &attr, -1, 0, -1, PERF_FLAG_FD_CLOEXEC);
    if (perf_fd < 0) return -1;

    if (ioctl(perf_fd, PERF_EVENT_IOC_SET_BPF, prog_fd) != 0) { close(perf_fd); return -1; }
    if (ioctl(perf_fd, PERF_EVENT_IOC_ENABLE,  0)        != 0) { close(perf_fd); return -1; }
    return perf_fd;
}

// Attach a kprobe by writing to the kprobe events tracefs interface
int bpf_attach_kprobe(int prog_fd, const char* func_name, const char* event_name) {
    // Register the kprobe via tracefs
    const char* kprobe_events = "/sys/kernel/tracing/kprobe_events";
    FILE* fp = fopen(kprobe_events, "a");
    if (!fp) {
        fp = fopen("/sys/kernel/debug/tracing/kprobe_events", "a");
        if (!fp) return -1;
    }
    fprintf(fp, "p:kprobes/%s %s\n", event_name, func_name);
    fclose(fp);

    // Now attach via perf_event_open using the dynamic tracepoint
    int tp_id = read_tracepoint_id("kprobes", event_name);
    if (tp_id < 0) return -1;

    perf_event_attr attr = {};
    attr.size          = sizeof(attr);
    attr.type          = PERF_TYPE_TRACEPOINT;
    attr.config        = static_cast<uint64_t>(tp_id);
    attr.sample_period = 1;
    attr.wakeup_events = 1;

    int perf_fd = syscall(__NR_perf_event_open, &attr, -1, 0, -1, PERF_FLAG_FD_CLOEXEC);
    if (perf_fd < 0) return -1;

    if (ioctl(perf_fd, PERF_EVENT_IOC_SET_BPF, prog_fd) != 0) { close(perf_fd); return -1; }
    if (ioctl(perf_fd, PERF_EVENT_IOC_ENABLE,  0)        != 0) { close(perf_fd); return -1; }
    return perf_fd;
}

void cleanup_kprobe(const char* event_name) {
    const char* kprobe_events = "/sys/kernel/tracing/kprobe_events";
    FILE* fp = fopen(kprobe_events, "a");
    if (!fp) fp = fopen("/sys/kernel/debug/tracing/kprobe_events", "a");
    if (!fp) return;
    fprintf(fp, "-:kprobes/%s\n", event_name);
    fclose(fp);
}

// -------------------------------------------------------------------------
// Reset latency_map — zeroes all per-order stats before each run
// Preserves Task 2 correctness lesson: never accumulate across runs
// -------------------------------------------------------------------------
void reset_latency_map(int map_fd) {
    const struct order_stats zero = {0, 0, 0, 0};
    for (int order = 0; order < MAX_ORDER; ++order) {
        uint32_t key = static_cast<uint32_t>(order);
        if (bpf_update_elem(map_fd, &key, &zero, BPF_ANY) != 0) {
            fprintf(stderr, "Warning: failed to reset order %d: %s\n",
                    order, strerror(errno));
        }
    }
    std::cout << "[reset] latency_map cleared — all stats zeroed." << std::endl;
}

// -------------------------------------------------------------------------
// main
// -------------------------------------------------------------------------

int main() {
    // Open kprobe prog (entry hook — records start time)
    int kprobe_prog_fd = bpf_obj_get_ro(BPF_PROG_KPROBE);
    if (kprobe_prog_fd < 0) {
        std::cerr << "Error: Could not retrieve kprobe prog " << BPF_PROG_KPROBE
                  << ": " << strerror(errno) << " (errno=" << errno << ")\n"
                  << "Note: kprobes may be restricted on this device.\n";
        return 1;
    }

    // Open tracepoint prog (completion hook — computes latency)
    int tp_prog_fd = bpf_obj_get_ro(BPF_PROG_TRACEPOINT);
    if (tp_prog_fd < 0) {
        std::cerr << "Error: Could not retrieve tracepoint prog " << BPF_PROG_TRACEPOINT
                  << ": " << strerror(errno) << " (errno=" << errno << ")\n";
        close(kprobe_prog_fd);
        return 1;
    }

    // Open latency map read-write for reset + read
    int latency_map_fd = bpf_obj_get_rw(BPF_MAP_LATENCY);
    if (latency_map_fd < 0) {
        std::cerr << "Error: Could not retrieve latency map " << BPF_MAP_LATENCY
                  << ": " << strerror(errno) << " (errno=" << errno << ")\n";
        close(tp_prog_fd);
        close(kprobe_prog_fd);
        return 1;
    }

    // >>> RESET — zero all stats before attaching anything <
    reset_latency_map(latency_map_fd);

    // Attach kprobe (start of allocation)
    int kprobe_fd = bpf_attach_kprobe(kprobe_prog_fd, "__alloc_pages", "t3_alloc_entry");
    if (kprobe_fd < 0) {
        std::cerr << "Error: Could not attach kprobe on __alloc_pages"
                  << ": " << strerror(errno) << " (errno=" << errno << ")\n";
        close(latency_map_fd);
        close(tp_prog_fd);
        close(kprobe_prog_fd);
        return 1;
    }

    // Attach tracepoint (end of allocation)
    int tp_fd = bpf_attach_tracepoint(tp_prog_fd, "kmem", "mm_page_alloc");
    if (tp_fd < 0) {
        std::cerr << "Error: Could not attach tracepoint kmem/mm_page_alloc"
                  << ": " << strerror(errno) << " (errno=" << errno << ")\n";
        close(kprobe_fd);
        close(latency_map_fd);
        close(tp_prog_fd);
        close(kprobe_prog_fd);
        return 1;
    }

    std::cout << "Monitoring page allocation latency via eBPF (Task 3)..." << std::endl;
    std::cout << "Kprobe prog : " << BPF_PROG_KPROBE     << std::endl;
    std::cout << "TP prog     : " << BPF_PROG_TRACEPOINT << std::endl;
    std::cout << "Latency map : " << BPF_MAP_LATENCY      << std::endl;
    std::cout << "Sampling for " << MONITOR_SECONDS << " seconds..." << std::endl;

    sleep(MONITOR_SECONDS);

    // Read per-order stats from latency_map
    struct order_stats stats[MAX_ORDER] = {};
    uint64_t grand_total_count = 0;

    for (int order = 0; order < MAX_ORDER; ++order) {
        uint32_t key = static_cast<uint32_t>(order);
        bpf_lookup_elem(latency_map_fd, &key, &stats[order]);
        grand_total_count += stats[order].count;
    }

    // Print per-order latency table
    std::cout << std::endl;
    std::cout << "Page Allocation Latency by Order (" << MONITOR_SECONDS << "s window):" << std::endl;
    std::cout << "------------------------------------------------------------------------" << std::endl;
    printf("%-6s | %-10s | %-16s | %-16s | %-16s\n",
           "Order", "Count", "Avg_lat(ns)", "Min_lat(ns)", "Max_lat(ns)");
    std::cout << "------------------------------------------------------------------------" << std::endl;

    for (int order = 0; order < MAX_ORDER; ++order) {
        if (stats[order].count == 0) continue;
        uint64_t avg = stats[order].total_ns / stats[order].count;
        printf("%-6d | %-10llu | %-16llu | %-16llu | %-16llu\n",
               order,
               (unsigned long long)stats[order].count,
               (unsigned long long)avg,
               (unsigned long long)stats[order].min_ns,
               (unsigned long long)stats[order].max_ns);
    }
    std::cout << "------------------------------------------------------------------------" << std::endl;

    // Summary
    std::cout << std::endl;
    std::cout << "=== Summary ===" << std::endl;
    for (int order = 0; order < MAX_ORDER; ++order) {
        if (stats[order].count == 0) {
            printf("  order %d -> no allocations\n", order);
            continue;
        }
        uint64_t avg = stats[order].total_ns / stats[order].count;
        printf("  order %d -> count=%-8llu avg=%llu ns  min=%llu ns  max=%llu ns\n",
               order,
               (unsigned long long)stats[order].count,
               (unsigned long long)avg,
               (unsigned long long)stats[order].min_ns,
               (unsigned long long)stats[order].max_ns);
    }
    printf("  TOTAL allocations measured -> %llu\n",
           (unsigned long long)grand_total_count);

    // Cleanup
    close(tp_fd);
    close(kprobe_fd);
    close(latency_map_fd);
    close(tp_prog_fd);
    close(kprobe_prog_fd);
    cleanup_kprobe("t3_alloc_entry");  // unregister kprobe from tracefs

    return 0;
}
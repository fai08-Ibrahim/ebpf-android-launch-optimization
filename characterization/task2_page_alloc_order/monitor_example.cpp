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

const char* BPF_PROG_PATH = "/sys/fs/bpf/prog_example_tracepoint_kmem_mm_page_alloc";
const char* BPF_MAP_PATH  = "/sys/fs/bpf/map_example_order_count_map";

static const int MAX_ORDER      = 11;
static const int MONITOR_SECONDS = 3;

// -------------------------------------------------------------------------
// BPF syscall helpers — unchanged from original
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

int bpf_obj_get(const char* path) {
    bpf_attr attr = {};
    attr.pathname   = reinterpret_cast<uintptr_t>(path);
    attr.file_flags = BPF_F_RDONLY;
    return syscall(__NR_bpf, BPF_OBJ_GET, &attr, sizeof(attr));
}

int bpf_obj_get_rw(const char* path) {
    bpf_attr attr = {};
    attr.pathname   = reinterpret_cast<uintptr_t>(path);
    attr.file_flags = 0;  // read-write — needed for map reset
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

    if (ioctl(perf_fd, PERF_EVENT_IOC_SET_BPF, prog_fd) != 0) {
        close(perf_fd);
        return -1;
    }
    if (ioctl(perf_fd, PERF_EVENT_IOC_ENABLE, 0) != 0) {
        close(perf_fd);
        return -1;
    }
    return perf_fd;
}

// -------------------------------------------------------------------------
// MAP RESET — zeroes all order slots before each sampling window
// Called once after map_fd is opened, before attaching the tracepoint.
// -------------------------------------------------------------------------
void reset_order_map(int map_fd) {
    const uint64_t zero = 0;
    for (int order = 0; order < MAX_ORDER; ++order) {
        uint32_t key = static_cast<uint32_t>(order);
        if (bpf_update_elem(map_fd, &key, &zero, BPF_ANY) != 0) {
            fprintf(stderr, "Warning: failed to reset order %d in map: %s\n",
                    order, strerror(errno));
        }
    }
    std::cout << "[reset] Map cleared — all order counts set to zero." << std::endl;
}

// -------------------------------------------------------------------------
// main
// -------------------------------------------------------------------------

int main() {
    int prog_fd = bpf_obj_get(BPF_PROG_PATH);
    if (prog_fd < 0) {
        std::cerr << "Error: Could not retrieve pinned BPF prog " << BPF_PROG_PATH
                  << ": " << strerror(errno) << " (errno=" << errno << ")" << std::endl;
        return 1;
    }

    // Open map read-write so we can zero it before sampling
    int map_fd = bpf_obj_get_rw(BPF_MAP_PATH);
    if (map_fd < 0) {
        std::cerr << "Error: Could not retrieve pinned BPF map " << BPF_MAP_PATH
                  << ": " << strerror(errno) << " (errno=" << errno << ")" << std::endl;
        close(prog_fd);
        return 1;
    }

    // >>> RESET HAPPENS HERE — before tracepoint attach and before sleep <
    reset_order_map(map_fd);

    // Attach tracepoint AFTER reset so no events are counted before zeroing
    int tp_fd = bpf_attach_tracepoint(prog_fd, "kmem", "mm_page_alloc");
    if (tp_fd < 0) {
        std::cerr << "Error: Could not attach tracepoint kmem/mm_page_alloc"
                  << ": " << strerror(errno) << " (errno=" << errno << ")" << std::endl;
        close(map_fd);
        close(prog_fd);
        return 1;
    }

    std::cout << "Monitoring page allocations via eBPF hook..." << std::endl;
    std::cout << "Using prog path: " << BPF_PROG_PATH << std::endl;
    std::cout << "Using map  path: " << BPF_MAP_PATH  << std::endl;
    std::cout << "Sampling for " << MONITOR_SECONDS << " seconds..." << std::endl;

    sleep(MONITOR_SECONDS);

    // Read histogram from map
    uint64_t counts[MAX_ORDER] = {0};
    uint64_t total = 0;

    for (int order = 0; order < MAX_ORDER; ++order) {
        uint32_t key = static_cast<uint32_t>(order);
        uint64_t val = 0;
        if (bpf_lookup_elem(map_fd, &key, &val) == 0) {
            counts[order] = val;
            total += val;
        } else {
            counts[order] = 0;
        }
    }

    // Per-order table
    std::cout << std::endl;
    std::cout << "Page Allocation Order Histogram (" << MONITOR_SECONDS << "s window):" << std::endl;
    std::cout << "--------------------------------------------" << std::endl;
    printf("%-10s | %-12s | %s\n", "Order", "Count", "Pages per alloc");
    std::cout << "--------------------------------------------" << std::endl;
    for (int order = 0; order < MAX_ORDER; ++order) {
        if (counts[order] > 0) {
            unsigned long pages = 1UL << order;
            printf("order %-4d | %-12llu | %lu page(s)\n",
                   order,
                   (unsigned long long)counts[order],
                   pages);
        }
    }
    std::cout << "--------------------------------------------" << std::endl;

    // Summary
    std::cout << std::endl;
    std::cout << "=== Summary ===" << std::endl;
    for (int order = 0; order < MAX_ORDER; ++order) {
        printf("  order %d -> count %llu\n", order, (unsigned long long)counts[order]);
    }
    printf("  TOTAL   -> %llu allocations\n", (unsigned long long)total);

    close(tp_fd);
    close(map_fd);
    close(prog_fd);
    return 0;
}
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
#include <vector>
#include <algorithm>   // std::sort
#include <cstdlib>     // atoi
#include <string>
#include <cctype>

// ── tunables ──────────────────────────────────────────────────────────────────

static const int      CAPTURE_SECONDS = 1;
static const int      TOP_N           = 5;
static const uint64_t MIN_ACTIVITY    = 5;
static const bool     CLEAR_MAP_FIRST = true;

enum attach_result {
    ATTACH_FAILED = -1,
    ATTACH_NEW = 0,
    ATTACH_REUSED = 1,
};

// ── data types ────────────────────────────────────────────────────────────────

// EDIT 1: Match the new eBPF io_stats layout exactly.
// Field order must match the kernel struct byte-for-byte.
// total_reads and total_writes are now real map fields (not computed here).
struct io_stats {
    uint64_t total_reads;   // read() + pread64() call count
    uint64_t total_writes;  // write() + pwrite64() call count
    uint64_t seq_reads;     // pread64() calls classified as sequential
    uint64_t rand_reads;    // pread64() calls classified as random
    uint64_t seq_writes;    // pwrite64() calls classified as sequential
    uint64_t rand_writes;   // pwrite64() calls classified as random
    uint64_t uncls_reads;   // explicit unclassified reads
    uint64_t uncls_writes;  // explicit unclassified writes
};

struct pid_row {
    uint32_t pid;
    uint64_t total_reads;
    uint64_t total_writes;
    uint64_t seq_reads;
    uint64_t rand_reads;
    uint64_t seq_writes;
    uint64_t rand_writes;
    uint64_t uncls_reads;
    uint64_t uncls_writes;
    char     comm[64];
};

struct foreground_info {
    bool        detected;
    bool        pid_found;
    uint32_t    pid;
    std::string package_name;
    std::string activity;
    std::string source;
};

// ── BPF syscall helpers ───────────────────────────────────────────────────────

static int bpf_obj_get(const char *path, uint32_t file_flags = 0) {
    bpf_attr attr = {};
    attr.pathname   = reinterpret_cast<uintptr_t>(path);
    attr.file_flags = file_flags;
    return syscall(__NR_bpf, BPF_OBJ_GET, &attr, sizeof(attr));
}

static int bpf_lookup_elem(int map_fd, const void *key, void *value) {
    bpf_attr attr = {};
    attr.map_fd = map_fd;
    attr.key    = reinterpret_cast<uintptr_t>(key);
    attr.value  = reinterpret_cast<uintptr_t>(value);
    return syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, &attr, sizeof(attr));
}

static int bpf_delete_elem(int map_fd, const void *key) {
    bpf_attr attr = {};
    attr.map_fd = map_fd;
    attr.key    = reinterpret_cast<uintptr_t>(key);
    return syscall(__NR_bpf, BPF_MAP_DELETE_ELEM, &attr, sizeof(attr));
}

static int bpf_get_next_key(int map_fd, const void *key, void *next_key) {
    bpf_attr attr = {};
    attr.map_fd   = map_fd;
    attr.key      = reinterpret_cast<uintptr_t>(key);
    attr.next_key = reinterpret_cast<uintptr_t>(next_key);
    return syscall(__NR_bpf, BPF_MAP_GET_NEXT_KEY, &attr, sizeof(attr));
}

// ── shell helpers for foreground app detection ───────────────────────────────

static std::string trim_copy(const std::string &s) {
    size_t b = 0;
    size_t e = s.size();
    while (b < e && std::isspace((unsigned char)s[b])) ++b;
    while (e > b && std::isspace((unsigned char)s[e - 1])) --e;
    return s.substr(b, e - b);
}

static bool run_cmd_capture(const char *cmd, std::string &out) {
    out.clear();
    FILE *f = popen(cmd, "r");
    if (!f) return false;

    char buf[512];
    while (fgets(buf, sizeof(buf), f)) out += buf;
    int rc = pclose(f);
    return (rc == 0);
}

static bool parse_uint32_from_text(const std::string &text, uint32_t &pid_out) {
    size_t i = 0;
    while (i < text.size()) {
        while (i < text.size() && !std::isdigit((unsigned char)text[i])) ++i;
        if (i >= text.size()) break;
        uint64_t v = 0;
        while (i < text.size() && std::isdigit((unsigned char)text[i])) {
            v = v * 10 + (uint64_t)(text[i] - '0');
            ++i;
        }
        if (v > 0 && v <= 0xffffffffULL) {
            pid_out = (uint32_t)v;
            return true;
        }
    }
    return false;
}

static bool extract_component_from_line(const std::string &line,
                                        std::string &pkg,
                                        std::string &activity,
                                        uint32_t &pid,
                                        bool &pid_found) {
    pkg.clear();
    activity.clear();
    pid_found = false;

    // Try to read pid=N if the line exposes it.
    size_t p = line.find("pid=");
    if (p != std::string::npos) {
        uint32_t parsed = 0;
        if (parse_uint32_from_text(line.substr(p + 4), parsed)) {
            pid = parsed;
            pid_found = true;
        }
    }

    // Find first token that looks like package/activity.
    size_t slash = line.find('/');
    if (slash == std::string::npos) return false;

    size_t start = slash;
    while (start > 0) {
        char c = line[start - 1];
        if (std::isspace((unsigned char)c) || c == '{' || c == '}' || c == '(' || c == ')') break;
        --start;
    }

    size_t end = slash + 1;
    while (end < line.size()) {
        char c = line[end];
        if (std::isspace((unsigned char)c) || c == '}' || c == ')' || c == ',') break;
        ++end;
    }

    std::string component = line.substr(start, end - start);
    size_t sep = component.find('/');
    if (sep == std::string::npos || sep == 0 || sep + 1 >= component.size()) return false;

    pkg = component.substr(0, sep);
    activity = component.substr(sep + 1);
    if (!activity.empty() && activity[0] == '.') activity = pkg + activity;
    return !pkg.empty();
}

static bool detect_foreground_from_cmd(const char *cmd,
                                       const char *source,
                                       foreground_info &fg) {
    std::string out;
    if (!run_cmd_capture(cmd, out)) return false;

    size_t pos = 0;
    while (pos < out.size()) {
        size_t nl = out.find('\n', pos);
        if (nl == std::string::npos) nl = out.size();
        std::string line = out.substr(pos, nl - pos);
        pos = (nl < out.size()) ? (nl + 1) : out.size();

        if (line.find("mResumedActivity") == std::string::npos &&
            line.find("topResumedActivity") == std::string::npos &&
            line.find("ResumedActivity") == std::string::npos &&
            line.find("mFocusedApp") == std::string::npos &&
            line.find("mCurrentFocus") == std::string::npos) {
            continue;
        }

        std::string pkg;
        std::string act;
        uint32_t pid = 0;
        bool pid_found = false;
        if (extract_component_from_line(line, pkg, act, pid, pid_found)) {
            fg.detected = true;
            fg.package_name = pkg;
            fg.activity = act;
            fg.source = source;
            if (pid_found) {
                fg.pid = pid;
                fg.pid_found = true;
            }
            return true;
        }
    }
    return false;
}

static bool resolve_pid_from_pidof(const std::string &pkg, uint32_t &pid_out) {
    std::string cmd = "pidof " + pkg + " 2>/dev/null";
    std::string out;
    if (!run_cmd_capture(cmd.c_str(), out)) return false;
    return parse_uint32_from_text(out, pid_out);
}

static foreground_info detect_foreground_app() {
    foreground_info fg = {};

    if (!detect_foreground_from_cmd("dumpsys activity activities", "dumpsys activity activities", fg)) {
        detect_foreground_from_cmd("dumpsys window windows", "dumpsys window windows", fg);
    }

    if (!fg.pid_found && !fg.package_name.empty()) {
        uint32_t pid = 0;
        if (resolve_pid_from_pidof(fg.package_name, pid)) {
            fg.pid = pid;
            fg.pid_found = true;
        }
    }
    return fg;
}

// ── map clear ─────────────────────────────────────────────────────────────────

static void clear_map(int map_fd) {
    uint32_t key, next_key;
    int rc = bpf_get_next_key(map_fd, nullptr, &key);
    while (rc == 0) {
        int rc2 = bpf_get_next_key(map_fd, &key, &next_key);
        bpf_delete_elem(map_fd, &key);
        if (rc2 != 0) break;
        key = next_key;
    }
    fprintf(stderr, "[map] cleared\n");
}

// ── process name lookup ───────────────────────────────────────────────────────

static void get_comm(uint32_t pid, char *buf, size_t sz) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%u/comm", pid);
    FILE *f = fopen(path, "r");
    if (!f) { strncpy(buf, "?", sz); return; }
    if (fgets(buf, (int)sz, f)) {
        size_t len = strlen(buf);
        if (len > 0 && buf[len-1] == '\n') buf[len-1] = '\0';
    } else {
        strncpy(buf, "?", sz);
    }
    fclose(f);
}

// ── map read ──────────────────────────────────────────────────────────────────

static std::vector<pid_row> read_map(int map_fd, uint32_t filter_pid) {
    std::vector<pid_row> rows;
    uint32_t key, next_key;

    int rc = bpf_get_next_key(map_fd, nullptr, &key);
    while (rc == 0) {
        int rc2 = bpf_get_next_key(map_fd, &key, &next_key);

        io_stats s = {};
        if (bpf_lookup_elem(map_fd, &key, &s) == 0) {
            if (filter_pid == 0 || key == filter_pid) {
                pid_row row = {};
                row.pid          = key;
                // EDIT 2: total_reads and total_writes now come directly from
                // the map fields — no longer computed as seq+rand here.
                // This is correct because read() and write() increment totals
                // without touching seq/rand, so seq+rand < total is expected.
                row.total_reads  = s.total_reads;
                row.total_writes = s.total_writes;
                row.seq_reads    = s.seq_reads;
                row.rand_reads   = s.rand_reads;
                row.seq_writes   = s.seq_writes;
                row.rand_writes  = s.rand_writes;
                row.uncls_reads  = s.uncls_reads;
                row.uncls_writes = s.uncls_writes;
                get_comm(key, row.comm, sizeof(row.comm));
                rows.push_back(row);
            }
        }

        if (rc2 != 0) break;
        key = next_key;
    }
    return rows;
}

// ── tracepoint attachment ─────────────────────────────────────────────────────

static int read_tracepoint_id(const char *tracefs_event_path) {
    char id_path[256];
    snprintf(id_path, sizeof(id_path),
             "/sys/kernel/tracing/events/%s/id", tracefs_event_path);
    FILE *f = fopen(id_path, "r");
    if (!f) {
        fprintf(stderr, "Cannot open %s: %s\n", id_path, strerror(errno));
        return -1;
    }
    int id = -1;
    fscanf(f, "%d", &id);
    fclose(f);
    fprintf(stderr, "[tracefs] %s -> id=%d\n", tracefs_event_path, id);
    return id;
}

static int attach_one_cpu(int prog_fd, int tp_id, int cpu, int *out_pfd) {
    if (out_pfd) *out_pfd = -1;

    perf_event_attr attr = {};
    attr.type          = PERF_TYPE_TRACEPOINT;
    attr.size          = sizeof(attr);
    attr.config        = static_cast<uint64_t>(tp_id);
    attr.sample_period = 1;
    attr.wakeup_events = 1;

    int pfd = syscall(__NR_perf_event_open, &attr, -1, cpu, -1, 0);
    if (pfd < 0) return -1;

    if (ioctl(pfd, PERF_EVENT_IOC_SET_BPF, prog_fd) < 0) {
        if (errno == EEXIST) {
            // Another attachment is already active for this CPU/tracepoint.
            // Treat this as reusable/active state and avoid noisy retries.
            close(pfd);
            return ATTACH_REUSED;
        }
        close(pfd);
        return ATTACH_FAILED;
    }

    if (ioctl(pfd, PERF_EVENT_IOC_ENABLE, 0) < 0) {
        close(pfd);
        return ATTACH_FAILED;
    }
    if (out_pfd) *out_pfd = pfd;
    return ATTACH_NEW;
}

static int attach_tracepoint_all_cpus(const char *pinned_prog_path,
                                       const char *tracefs_event_path,
                                       std::vector<int> &out_fds) {
    int prog_fd = bpf_obj_get(pinned_prog_path);
    if (prog_fd < 0) {
        fprintf(stderr, "bpf_obj_get(%s): %s\n", pinned_prog_path, strerror(errno));
        return 0;
    }

    int tp_id = read_tracepoint_id(tracefs_event_path);
    if (tp_id < 0) { close(prog_fd); return 0; }

    int num_cpus = (int)sysconf(_SC_NPROCESSORS_ONLN);
    if (num_cpus <= 0) num_cpus = 1;

    int attached_new = 0;
    int attached_reused = 0;
    for (int cpu = 0; cpu < num_cpus; ++cpu) {
        int pfd = -1;
        int rc = attach_one_cpu(prog_fd, tp_id, cpu, &pfd);
        if (rc == ATTACH_NEW) {
            ++attached_new;
            if (pfd >= 0) out_fds.push_back(pfd);
        } else if (rc == ATTACH_REUSED) {
            ++attached_reused;
        }
    }
    close(prog_fd);

    int attached_total = attached_new + attached_reused;

    if (attached_total < num_cpus) {
        fprintf(stderr,
            "[warn] active %d/%d CPUs (new=%d, reused=%d); results may be partial.\n",
            attached_total, num_cpus, attached_new, attached_reused);
    } else {
        fprintf(stderr,
            "[ok] active on %d/%d CPUs (new=%d, reused=%d) for '%s'\n",
            attached_total, num_cpus, attached_new, attached_reused, pinned_prog_path);
    }
    return attached_total;
}

// ── main ──────────────────────────────────────────────────────────────────────

int main(int argc, char **argv) {
    uint32_t filter_pid = 0;
    int      top_n      = TOP_N;
    if (argc >= 2) filter_pid = (uint32_t)atoi(argv[1]);
    if (argc >= 3) top_n      = atoi(argv[2]);
    if (top_n <= 0) top_n = TOP_N;
    if (top_n > TOP_N) top_n = TOP_N;

    foreground_info fg = detect_foreground_app();

    uint32_t focused_pid = filter_pid;
    if (focused_pid == 0 && fg.pid_found) focused_pid = fg.pid;

    if (filter_pid != 0) {
        fprintf(stderr, "[focus] using explicit PID=%u (argv override)\n", filter_pid);
    } else if (fg.detected && fg.pid_found) {
        fprintf(stderr, "[focus] foreground %s (%s), pid=%u [%s]\n",
                fg.package_name.c_str(),
                fg.activity.empty() ? "?" : fg.activity.c_str(),
                fg.pid,
                fg.source.c_str());
    } else if (fg.detected) {
        fprintf(stderr, "[focus] foreground %s (%s), pid unresolved; using top-%d fallback\n",
                fg.package_name.c_str(),
                fg.activity.empty() ? "?" : fg.activity.c_str(),
                top_n);
    } else {
        fprintf(stderr, "[focus] foreground app not detected; using top-%d fallback\n", top_n);
    }

    std::vector<int> perf_fds;
    int n_enter = attach_tracepoint_all_cpus(
        "/sys/fs/bpf/prog_example_tracepoint_raw_syscalls_sys_enter",
        "raw_syscalls/sys_enter",
        perf_fds
    );
    if (n_enter == 0) {
        std::cerr << "No CPUs attached. Run as root / check SELinux.\n";
        return 1;
    }

    int n_exit = attach_tracepoint_all_cpus(
        "/sys/fs/bpf/prog_example_tracepoint_raw_syscalls_sys_exit",
        "raw_syscalls/sys_exit",
        perf_fds
    );
    if (n_exit == 0) {
        fprintf(stderr,
            "[warn] sys_exit classifier program not attached; plain read/write classification will be limited.\n");
    }

    int n = (n_exit > 0) ? std::min(n_enter, n_exit) : n_enter;

    const char *STATS_MAP_PATH = "/sys/fs/bpf/map_example_io_stats_map";
    int map_fd = bpf_obj_get(STATS_MAP_PATH);
    if (map_fd < 0) {
        std::cerr << "bpf_obj_get(" << STATS_MAP_PATH << "): " << strerror(errno) << "\n";
        return 1;
    }

    int inflight_fd = -1;
    if (CLEAR_MAP_FIRST) {
        clear_map(map_fd);

        inflight_fd = bpf_obj_get("/sys/fs/bpf/map_example_inflight_map");
        if (inflight_fd >= 0) clear_map(inflight_fd);
    }

    fprintf(stderr, "[capture] waiting %d second(s)...\n", CAPTURE_SECONDS);
    sleep(CAPTURE_SECONDS);

    std::vector<pid_row> rows = read_map(map_fd, 0);

    std::vector<pid_row> active;
    for (auto &r : rows)
        if (r.total_reads + r.total_writes >= MIN_ACTIVITY)
            active.push_back(r);

    std::sort(active.begin(), active.end(), [](const pid_row &a, const pid_row &b) {
        return (a.total_reads + a.total_writes) > (b.total_reads + b.total_writes);
    });

    if ((int)active.size() > top_n) active.resize(top_n);

    pid_row focused_row = {};
    bool focused_row_found = false;
    if (focused_pid != 0) {
        for (auto &r : rows) {
            if (r.pid == focused_pid) {
                focused_row = r;
                focused_row_found = true;
                break;
            }
        }
    }

    // EDIT 3: updated header to clarify totalR/totalW meaning.
    // seq+rand will be <= total because read()/write() increment total only.
    int num_cpus = (int)sysconf(_SC_NPROCESSORS_ONLN);
    printf("\n");
        printf("%-8s %-16s | %-8s %-8s | %-8s %-8s %-8s %-8s | %-8s %-8s\n",
            "PID", "COMM", "totalR", "totalW", "seqR", "randR", "seqW", "randW", "unclsR", "unclsW");
        printf("-------- ---------------- | -------- -------- "
            "| -------- -------- -------- -------- | -------- --------\n");

    if (focused_pid != 0) {
        if (focused_row_found) {
                 uint64_t cls_r = focused_row.seq_reads + focused_row.rand_reads;
                 uint64_t cls_w = focused_row.seq_writes + focused_row.rand_writes;
                 uint64_t uncls_r = focused_row.uncls_reads;
                 uint64_t uncls_w = focused_row.uncls_writes;
                 printf("%-8u %-16s | %-8llu %-8llu | %-8llu %-8llu %-8llu %-8llu | %-8llu %-8llu\n",
                   focused_row.pid, focused_row.comm,
                   (unsigned long long)focused_row.total_reads,
                   (unsigned long long)focused_row.total_writes,
                   (unsigned long long)focused_row.seq_reads,
                   (unsigned long long)focused_row.rand_reads,
                   (unsigned long long)focused_row.seq_writes,
                     (unsigned long long)focused_row.rand_writes,
                     (unsigned long long)uncls_r,
                     (unsigned long long)uncls_w);

                 double cov_r = (focused_row.total_reads > 0)
                  ? (100.0 * (double)cls_r / (double)focused_row.total_reads) : 0.0;
                 double cov_w = (focused_row.total_writes > 0)
                  ? (100.0 * (double)cls_w / (double)focused_row.total_writes) : 0.0;
                 printf("coverage: classifiedR=%llu/%llu (%.1f%%), classifiedW=%llu/%llu (%.1f%%)\n",
                     (unsigned long long)cls_r,
                     (unsigned long long)focused_row.total_reads,
                     cov_r,
                     (unsigned long long)cls_w,
                     (unsigned long long)focused_row.total_writes,
                     cov_w);

            if (focused_row.total_writes > 0 &&
                (focused_row.seq_writes + focused_row.rand_writes) == 0) {
                printf("note: totalW>0 but seqW/randW are 0 for focused PID; writes may be unclassified by current kernel-side logic.\n");
            }
        } else {
            printf("  (no map row for focused PID=%u in %ds window; showing fallback top-%d)\n",
                   focused_pid, CAPTURE_SECONDS, top_n);
            for (auto &r : active) {
                  uint64_t uncls_r = r.uncls_reads;
                  uint64_t uncls_w = r.uncls_writes;
                  printf("%-8u %-16s | %-8llu %-8llu | %-8llu %-8llu %-8llu %-8llu | %-8llu %-8llu\n",
                       r.pid, r.comm,
                       (unsigned long long)r.total_reads,
                       (unsigned long long)r.total_writes,
                       (unsigned long long)r.seq_reads,
                       (unsigned long long)r.rand_reads,
                       (unsigned long long)r.seq_writes,
                      (unsigned long long)r.rand_writes,
                      (unsigned long long)uncls_r,
                      (unsigned long long)uncls_w);
            }
        }
    } else {
        if (active.empty()) {
            printf("  (no entries above threshold=%llu in %ds window)\n",
                   (unsigned long long)MIN_ACTIVITY, CAPTURE_SECONDS);
        } else {
            for (auto &r : active) {
                  uint64_t uncls_r = r.uncls_reads;
                  uint64_t uncls_w = r.uncls_writes;
                  printf("%-8u %-16s | %-8llu %-8llu | %-8llu %-8llu %-8llu %-8llu | %-8llu %-8llu\n",
                       r.pid, r.comm,
                       (unsigned long long)r.total_reads,
                       (unsigned long long)r.total_writes,
                       (unsigned long long)r.seq_reads,
                       (unsigned long long)r.rand_reads,
                       (unsigned long long)r.seq_writes,
                      (unsigned long long)r.rand_writes,
                      (unsigned long long)uncls_r,
                      (unsigned long long)uncls_w);
            }
        }
    }

    int shown = 0;
    if (focused_pid != 0 && focused_row_found) shown = 1;
    else shown = (int)active.size();

    printf("\n[%d shown | %zu total pids | %ds window | threshold=%llu | %d/%d CPUs]\n",
           shown, rows.size(),
           CAPTURE_SECONDS, (unsigned long long)MIN_ACTIVITY,
           n, num_cpus);

    close(map_fd);
    if (inflight_fd >= 0) close(inflight_fd);
    for (int pfd : perf_fds) close(pfd);
    return 0;
}
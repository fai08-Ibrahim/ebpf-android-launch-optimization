#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <map>
#include <chrono>
#include <ctime>
#include <cstring>
#include <cstdlib>
#include <cerrno>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <linux/perf_event.h>
#include <linux/bpf.h>
#include <errno.h>


// ============================================================================
// Configuration and Constants
// ============================================================================

constexpr int MAX_ALLOC_ORDERS = 11;

// Experiment defaults
constexpr const char* DEFAULT_PACKAGE = "com.android.gallery3d";
constexpr const char* DEFAULT_ACTIVITY = "com.android.gallery3d.app.GalleryActivity";
constexpr int DEFAULT_RUNS = 5;
constexpr int DEFAULT_LAUNCH_TIMEOUT_MS = 30000;
constexpr int STABILIZATION_DELAY_MS = 2000;  // wait between runs

// Pinned map paths (Android bpfloader-style map names for example.o)
constexpr const char* PINNED_FILE_OPEN_COUNT_MAP = "/sys/fs/bpf/map_example_file_open_count";
constexpr const char* PINNED_ORDER_COUNT_MAP = "/sys/fs/bpf/map_example_order_count_map";
constexpr const char* PINNED_LATENCY_MAX_MAP = "/sys/fs/bpf/map_example_latency_max_map";

// Pinned programs (expected bpfloader names for example.o)
constexpr const char* PINNED_PROG_SYS_ENTER = "/sys/fs/bpf/prog_example_tracepoint_raw_syscalls_sys_enter";
constexpr const char* PINNED_PROG_SYS_EXIT = "/sys/fs/bpf/prog_example_tracepoint_raw_syscalls_sys_exit";
constexpr const char* PINNED_PROG_PAGE_ALLOC = "/sys/fs/bpf/prog_example_tracepoint_kmem_mm_page_alloc";

// ============================================================================
// BPF syscall helpers (no libbpf dependency)
// ============================================================================

static int bpf_obj_get(const char *path, uint32_t file_flags = 0) {
    union bpf_attr attr = {};
    attr.pathname = reinterpret_cast<uint64_t>(path);
    attr.file_flags = file_flags;
    return syscall(__NR_bpf, BPF_OBJ_GET, &attr, sizeof(attr));
}

static int bpf_map_update_elem(int map_fd, const void *key, const void *value, uint64_t flags) {
    union bpf_attr attr = {};
    attr.map_fd = map_fd;
    attr.key = reinterpret_cast<uint64_t>(key);
    attr.value = reinterpret_cast<uint64_t>(value);
    attr.flags = flags;
    return syscall(__NR_bpf, BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
}

static int bpf_map_lookup_elem(int map_fd, const void *key, void *value) {
    union bpf_attr attr = {};
    attr.map_fd = map_fd;
    attr.key = reinterpret_cast<uint64_t>(key);
    attr.value = reinterpret_cast<uint64_t>(value);
    return syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, &attr, sizeof(attr));
}

static int bpf_map_delete_elem(int map_fd, const void *key) {
    union bpf_attr attr = {};
    attr.map_fd = map_fd;
    attr.key = reinterpret_cast<uint64_t>(key);
    return syscall(__NR_bpf, BPF_MAP_DELETE_ELEM, &attr, sizeof(attr));
}

static int bpf_map_get_next_key(int map_fd, const void *key, void *next_key) {
    union bpf_attr attr = {};
    attr.map_fd = map_fd;
    attr.key = reinterpret_cast<uint64_t>(key);
    attr.next_key = reinterpret_cast<uint64_t>(next_key);
    return syscall(__NR_bpf, BPF_MAP_GET_NEXT_KEY, &attr, sizeof(attr));
}


// ============================================================================
// Tracepoint attachment helpers
// ============================================================================
static int read_tracepoint_id(const char *tracefs_event_path) {
    char id_path[256];
    snprintf(id_path, sizeof(id_path), "/sys/kernel/tracing/events/%s/id", tracefs_event_path);
    FILE *f = fopen(id_path, "r");
    if (!f) {
        return -1;
    }
    int id = -1;
    if (fscanf(f, "%d", &id) != 1) {
        id = -1;
    }
    fclose(f);
    return id;
}

static int attach_tracepoint_all_cpus(const char *pinned_prog_path,
                                      const char *tracefs_event_path,
                                      std::vector<int> &out_fds) {
    int prog_fd = bpf_obj_get(pinned_prog_path);
    if (prog_fd < 0) {
        return -1;
    }

    int tp_id = read_tracepoint_id(tracefs_event_path);
    if (tp_id < 0) {
        close(prog_fd);
        return -1;
    }

    int num_cpus = (int)sysconf(_SC_NPROCESSORS_ONLN);
    if (num_cpus <= 0) num_cpus = 1;

    int attached = 0;
    for (int cpu = 0; cpu < num_cpus; ++cpu) {
        struct perf_event_attr attr = {};
        attr.type = PERF_TYPE_TRACEPOINT;
        attr.size = sizeof(attr);
        attr.config = (uint64_t)tp_id;
        attr.sample_period = 1;
        attr.wakeup_events = 1;

        int pfd = (int)syscall(__NR_perf_event_open, &attr, -1, cpu, -1, 0);
        if (pfd < 0) {
            continue;
        }

        if (ioctl(pfd, PERF_EVENT_IOC_SET_BPF, prog_fd) < 0) {
            if (errno != EEXIST) {
                close(pfd);
                continue;
            }
        }

        if (ioctl(pfd, PERF_EVENT_IOC_ENABLE, 0) < 0) {
            close(pfd);
            continue;
        }

        out_fds.push_back(pfd);
        attached++;
    }

    close(prog_fd);
    return attached;
}

// ============================================================================
// Experiment Configuration
// ============================================================================

struct ExperimentConfig {
    std::string package_name = DEFAULT_PACKAGE;
    std::string activity_name = DEFAULT_ACTIVITY;
    std::string output_dir = "/data/local/tmp/ebpf_results";
    int num_runs = DEFAULT_RUNS;
    int launch_timeout_ms = DEFAULT_LAUNCH_TIMEOUT_MS;
    bool enable_warmup = false;
    bool verbose = true;
};

struct RunResult {
    int run_number = 0;
    bool success = false;
    std::string error_msg;

    int64_t duration_ms = 0;
    std::chrono::system_clock::time_point start_time;
    std::chrono::system_clock::time_point end_time;

    // Aggregated metrics
    size_t unique_files_count = 0;
    uint64_t total_file_opens = 0;
    uint64_t total_file_reads = 0;
    uint64_t total_page_allocs = 0;
    uint64_t avg_latency_ns = 0;
    uint64_t max_latency_ns = 0;
};

// ============================================================================
// Utility: Execute Shell Command and Capture Output
// ============================================================================

struct CommandResult {
    int exit_code;
    std::string stdout_output;
    std::string stderr_output;
    bool success;
};

CommandResult execute_command(const std::string& cmd, bool capture_output = true) {
    CommandResult result;
    result.exit_code = -1;
    result.success = false;
    
    if (!capture_output) {
        // Simple execution without capture
        result.exit_code = system(cmd.c_str());
        result.success = (result.exit_code == 0);
        return result;
    }
    
    // Capture stdout using popen
    std::string full_cmd = cmd + " 2>&1";  // redirect stderr to stdout
    FILE* pipe = popen(full_cmd.c_str(), "r");
    if (!pipe) {
        result.stderr_output = "Failed to execute command";
        return result;
    }
    
    char buffer[256];
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        result.stdout_output += buffer;
    }
    
    int status = pclose(pipe);
    result.exit_code = WEXITSTATUS(status);
    result.success = (result.exit_code == 0);
    
    return result;
}

// ============================================================================
// Android Command Helpers
// ============================================================================

bool force_stop_app(const std::string& package, bool verbose) {
    std::string cmd = "am force-stop " + package;
    if (verbose) {
        std::cout << "[CMD] " << cmd << std::endl;
    }
    
    CommandResult res = execute_command(cmd, false);
    if (!res.success) {
        std::cerr << "Warning: force-stop failed for " << package << std::endl;
        return false;
    }
    
    // Give the system time to actually stop the process
    usleep(500000);  // 500ms
    return true;
}

bool return_to_home() {
    std::string cmd = "input keyevent KEYCODE_HOME";
    CommandResult res = execute_command(cmd, false);
    usleep(200000);  // 200ms for home screen to settle
    return res.success;
}

int get_process_pid(const std::string& package) {
    // Use pidof to find the process
    // Note: On Android, the process name is typically the package name
    std::string cmd = "pidof " + package;
    CommandResult res = execute_command(cmd, true);
    
    if (!res.success || res.stdout_output.empty()) {
        return -1;
    }
    
    // Parse the PID (pidof returns space-separated PIDs if multiple)
    std::istringstream iss(res.stdout_output);
    int pid;
    if (iss >> pid) {
        return pid;
    }
    
    return -1;
}

struct LaunchResult {
    bool success;
    int64_t total_time_ms;
    std::string error_msg;
};

// Launch app using 'am start -W' which blocks until window is displayed
// and returns timing information
LaunchResult launch_app_and_measure(const std::string& package, 
                                     const std::string& activity,
                                     int timeout_ms,
                                     bool verbose) {
    LaunchResult result;
    result.success = false;
    result.total_time_ms = 0;
    
    // Build the am start command
    // -W: wait for launch to complete
    // -n: component name
    std::string component = package + "/" + activity;
    std::string cmd = "am start -W -n " + component;
    
    if (verbose) {
        std::cout << "[CMD] " << cmd << std::endl;
    }
    
    auto start = std::chrono::steady_clock::now();
    CommandResult res = execute_command(cmd, true);
    auto end = std::chrono::steady_clock::now();
    
    if (!res.success) {
        result.error_msg = "am start command failed";
        return result;
    }
    
    // Parse the output for TotalTime
    // Example output:
    // Starting: Intent { cmp=com.android.gallery3d/.app.GalleryActivity }
    // Status: ok
    // LaunchState: COLD
    // Activity: com.android.gallery3d/.app.GalleryActivity
    // TotalTime: 823
    // WaitTime: 835
    // Complete
    
    std::istringstream iss(res.stdout_output);
    std::string line;
    bool found_total_time = false;
    
    while (std::getline(iss, line)) {
        if (line.find("TotalTime:") != std::string::npos) {
            size_t pos = line.find("TotalTime:");
            std::string time_str = line.substr(pos + 10);
            errno = 0;
            const char *start = time_str.c_str();
            char *end = nullptr;
            long long parsed = std::strtoll(start, &end, 10);
            if (errno == 0 && end != start) {
                result.total_time_ms = parsed;
                found_total_time = true;
            }
        }
    }
    
    if (!found_total_time) {
        // Fallback to wall-clock timing if parsing failed
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
        result.total_time_ms = duration.count();
        if (verbose) {
            std::cout << "Warning: Could not parse TotalTime, using wall-clock: " 
                      << result.total_time_ms << "ms" << std::endl;
        }
    }
    
    result.success = true;
    return result;
}

// ============================================================================
// BPF Map Interaction Helpers
// ============================================================================

bool clear_map(int map_fd, const std::string& map_name, bool verbose) {
    // Iterate and delete all keys
    void* prev_key = nullptr;
    void* key = malloc(256);  // max key size
    
    if (!key) return false;
    
    int deleted = 0;
    while (bpf_map_get_next_key(map_fd, prev_key, key) == 0) {
        bpf_map_delete_elem(map_fd, key);
        deleted++;
        prev_key = key;
    }
    
    free(key);
    
    if (verbose && deleted > 0) {
        std::cout << "[BPF] Cleared " << deleted << " entries from " << map_name << std::endl;
    }
    
    return true;
}

bool clear_aggregation_maps(int file_map_fd, int order_map_fd, int latency_map_fd, bool verbose) {
    clear_map(file_map_fd, "file_open_count", verbose);

    for (int i = 0; i < MAX_ALLOC_ORDERS; i++) {
        uint64_t zero = 0;
        bpf_map_update_elem(order_map_fd, &i, &zero, BPF_ANY);
    }

    int key = 0;
    uint64_t zero = 0;
    bpf_map_update_elem(latency_map_fd, &key, &zero, BPF_ANY);

    if (verbose) {
        std::cout << "[BPF] Cleared aggregation maps" << std::endl;
    }

    return true;
}

// ============================================================================
// Result Dumping Helpers
// ============================================================================

bool dump_file_activity(int file_map_fd, const std::string& output_path,
                         int run_number, bool verbose) {
    std::ofstream ofs(output_path);
    if (!ofs.is_open()) {
        std::cerr << "Failed to open file activity output: " << output_path << std::endl;
        return false;
    }
    
    // Write CSV header
    ofs << "run,pid_tgid,open_count\n";

    uint64_t key = 0;
    uint64_t next_key = 0;
    uint64_t stats = 0;
    int count = 0;
    
    while (bpf_map_get_next_key(file_map_fd, &key, &next_key) == 0) {
        if (bpf_map_lookup_elem(file_map_fd, &next_key, &stats) == 0) {
            ofs << run_number << "," << next_key << "," << stats << "\n";
            count++;
        }
        key = next_key;
    }
    
    ofs.close();
    
    if (verbose) {
        std::cout << "[DUMP] Wrote " << count << " file entries to " << output_path << std::endl;
    }
    
    return true;
}

bool dump_alloc_stats(int order_map_fd, const std::string& output_path,
                      int run_number, bool verbose) {
    std::ofstream ofs(output_path);
    if (!ofs.is_open()) {
        std::cerr << "Failed to open alloc stats output: " << output_path << std::endl;
        return false;
    }
    
    // Write CSV header
    ofs << "run,order,count\n";
    
    for (int i = 0; i < MAX_ALLOC_ORDERS; i++) {
        uint64_t count = 0;
        if (bpf_map_lookup_elem(order_map_fd, &i, &count) == 0 && count > 0) {
            ofs << run_number << "," << i << "," << count << "\n";
        }
    }
    
    ofs.close();
    
    if (verbose) {
        std::cout << "[DUMP] Wrote alloc stats to " << output_path << std::endl;
    }
    
    return true;
}

bool dump_latency_stats(int latency_map_fd, const std::string& output_path,
                        int run_number, bool verbose) {
    std::ofstream ofs(output_path);
    if (!ofs.is_open()) {
        std::cerr << "Failed to open latency stats output: " << output_path << std::endl;
        return false;
    }
    
    // Write summary header
    ofs << "run,metric,value\n";
    
    int key = 0;
    uint64_t max_ns = 0;
    if (bpf_map_lookup_elem(latency_map_fd, &key, &max_ns) == 0) {
        ofs << run_number << ",max_ns," << max_ns << "\n";
    }
    
    ofs.close();
    
    if (verbose) {
        std::cout << "[DUMP] Wrote latency stats to " << output_path << std::endl;
    }
    
    return true;
}

bool dump_run_summary(const std::string& output_path, const RunResult& result,
                      const ExperimentConfig& cfg) {
    // Append to summary CSV
    std::ofstream ofs;
    bool write_header = false;
    
    // Check if file exists
    struct stat buffer;
    if (stat(output_path.c_str(), &buffer) != 0) {
        write_header = true;
    }
    
    ofs.open(output_path, std::ios::app);
    if (!ofs.is_open()) {
        std::cerr << "Failed to open summary output: " << output_path << std::endl;
        return false;
    }
    
    if (write_header) {
        ofs << "run,mode,package,success,duration_ms,unique_files,total_opens,"
            << "total_reads,total_allocs,avg_latency_ns,max_latency_ns,timestamp\n";
    }
    
    // Format timestamp
    auto tt = std::chrono::system_clock::to_time_t(result.start_time);
    char time_buf[32];
    strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", localtime(&tt));
    
    ofs << result.run_number << ","
        << "baseline" << ","
        << cfg.package_name << ","
        << (result.success ? "true" : "false") << ","
        << result.duration_ms << ","
        << result.unique_files_count << ","
        << result.total_file_opens << ","
        << result.total_file_reads << ","
        << result.total_page_allocs << ","
        << result.avg_latency_ns << ","
        << result.max_latency_ns << ","
        << time_buf << "\n";
    
    ofs.close();
    return true;
}

// ============================================================================
// Warm-up Placeholder (for future implementation)
// ============================================================================

// This function is a placeholder for the future file warm-up phase.
// In the baseline experiment, it does nothing.
// In the warm-up experiment, it will:
//   1. Read a list of startup-critical files (identified from baseline runs)
//   2. Perform a sequential read of those files to warm the page cache
//   3. Return true if warm-up succeeded
// The warm-up should happen AFTER force-stop but BEFORE launch and tracing.
bool perform_file_warmup(const ExperimentConfig& cfg, int run_idx) {
    if (!cfg.enable_warmup) {
        return true;  // No-op in baseline mode
    }
    
    // FUTURE IMPLEMENTATION:
    // 1. Load warmup file list from cfg.output_dir + "/warmup_files.txt"
    // 2. For each file: open, read sequentially, close
    // 3. Log warm-up completion
    
    if (cfg.verbose) {
        std::cout << "[WARMUP] Placeholder - warm-up would happen here" << std::endl;
    }
    
    return true;
}

// ============================================================================
// Per-Run Experiment Execution
// ============================================================================

RunResult run_cold_launch_once(const ExperimentConfig& cfg,
                                int run_number,
                                int file_map_fd,
                                int order_map_fd,
                                int latency_map_fd) {
    RunResult result;
    result.run_number = run_number;
    result.success = false;
    result.duration_ms = 0;
    
    std::cout << "\n=== Run " << run_number << " ===" << std::endl;
    
    // Step 1: Force stop the app
    if (cfg.verbose) {
        std::cout << "[1/8] Force stopping " << cfg.package_name << std::endl;
    }
    force_stop_app(cfg.package_name, cfg.verbose);
    
    // Step 2: Return to home screen
    if (cfg.verbose) {
        std::cout << "[2/8] Returning to home screen" << std::endl;
    }
    return_to_home();
    
    // Step 3: Clear BPF maps from previous run
    if (cfg.verbose) {
        std::cout << "[3/8] Clearing BPF aggregation maps" << std::endl;
    }
    clear_aggregation_maps(file_map_fd, order_map_fd, latency_map_fd, cfg.verbose);
    
    // Step 4: Perform warm-up if enabled (placeholder for now)
    if (cfg.verbose) {
        std::cout << "[4/8] Warm-up phase" << std::endl;
    }
    if (!perform_file_warmup(cfg, run_number)) {
        result.error_msg = "Warm-up failed";
        return result;
    }
    
    // Step 5: Tracing is always on in the kernel program (no config map)
    
    // Step 6: Launch app and measure
    if (cfg.verbose) {
        std::cout << "[6/8] Launching app" << std::endl;
    }
    
    result.start_time = std::chrono::system_clock::now();
    
    LaunchResult launch = launch_app_and_measure(cfg.package_name, 
                                                  cfg.activity_name,
                                                  cfg.launch_timeout_ms,
                                                  cfg.verbose);
    
    result.end_time = std::chrono::system_clock::now();
    
    if (!launch.success) {
        result.error_msg = launch.error_msg;
        return result;
    }
    
    result.duration_ms = launch.total_time_ms;
    
    // Step 7: Tracing is always on in the kernel program (no config map)
    
    // Step 8: Collect BPF map data
    if (cfg.verbose) {
        std::cout << "[8/8] Collecting results" << std::endl;
    }
    
    // Create output filenames
    char run_suffix[16];
    snprintf(run_suffix, sizeof(run_suffix), "%03d", run_number);
    
    std::string file_output = cfg.output_dir + "/run_" + run_suffix + "_files.csv";
    std::string alloc_output = cfg.output_dir + "/run_" + run_suffix + "_alloc.csv";
    std::string latency_output = cfg.output_dir + "/run_" + run_suffix + "_latency.csv";
    
    dump_file_activity(file_map_fd, file_output, run_number, cfg.verbose);
    dump_alloc_stats(order_map_fd, alloc_output, run_number, cfg.verbose);
    dump_latency_stats(latency_map_fd, latency_output, run_number, cfg.verbose);
    
    // Compute summary statistics from maps
    uint64_t key = 0;
    uint64_t next_key = 0;
    uint64_t count = 0;
    result.unique_files_count = 0;
    result.total_file_opens = 0;
    result.total_file_reads = 0;

    while (bpf_map_get_next_key(file_map_fd, &key, &next_key) == 0) {
        if (bpf_map_lookup_elem(file_map_fd, &next_key, &count) == 0) {
            result.unique_files_count++;
            result.total_file_opens += count;
        }
        key = next_key;
    }

    result.total_page_allocs = 0;
    for (int order = 0; order < MAX_ALLOC_ORDERS; order++) {
        uint64_t c = 0;
        if (bpf_map_lookup_elem(order_map_fd, &order, &c) == 0) {
            result.total_page_allocs += c;
        }
    }

    int lkey = 0;
    uint64_t max_ns = 0;
    if (bpf_map_lookup_elem(latency_map_fd, &lkey, &max_ns) == 0) {
        result.avg_latency_ns = 0;
        result.max_latency_ns = max_ns;
    }

    result.success = true;
    
    std::cout << "Launch time: " << result.duration_ms << " ms" << std::endl;
    std::cout << "Files touched: " << result.unique_files_count << std::endl;
    std::cout << "Page allocs: " << result.total_page_allocs << std::endl;
    
    return result;
}

// ============================================================================
// BPF Loading and Setup
// ============================================================================

struct BPFContext {
    int file_open_count_fd;
    int order_count_fd;
    int latency_max_fd;
    std::vector<int> perf_fds;
    
    BPFContext() : file_open_count_fd(-1), order_count_fd(-1),
                   latency_max_fd(-1) {}
};

bool load_and_attach_bpf(BPFContext& ctx, bool verbose) {
    ctx.file_open_count_fd = bpf_obj_get(PINNED_FILE_OPEN_COUNT_MAP);
    ctx.order_count_fd = bpf_obj_get(PINNED_ORDER_COUNT_MAP);
    ctx.latency_max_fd = bpf_obj_get(PINNED_LATENCY_MAX_MAP);

    if (ctx.file_open_count_fd < 0) {
        std::cerr << "Error: failed to open " << PINNED_FILE_OPEN_COUNT_MAP
                  << ": " << strerror(errno) << std::endl;
    }
    if (ctx.order_count_fd < 0) {
        std::cerr << "Error: failed to open " << PINNED_ORDER_COUNT_MAP
                  << ": " << strerror(errno) << std::endl;
    }
    if (ctx.latency_max_fd < 0) {
        std::cerr << "Error: failed to open " << PINNED_LATENCY_MAX_MAP
                  << ": " << strerror(errno) << std::endl;
    }

    if (verbose) {
        std::cout << "[BPF] Opened pinned maps:" << std::endl;
        std::cout << "  " << PINNED_FILE_OPEN_COUNT_MAP << " (fd=" << ctx.file_open_count_fd << ")" << std::endl;
        std::cout << "  " << PINNED_ORDER_COUNT_MAP << " (fd=" << ctx.order_count_fd << ")" << std::endl;
        std::cout << "  " << PINNED_LATENCY_MAX_MAP << " (fd=" << ctx.latency_max_fd << ")" << std::endl;
    }

    if (ctx.file_open_count_fd < 0 || ctx.order_count_fd < 0 || ctx.latency_max_fd < 0) {
        std::cerr << "Error: failed to open pinned maps. Ensure the BPF program is loaded and maps are pinned."
                  << std::endl;
        return false;
    }

    // Ensure tracepoint programs are actually attached (bpfloader pins but may not attach).
    int n_enter = attach_tracepoint_all_cpus(PINNED_PROG_SYS_ENTER,
                                             "raw_syscalls/sys_enter",
                                             ctx.perf_fds);
    int n_exit = attach_tracepoint_all_cpus(PINNED_PROG_SYS_EXIT,
                                            "raw_syscalls/sys_exit",
                                            ctx.perf_fds);
    int n_alloc = attach_tracepoint_all_cpus(PINNED_PROG_PAGE_ALLOC,
                                             "kmem/mm_page_alloc",
                                             ctx.perf_fds);

    if (n_enter <= 0 && n_exit <= 0 && n_alloc <= 0) {
        std::cerr << "Error: failed to attach tracepoints. Programs may not be pinned or tracefs missing."
                  << std::endl;
        return false;
    }

    if (verbose) {
        std::cout << "[BPF] Attached tracepoints: sys_enter=" << n_enter
                  << " sys_exit=" << n_exit
                  << " mm_page_alloc=" << n_alloc << std::endl;
    }

    return true;
}


void cleanup_bpf(BPFContext& ctx) {
    for (int fd : ctx.perf_fds) {
        close(fd);
    }
    ctx.perf_fds.clear();
}

// ============================================================================
// Main
// ============================================================================

int main(int argc, char* argv[]) {
    (void)argc;
    (void)argv;
    ExperimentConfig cfg;
    
    std::cout << "Android Cold-Launch eBPF Experiment" << std::endl;
    std::cout << "====================================" << std::endl;
    std::cout << "Package: " << cfg.package_name << std::endl;
    std::cout << "Activity: " << cfg.activity_name << std::endl;
    std::cout << "Runs: " << cfg.num_runs << std::endl;
    std::cout << "Output: " << cfg.output_dir << std::endl;
    std::cout << "Mode: baseline" << std::endl;
    std::cout << std::endl;
    
    // Create output directory
    std::string mkdir_cmd = "mkdir -p " + cfg.output_dir;
    execute_command(mkdir_cmd, false);
    
    // Load and attach BPF programs
    BPFContext bpf_ctx;
    if (!load_and_attach_bpf(bpf_ctx, cfg.verbose)) {
        std::cerr << "Failed to load BPF programs" << std::endl;
        return 1;
    }
    
    std::cout << "BPF programs loaded and attached successfully\n" << std::endl;
    
    // Run the experiment
    std::vector<RunResult> results;
    std::string summary_path = cfg.output_dir + "/summary.csv";
    
    for (int i = 1; i <= cfg.num_runs; i++) {
        RunResult result = run_cold_launch_once(cfg, i,
                                                 bpf_ctx.file_open_count_fd,
                                                 bpf_ctx.order_count_fd,
                                                 bpf_ctx.latency_max_fd);
        
        results.push_back(result);
        dump_run_summary(summary_path, result, cfg);
        
        if (!result.success) {
            std::cerr << "Run " << i << " failed: " << result.error_msg << std::endl;
            // Continue with remaining runs
        }
        
        // Stabilization delay between runs (except after last run)
        if (i < cfg.num_runs) {
            if (cfg.verbose) {
                std::cout << "Waiting " << STABILIZATION_DELAY_MS << "ms before next run..." << std::endl;
            }
            usleep(STABILIZATION_DELAY_MS * 1000);
        }
    }
    
    // Print summary
    std::cout << "\n=== Experiment Complete ===" << std::endl;
    std::cout << "Total runs: " << cfg.num_runs << std::endl;
    
    int successful = 0;
    int64_t total_time = 0;
    for (const auto& r : results) {
        if (r.success) {
            successful++;
            total_time += r.duration_ms;
        }
    }
    
    std::cout << "Successful: " << successful << std::endl;
    if (successful > 0) {
        std::cout << "Average launch time: " << (total_time / successful) << " ms" << std::endl;
    }
    std::cout << "Results saved to: " << cfg.output_dir << std::endl;
    
    // Cleanup
    cleanup_bpf(bpf_ctx);
    
    return 0;
}
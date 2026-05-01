#include <linux/bpf.h>
#include <stdbool.h>
#include <stdint.h>
#include <bpf_helpers.h>

// arm64 syscall numbers
#define __NR_close      57
#define __NR_lseek      62
#define __NR_read       63
#define __NR_write      64
#define __NR_openat     56
#define __NR_openat2    437
#define __NR_pread64    67
#define __NR_pwrite64   68

#define __ESPIPE        29

// map 1: per-TGID I/O counters read by monitor
struct io_stats {
    uint64_t total_reads;    // read() + pread64() calls
    uint64_t total_writes;   // write() + pwrite64() calls
    uint64_t seq_reads;      // classified sequential reads
    uint64_t rand_reads;     // classified random reads
    uint64_t seq_writes;     // classified sequential writes
    uint64_t rand_writes;    // classified random writes
    uint64_t uncls_reads;    // explicit unclassified reads
    uint64_t uncls_writes;   // explicit unclassified writes
};
DEFINE_BPF_MAP(io_stats_map, HASH, uint32_t, struct io_stats, 1024);

// map 2: per-(tgid,fd) stream state
struct file_key {
    uint32_t pid;  // TGID (process id)
    int fd;
};

struct file_state {
    uint64_t last_end;       // end offset of previous classified access (read or write)
    uint64_t cursor;         // trusted cursor (learned from lseek or explicit positional ops)
    uint32_t last_valid;
    uint32_t cursor_valid;
    uint32_t nonseekable;    // set after lseek(...)= -ESPIPE
    uint32_t _pad;
};
DEFINE_BPF_MAP(file_state_map, HASH, struct file_key, struct file_state, 4096);

// map 3: per-thread syscall context (sys_enter -> sys_exit)
enum inflight_op {
    OP_READ = 1,
    OP_WRITE,
    OP_PREAD,
    OP_PWRITE,
    OP_OPENAT,
    OP_OPENAT2,
    OP_LSEEK,
    OP_CLOSE,
};

struct inflight_state {
    uint32_t tgid;
    int32_t fd;
    uint8_t op;
    uint8_t _pad0;
    uint16_t _pad1;
    uint64_t pos;  // explicit offset for pread/pwrite
};
DEFINE_BPF_MAP(inflight_map, HASH, uint64_t, struct inflight_state, 8192);

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

static __always_inline struct io_stats *get_io_stats(uint32_t pid) {
    struct io_stats *s = bpf_io_stats_map_lookup_elem(&pid);
    if (!s) {
        struct io_stats zero = {};
        bpf_io_stats_map_update_elem(&pid, &zero, BPF_ANY);
        s = bpf_io_stats_map_lookup_elem(&pid);
    }
    return s;
}

static __always_inline struct file_state *get_file_state(struct file_key *k) {
    struct file_state *fs = bpf_file_state_map_lookup_elem(k);
    if (!fs) {
        struct file_state zero = {};
        bpf_file_state_map_update_elem(k, &zero, BPF_ANY);
        fs = bpf_file_state_map_lookup_elem(k);
    }
    return fs;
}

static __always_inline void bump_unclassified(struct io_stats *s, bool is_read) {
    if (is_read) {
        s->uncls_reads += 1;
    } else {
        s->uncls_writes += 1;
    }
}

static __always_inline void classify_with_pos(struct io_stats *s,
                                              struct file_state *fs,
                                              bool is_read,
                                              uint64_t start,
                                              uint64_t len) {
    bool is_seq = (!fs->last_valid || start == fs->last_end);

    if (is_read) {
        if (is_seq) {
            s->seq_reads += 1;
        } else {
            s->rand_reads += 1;
        }
    } else {
        if (is_seq) {
            s->seq_writes += 1;
        } else {
            s->rand_writes += 1;
        }
    }

    fs->last_end = start + len;
    fs->last_valid = 1;
}

DEFINE_BPF_PROG("tracepoint/raw_syscalls/sys_enter", AID_ROOT, AID_SYSTEM, tp_sys_enter)
(struct raw_syscalls_sys_enter_args *args) {
    long syscall_id = args->id;

    if (syscall_id != __NR_read &&
        syscall_id != __NR_write &&
        syscall_id != __NR_pread64 &&
        syscall_id != __NR_pwrite64 &&
        syscall_id != __NR_openat &&
        syscall_id != __NR_openat2 &&
        syscall_id != __NR_lseek &&
        syscall_id != __NR_close) {
        return 1;
    }

    uint64_t pid_tgid = bpf_get_current_pid_tgid();
    uint32_t tgid = (uint32_t)(pid_tgid >> 32);
    uint64_t tid_key = pid_tgid;

    struct inflight_state in = {};
    in.tgid = tgid;

    if (syscall_id == __NR_read) {
        in.op = OP_READ;
        in.fd = (int32_t)args->args[0];
        bpf_inflight_map_update_elem(&tid_key, &in, BPF_ANY);
        return 1;
    }

    if (syscall_id == __NR_write) {
        in.op = OP_WRITE;
        in.fd = (int32_t)args->args[0];
        bpf_inflight_map_update_elem(&tid_key, &in, BPF_ANY);
        return 1;
    }

    if (syscall_id == __NR_pread64) {
        in.op = OP_PREAD;
        in.fd = (int32_t)args->args[0];
        in.pos = (uint64_t)args->args[3];
        bpf_inflight_map_update_elem(&tid_key, &in, BPF_ANY);
        return 1;
    }

    if (syscall_id == __NR_pwrite64) {
        in.op = OP_PWRITE;
        in.fd = (int32_t)args->args[0];
        in.pos = (uint64_t)args->args[3];
        bpf_inflight_map_update_elem(&tid_key, &in, BPF_ANY);
        return 1;
    }

    if (syscall_id == __NR_lseek) {
        in.op = OP_LSEEK;
        in.fd = (int32_t)args->args[0];
        bpf_inflight_map_update_elem(&tid_key, &in, BPF_ANY);
        return 1;
    }

    if (syscall_id == __NR_openat) {
        in.op = OP_OPENAT;
        bpf_inflight_map_update_elem(&tid_key, &in, BPF_ANY);
        return 1;
    }

    if (syscall_id == __NR_openat2) {
        in.op = OP_OPENAT2;
        bpf_inflight_map_update_elem(&tid_key, &in, BPF_ANY);
        return 1;
    }

    if (syscall_id == __NR_close) {
        in.op = OP_CLOSE;
        in.fd = (int32_t)args->args[0];
        bpf_inflight_map_update_elem(&tid_key, &in, BPF_ANY);
        return 1;
    }

    return 1;
}

DEFINE_BPF_PROG("tracepoint/raw_syscalls/sys_exit", AID_ROOT, AID_SYSTEM, tp_sys_exit)
(struct raw_syscalls_sys_exit_args *args) {
    uint64_t tid_key = bpf_get_current_pid_tgid();
    struct inflight_state *in = bpf_inflight_map_lookup_elem(&tid_key);
    if (!in) return 1;

    struct io_stats *s = get_io_stats(in->tgid);
    if (!s) {
        bpf_inflight_map_delete_elem(&tid_key);
        return 1;
    }

    long ret = args->ret;

    if (in->op == OP_READ || in->op == OP_WRITE ||
        in->op == OP_PREAD || in->op == OP_PWRITE) {
        bool is_read = (in->op == OP_READ || in->op == OP_PREAD);

        if (is_read) {
            s->total_reads += 1;
        } else {
            s->total_writes += 1;
        }

        struct file_key fk = { .pid = in->tgid, .fd = in->fd };
        struct file_state *fs = get_file_state(&fk);
        if (!fs) {
            bump_unclassified(s, is_read);
            bpf_inflight_map_delete_elem(&tid_key);
            return 1;
        }

        if (ret <= 0) {
            bump_unclassified(s, is_read);
            bpf_inflight_map_delete_elem(&tid_key);
            return 1;
        }

        uint64_t len = (uint64_t)ret;

        if (in->op == OP_PREAD || in->op == OP_PWRITE) {
            classify_with_pos(s, fs, is_read, in->pos, len);
            fs->nonseekable = 0;
            // Keep cursor in sync when we have an explicit position anchor.
            fs->cursor = in->pos + len;
            fs->cursor_valid = 1;
        } else {
            if (fs->nonseekable) {
                bump_unclassified(s, is_read);
            } else if (!fs->cursor_valid) {
                // For plain read/write without an explicit anchor, start with
                // a sequential baseline so subsequent accesses can be compared.
                classify_with_pos(s, fs, is_read, 0, len);
                fs->cursor = len;
                fs->cursor_valid = 1;
            } else {
                uint64_t start = fs->cursor;
                classify_with_pos(s, fs, is_read, start, len);
                fs->cursor = start + len;
                fs->cursor_valid = 1;
            }
        }
    } else if (in->op == OP_LSEEK) {
        struct file_key fk = { .pid = in->tgid, .fd = in->fd };
        struct file_state *fs = get_file_state(&fk);
        if (fs) {
            if (ret >= 0) {
                fs->cursor = (uint64_t)ret;
                fs->cursor_valid = 1;
                fs->nonseekable = 0;
            } else if (ret == -__ESPIPE) {
                fs->nonseekable = 1;
                fs->cursor_valid = 0;
            }
        }
    } else if (in->op == OP_CLOSE) {
        if (ret == 0) {
            struct file_key fk = { .pid = in->tgid, .fd = in->fd };
            bpf_file_state_map_delete_elem(&fk);
        }
    } else if (in->op == OP_OPENAT || in->op == OP_OPENAT2) {
        if (ret >= 0) {
            struct file_key fk = { .pid = in->tgid, .fd = (int32_t)ret };
            struct file_state *fs = get_file_state(&fk);
            if (fs) {
                fs->cursor = 0;
                fs->cursor_valid = 1;
                fs->nonseekable = 0;
            }
        }
    }

    bpf_inflight_map_delete_elem(&tid_key);
    return 1;
}

LICENSE("GPL");

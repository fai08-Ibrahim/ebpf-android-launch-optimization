# Exploring Cold App Launch Behavior on Android using eBPF

> A characterization and optimization study of storage and memory activity during Android app startup.

**CS7601 — Operating Systems · Spring 2026 · Final Project**
**Author:** Fathy Ibrahim

---

## 📌 Overview

This project investigates a straightforward question:

> *Can eBPF-based kernel observation help us understand — and actually reduce — repeated cold-launch overhead on Android?*

The work is divided into two parts:

1. **Characterization** — three eBPF-based studies that profile Android kernel-level behavior during real workloads (file I/O, memory allocation size, and allocation latency).
2. **Exploration** — lightweight optimization attempts targeting cold launches of the AOSP **Gallery** app, evaluated against a controlled baseline.

The main result is that **a small, kernel-informed scheduling intervention reduces Gallery cold-launch time from ~203 ms to ~136 ms** — a meaningful and reproducible improvement limited specifically to the launch window.

All experiments are repeated multiple times (4 runs for characterization and 5 runs for exploration) and reported using both averages and per-run values.

---

## 🖼️ Why Gallery?

The AOSP **Gallery** app was deliberately selected as the case study for the optimization portion of the project for several reasons:

- It is an app **almost every Android user opens multiple times a day** — to view photos, share images, check screenshots, and so on.
- Its launch path is **storage-sensitive**, **repeatable**, and **largely independent of network conditions**, unlike cloud-backed or login-heavy apps.
- It has a **clearly defined visible result** (the gallery grid appears), which makes cold-launch time straightforward to measure.

This matters because the user-side and kernel-side optimizations explored here both aim to **reduce launch time across repeated cold launches** — exactly the kind of real-world usage pattern Gallery already exhibits. An improvement of ~70 ms per launch may sound modest, but across repeated daily use it becomes a tangible gain in perceived responsiveness.

---

## 🧠 Part I — Characterization (Brief)

Three eBPF programs were built to profile different kernel-level dimensions on a real Android device.

### Task 1 — File I/O Pattern Analysis
Classifies syscalls as **sequential**, **random**, or **unclassified** using a dual-hook design (`sys_enter` + `sys_exit`) with per-(PID, fd) state tracking to recover offsets.

> **Key insight:** Even when the user is clearly performing random access (for example, seeking through a video), the kernel-level view of the *foreground* process appears almost entirely sequential. Media services (`mediaserver`, `mediaextractor`, codecs) absorb the random behavior internally.

### Task 2 — Page Allocation Order
Profiles allocation sizes (in powers of two) using the `kmem/mm_page_alloc` tracepoint.

> **Key insight:** Order-0 (single 4 KB page) allocations dominate at ~99% across all workloads. Higher-order allocations become measurable only under sustained workloads such as image rendering.

### Task 3 — Page Allocation Latency
Adds timing measurement using a kprobe on `__alloc_pages` plus the existing tracepoint, correlated through an in-flight map keyed by `pid_tgid`.

> **Key insight:** Heavier workloads produce *lower* average allocation latency (~2–4 µs under scrolling vs. ~25–55 µs while idle) because the allocator's fast paths remain warm — but the **maximum** latency stays high regardless, with occasional spikes up to 4 ms.

---

## 🚀 Part II — Exploration (Main Focus)

The exploration uses the AOSP **Gallery** app as a focused and repeatable target. A *cold launch* is defined operationally as launching Gallery after force-stopping it. Every measurement is repeated **5 times**.

### Baseline

Before any optimization is applied, repeated cold launches are measured under the unmodified system — with no warm-up, no kernel-side optimization, and no preloading. This serves as the reference point against which all other results are compared.

| Metric | 5-Run Average |
|---|---|
| Gallery cold-launch time | **203.4 ms** |
| Files touched during launch | 18.2 |
| Total page allocations | 5,708.6 |

The baseline is stable enough across runs to support a controlled comparison. Every optimization result below is interpreted **relative to this baseline**.

> ⚠️ **Critical:** Before running any baseline, you **must** follow the full cleanup procedure (see [Reproducing the Experiments](#️-reproducing-the-experiments)) to ensure an authentic cold-launch state. Skipping this step biases the baseline because page caches, ART/Dex caches, and profile-guided compilation artifacts persist across runs and even reboots.

---

### 🧪 The Four Optimization Experiments

Two were attempted on the user-space side (in `monitor_example.cpp`) and two on the kernel side (in `example.c`). On each side, one was weak or unsuccessful, and one produced meaningful results.

| # | Side | Approach | Result |
|---|---|---|---|
| 1 | User-space | Generic pre-launch warm-up | ❌ **Failed** *(report only)* |
| 2 | User-space | Observation-guided file warm-up | ✅ **Improved launch time** |
| 3 | Kernel-side | Selective tracing / launch-process locking | ❌ **Misleading** |
| 4 | Kernel-side | Kernel-guided priority boost | ✅ **Strongest result** |

---

#### ❌ Experiment 1 — Simple Pre-Launch Warm-Up *(Failed — Report Only)*

The idea was to launch Gallery once briefly, kill it, and then launch it again for measurement — with the hope that the second launch would benefit from a warmed state.

**Why it failed:** the baseline protocol *already* involves repeated launches with short gaps, so the system is partially warm to begin with. An additional generic launch does not create a meaningfully different cache state, and the extra churn sometimes made things worse.

> This experiment is **not** preserved as a folder in the repo because it produced no usable artifacts. It is documented in the report as a negative result that motivated the design of Experiment 2.

> **Lesson:** A generic warm-up does nothing that the baseline is not already doing implicitly. To have any effect, an intervention must either be **observation-informed** or **change actual launch conditions** (rather than simply repeating the launch).

---

#### ✅ Experiment 2 — Observation-Guided User-Space Warm-Up *(Successful)*

This experiment replaces the generic warm-up with a real, observed startup-file list:

1. Run a short **unmeasured** launch of Gallery.
2. Walk `/proc/<pid>/fd` to capture which files Gallery actually opens at startup.
3. Save them to `warmup_files.txt`.
4. Before each measured launch, **pre-read a small chunk from each file** to populate the Linux page cache.

**Result:** Launch time improved visibly relative to the baseline. Page allocations and file-touch counts remained close to baseline (the optimization works through caching, not by changing the startup path).

> 💡 **No need to rebuild or switch folders for the comparison.** The same monitor binary in `exploration/exploration_user/` supports both baseline and warm-up modes, toggled by an environment variable. See the [Reproducing the Experiments](#️-reproducing-the-experiments) section.

> ⚠️ **Methodological note:** Re-running the baseline *after* warm-up experiments does not produce a truly cold state — the page cache, ART/Dex cache, and profile-guided compilation artifacts persist across runs and even reboots. Always collect the baseline **first**, or actively reset caches with `drop_caches`, `cmd package compile --reset`, and `pm clear`.

---

#### ❌ Experiment 3 — Selective Kernel-Side Tracing *(Failed but Informative)*

The eBPF program identifies the first TGID that performs a startup `openat`/`openat2` after map reset, then **locks tracing to that process only** and caps further open counting after enough early opens are recorded.

**Numerical results:**

| Metric | Baseline | This Experiment |
|---|---|---|
| Avg launch time | ~201 ms | ~192 ms |
| Page allocations / run | ~4,700–4,800 | ~320–322 |
| Files touched / run | 16–18 | 0–1 |

The 9 ms difference in launch time is **within run-to-run noise**. The dramatic 15× drop in counted allocations and the collapse in files touched to nearly zero look impressive, but they are an **artifact of narrowing the observation scope**, not a real performance gain.

> **Lesson:** Reducing what you *count* is not the same as reducing what the system *does*. To improve launch time, the intervention must change actual execution conditions.

---

#### ✅ Experiment 4 — Kernel-Guided Launch Priority Boost *(Strongest Result)*

This is the experiment that actually works.

**Mechanism:**
1. The eBPF program captures the first TGID performing startup `openat`/`openat2` immediately after maps reset.
2. The user-space monitor reads that TGID and applies `renice -10` to it — but **only for the launch window**.
3. Once the launch completes, priority returns to normal.

The intervention is *kernel-informed* (the target process is identified through kernel-side tracing rather than guessed in user space) but relies on a standard, well-understood scheduling mechanism. It is tightly scoped to Gallery startup and does not require deep modification of Android internals.

**Results across 5 runs:**

| Metric | Baseline | Optimized | Change |
|---|---|---|---|
| **Avg launch time** | **203.4 ms** | **136 ms** | **↓ ~33%** |
| Per-run launch times | 204, 201, 194, 203, 203 ms | 125, 137, 130, 148, 140 ms | — |
| Files touched | 16–18 | 18–21 | comparable |
| Page allocations | ~5,700 | ~8,500–8,700 | ↑ |

The increase in allocations is **not a regression** — it is consistent with the launch process executing more aggressively when given additional CPU time, completing more work within the same window.

> 💡 **No need to rebuild or switch folders for the comparison.** The same monitor binary in `exploration/exploration_kernel/` supports both baseline and optimized modes, toggled by an environment variable. See the [Reproducing the Experiments](#️-reproducing-the-experiments) section.

> **Why it's defensible:** The intervention does not broadly alter Android internals. It applies a small, tightly scoped scheduling advantage to the specific process performing the launch, identified through kernel-side observation, and only during the launch window itself.

---

## 📊 Summary

| Approach | Side | Outcome |
|---|---|---|
| Generic pre-launch warm-up | User-space | ❌ Failed |
| Observation-guided file warm-up | User-space | ✅ Meaningful improvement |
| Selective kernel-side tracing | Kernel | ❌ Misleading (changed observation, not behavior) |
| **Kernel-guided priority boost** | **Kernel** | ✅ **~33% reduction in cold-launch time** |

The strongest result comes from combining **kernel-side observation** (to identify the right process at the right moment) with a **standard user-space scheduling mechanism** (to act on that information). Neither component alone would have been sufficient.

---

## 📁 Repository Structure

```
.
├── README.md                              # This file
├── report/
│   ├── ebpf_report.pdf                    # Full technical report
│   └── ebpf_report.tex                    # LaTeX source
│
├── characterization/                      # Part I — three eBPF profiling tasks
│   ├── task1_io_patterns/
│   │   ├── example.c                      # Kernel-side eBPF program (source)
│   │   ├── example.o                      # Compiled BPF object
│   │   ├── monitor_example.cpp            # User-space monitor (source)
│   │   ├── monitor_example                # Compiled monitor binary
│   │   └── libc++_shared.so               # NDK runtime dependency
│   ├── task2_page_alloc_order/
│   │   └── (same file layout as task1)
│   └── task3_alloc_latency/
│       └── (same file layout as task1)
│
└── exploration/                           # Part II — Gallery cold-launch optimization
    ├── exploration_baseline/              # Unmodified reference condition
    │   ├── example.c
    │   ├── example.o
    │   ├── monitor_example.cpp
    │   ├── monitor_example
    │   ├── libc++_shared.so
    │   └── script                         # Jupyter notebook for plot generation
    │
    ├── exploration_user/                  # Experiment 2: observation-guided warm-up
    │   ├── example.c
    │   ├── example.o
    │   ├── monitor_example.cpp
    │   ├── monitor_example
    │   ├── libc++_shared.so
    │   └── script                         # Same Jupyter notebook for plotting
    │
    └── exploration_kernel/                # Experiment 4: kernel-guided priority boost
        ├── example.c
        ├── example.o
        ├── monitor_example.cpp
        ├── monitor_example
        ├── libc++_shared.so
        └── script                         # Same Jupyter notebook for plotting
```

> 📓 **About the `script` files:** Each exploration folder contains the same Jupyter notebook used to generate the plots in the report (along with several others not included there). After pulling `ebpf_results/` from the device into the same directory as the script, open it in **JupyterLab** to generate per-run charts, averages, and comparisons.

> ❌ **Note on Experiment 1 (failed user-space warm-up):** Not preserved as a folder because it produced no usable artifacts. It is fully discussed in the report as a negative result that informed the design of Experiment 2.

---

## ⚙️ Reproducing the Experiments

### Build (WSL on Windows)

```bash
# Compile kernel-side eBPF program
cd ~/ebpf_project
cp <path-to>/example.c .
make                                    # produces example.o

# Compile user-space monitor with Android NDK
cp <path-to>/monitor_example.cpp ~/ebpf_project/jni/
~/android-ndk-r27d/ndk-build \
    NDK_PROJECT_PATH=. \
    NDK_APPLICATION_MK=Application.mk \
    APP_BUILD_SCRIPT=jni/Android.mk
# Outputs:
#   ~/ebpf_project/libs/arm64-v8a/monitor_example
#   ~/ebpf_project/libs/arm64-v8a/libc++_shared.so
```

### Deploy to Device

```bash
adb root
adb push example.o monitor_example libc++_shared.so /data/local/tmp/
adb shell chmod +x /data/local/tmp/monitor_example

# Install eBPF object to system location
adb remount
adb shell cp /data/local/tmp/example.o /system/etc/bpf/
adb shell chmod 644 /system/etc/bpf/example.o
adb reboot
adb root

# Verify the eBPF object loaded
adb shell "ls /sys/fs/bpf | grep example"
```

---

### 🧹 Mandatory Cleanup Before Any Baseline Run

> ⚠️ **This step is non-negotiable.** Without it, the baseline is biased by residual cache state from earlier runs, and any comparison against the optimized configurations becomes meaningless.

```bash
adb shell "rm /data/local/tmp/ebpf_results/warmup_files.txt"
adb shell "am force-stop com.android.gallery3d"
adb shell "pm clear com.android.gallery3d"
adb shell "cmd package compile --reset com.android.gallery3d"
adb shell "sync; echo 3 > /proc/sys/vm/drop_caches"
```

These commands respectively remove the warm-up file list (if it exists), force-stop Gallery, clear its app data, reset profile-guided compilation, and drop the kernel page cache — together restoring a genuinely cold initial state.

---

### ▶️ Running Each Configuration

The same monitor binary in each exploration folder supports **both baseline and optimized modes** — toggled by environment variables. **You do not need to rebuild or switch folders to compare baseline vs. optimized.**

#### From `exploration/exploration_baseline/`

*Reference measurements — always run this first, after the cleanup steps above.*

```bash
adb shell "export LD_LIBRARY_PATH=/data/local/tmp:$LD_LIBRARY_PATH; \
           /data/local/tmp/monitor_example"
```

#### From `exploration/exploration_user/`

*Observation-guided user-space warm-up (Experiment 2). The same binary supports both modes:*

```bash
# Baseline mode (no warm-up)
adb shell "export LD_LIBRARY_PATH=/data/local/tmp:$LD_LIBRARY_PATH; \
           /data/local/tmp/monitor_example"

# Warm-up mode
adb shell "export LD_LIBRARY_PATH=/data/local/tmp:$LD_LIBRARY_PATH; \
           export EBPF_WARMUP=1; \
           /data/local/tmp/monitor_example"
```

#### From `exploration/exploration_kernel/`

*Kernel-guided priority boost (Experiment 4). The same binary supports both modes:*

```bash
# Baseline mode (no kernel optimization)
adb shell "export LD_LIBRARY_PATH=/data/local/tmp:$LD_LIBRARY_PATH; \
           /data/local/tmp/monitor_example"

# Kernel optimization enabled
adb shell "export LD_LIBRARY_PATH=/data/local/tmp:$LD_LIBRARY_PATH; \
           export EBPF_Kernel_optimization=1; \
           /data/local/tmp/monitor_example"
```

---

### 📥 Pulling Results and Generating Plots

After running an experiment, pull the results from the device into the same folder as the `script` notebook:

```bash
adb pull /data/local/tmp/ebpf_results ./ebpf_results
```

Then open the `script` notebook in **JupyterLab** in that folder. It generates per-run launch-time bars, averages, file-touch counts, page allocation totals, and several additional comparisons not shown in the report. The same notebook works in `exploration_baseline/`, `exploration_user/`, and `exploration_kernel/`.

To start fresh between experiments:

```bash
adb shell "rm -rf /data/local/tmp/ebpf_results"
```

The full command reference (including verification, debugging, and rebuild reminders) is in **Appendix A** of the report.

---

## 📝 Scope and Limitations

This work targets **only** the storage- and memory-related portion of cold-launch overhead. Android startup is also affected by process creation, runtime initialization, class loading, resource setup, and app-specific logic — none of which are addressed here.

Results are reported for **one application** (AOSP Gallery) on **one device**. They should therefore be read as a focused case study of what kernel-level eBPF observation can help guide, not as a general-purpose solution to app launch latency.

---

## 📄 Full Report

The complete technical report with detailed methodology, plots, and discussion is in [`report/ebpf_report.pdf`](report/ebpf_report.pdf).

---

## 👤 Author

**Fathy Ibrahim**
CS7601 — Operating Systems, Spring 2026
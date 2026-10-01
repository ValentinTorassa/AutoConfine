//go:build ignore

// Raw tracepoint probes: record the syscalls of one cgroup v2 subtree.
//
// A task matches when its cgroup is the target or any descendant of it
// (bpf_get_current_ancestor_cgroup_id at the target's level), so processes a
// container moves into child cgroups (systemd inside, --cgroups=split) still
// count. Every event that cannot be recorded increments a per-CPU drop
// counter, which user space checks before trusting the trace.
//
// User space loads and attaches one of the two programs:
//   - trace_sys_enter sees every syscall that seccomp lets run (learn, and
//     enforce --audit, where the profile only logs).
//   - trace_sys_exit also sees the syscalls a profile denies with an errno:
//     seccomp runs before sys_enter and skips it for them, but they still
//     return through sys_exit (kernel/entry/common.c). A call that does not
//     return (exit, exit_group, a killed process) has no sys_exit.
//
// Rebuild with `make bpf`; CI checks the committed object matches the source.
typedef unsigned int u32;
typedef unsigned long long u64;
#define SEC(name) __attribute__((section(name), used))
#define __uint(name, val) int (*name)[val]
#define __type(name, val) val *name
#define __always_inline inline __attribute__((always_inline))

struct bpf_raw_tracepoint_args { u64 args[0]; };

struct target { u64 cgroup_id; u32 level; u32 pad; };

// 48 bytes; offsets are mirrored by decodeEvent in event.go.
struct syscall_event {
    u64 timestamp_ns; // bpf_ktime_get_ns (CLOCK_MONOTONIC)
    u64 cgroup_id;    // the task's own cgroup (may be a child of the target)
    u32 pid;
    u32 tid;
    u32 syscall_nr;
    u32 err;          // sys_exit only: the errno of a failed call, else 0
    char comm[16];
};

// sys_exit gets the syscall number from pt_regs->orig_ax, which a seccomp
// denial leaves intact. Offset on x86_64, the only architecture the Go side
// names; object_linux_test.go checks it against the running kernel's BTF.
#define PT_REGS_ORIG_AX 120
#define MAX_ERRNO 4095

struct {
    __uint(type, 2); /* BPF_MAP_TYPE_ARRAY */
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct target);
} target_cgroup SEC(".maps");

struct {
    __uint(type, 6); /* BPF_MAP_TYPE_PERCPU_ARRAY */
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
} drops SEC(".maps");

struct {
    __uint(type, 27); /* BPF_MAP_TYPE_RINGBUF */
    __uint(max_entries, 1 << 22);
} events SEC(".maps");

static void *(*bpf_map_lookup_elem)(void *, const void *) = (void *)1;
static u64 (*bpf_ktime_get_ns)(void) = (void *)5;
static u64 (*bpf_get_current_pid_tgid)(void) = (void *)14;
static long (*bpf_get_current_comm)(void *, u32) = (void *)16;
static u64 (*bpf_get_current_cgroup_id)(void) = (void *)80;
static long (*bpf_probe_read_kernel)(void *, u32, const void *) = (void *)113;
static u64 (*bpf_get_current_ancestor_cgroup_id)(int) = (void *)123;
static void *(*bpf_ringbuf_reserve)(void *, u64, u64) = (void *)131;
static void (*bpf_ringbuf_submit)(void *, u64) = (void *)132;

static __always_inline int in_target(void) {
    u32 key = 0;
    struct target *target = bpf_map_lookup_elem(&target_cgroup, &key);
    if (!target || !target->cgroup_id)
        return 0;
    return bpf_get_current_cgroup_id() == target->cgroup_id ||
           bpf_get_current_ancestor_cgroup_id((int)target->level) == target->cgroup_id;
}

static __always_inline void count_drop(void) {
    u32 key = 0;
    u64 *dropped = bpf_map_lookup_elem(&drops, &key);
    if (dropped)
        (*dropped)++;
}

static __always_inline void record(u32 nr, u32 err) {
    struct syscall_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        count_drop();
        return;
    }
    u64 pid_tgid = bpf_get_current_pid_tgid();
    event->timestamp_ns = bpf_ktime_get_ns();
    event->cgroup_id = bpf_get_current_cgroup_id();
    event->pid = pid_tgid >> 32;
    event->tid = (u32)pid_tgid;
    event->syscall_nr = nr;
    event->err = err;
    bpf_get_current_comm(event->comm, sizeof(event->comm));
    bpf_ringbuf_submit(event, 0);
}

// sys_enter(struct pt_regs *regs, long id)
SEC("raw_tracepoint/sys_enter")
int trace_sys_enter(struct bpf_raw_tracepoint_args *ctx) {
    if (in_target())
        record((u32)ctx->args[1], 0);
    return 0;
}

// sys_exit(struct pt_regs *regs, long ret)
SEC("raw_tracepoint/sys_exit")
int trace_sys_exit(struct bpf_raw_tracepoint_args *ctx) {
    if (!in_target())
        return 0;
    long nr = -1;
    if (bpf_probe_read_kernel(&nr, sizeof(nr), (void *)(ctx->args[0] + PT_REGS_ORIG_AX))) {
        count_drop();
        return 0;
    }
    long ret = (long)ctx->args[1];
    record((u32)nr, ret < 0 && ret >= -MAX_ERRNO ? (u32)-ret : 0);
    return 0;
}

char _license[] SEC("license") = "Dual MIT/GPL";

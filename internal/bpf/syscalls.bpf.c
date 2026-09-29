//go:build ignore

// Minimal raw tracepoint probe: record only syscalls in one cgroup v2.
typedef unsigned int u32;
typedef unsigned long long u64;
#define SEC(name) __attribute__((section(name), used))
#define __uint(name, val) int (*name)[val]
#define __type(name, val) val *name

struct bpf_raw_tracepoint_args { u64 args[0]; };
struct syscall_event { u64 timestamp_ns; u64 cgroup_id; u32 pid; u32 tid; u32 syscall_nr; u32 pad; };

struct {
    __uint(type, 2); /* BPF_MAP_TYPE_ARRAY */
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
} target_cgroup SEC(".maps");

struct {
    __uint(type, 27); /* BPF_MAP_TYPE_RINGBUF */
    __uint(max_entries, 1 << 20);
} events SEC(".maps");

static u64 (*bpf_get_current_cgroup_id)(void) = (void *)80;
static u64 (*bpf_get_current_pid_tgid)(void) = (void *)14;
static u64 (*bpf_ktime_get_ns)(void) = (void *)5;
static void *(*bpf_map_lookup_elem)(void *, const void *) = (void *)1;
static void *(*bpf_ringbuf_reserve)(void *, u64, u64) = (void *)131;
static void (*bpf_ringbuf_submit)(void *, u64) = (void *)132;

SEC("raw_tracepoint/sys_enter")
int trace_sys_enter(struct bpf_raw_tracepoint_args *ctx) {
    u32 key = 0;
    u64 *target = bpf_map_lookup_elem(&target_cgroup, &key);
    if (!target || !*target || bpf_get_current_cgroup_id() != *target)
        return 0;
    struct syscall_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return 0;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    event->timestamp_ns = bpf_ktime_get_ns();
    event->cgroup_id = *target;
    event->pid = pid_tgid >> 32;
    event->tid = (u32)pid_tgid;
    event->syscall_nr = (u32)ctx->args[1];
    event->pad = 0;
    bpf_ringbuf_submit(event, 0);
    return 0;
}

char _license[] SEC("license") = "Dual MIT/GPL";

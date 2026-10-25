#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct syscall_enter_data {
    __u32 syscall_nr;
    __u64 enter_time;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u64);
    __type(value, struct syscall_enter_data);
} running_syscalls SEC(".maps");


SEC("raw_tracepoint/sys_enter")
int catch_syscall_enter(struct bpf_raw_tracepoint_args *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    struct syscall_enter_data d = {};
    d.enter_time = bpf_ktime_get_ns();
    d.syscall_nr = ctx->args[1];

    bpf_map_update_elem(&running_syscalls, &pid_tgid, &d, BPF_ANY);
    return 0;
}

struct syscall_data
{
    __u64 count;
    __u64 total_ns;
};


struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 512);
    __type(key, __u32); // Kulcs: Syscall number
    __type(value, struct syscall_data);
} syscalls SEC(".maps");


SEC("raw_tracepoint/sys_exit")
int catch_syscall_exit(struct bpf_raw_tracepoint_args *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    struct syscall_enter_data *e = bpf_map_lookup_elem(&running_syscalls, &pid_tgid);
    if (!e) {
        return 0;
    }

    __u32 syscall_nr = e->syscall_nr; 
    __u64 runtime = bpf_ktime_get_ns() - e->enter_time;
    bpf_map_delete_elem(&running_syscalls, &pid_tgid);

    struct syscall_data *d = bpf_map_lookup_elem(&syscalls, &syscall_nr);    
    if (d) {
        d->count++;
        d->total_ns += runtime;
    }
    else {
        struct syscall_data new = {}; // Kinullázza a biztonság kedvéért
        new.count = 1;
        new.total_ns = runtime;
        bpf_map_update_elem(&syscalls, &syscall_nr, &new, BPF_ANY);
    }

    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
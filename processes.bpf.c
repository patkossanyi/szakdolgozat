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
    __type(key, __u64); // Kulcs PID - TGID
    __type(value, struct syscall_enter_data);
} running_syscalls SEC(".maps");


SEC("raw_tracepoint/sys_enter")                                   //https://docs.ebpf.io/ebpf-library/libbpf/ebpf/BPF_PROG/
int catch_syscall_enter(struct bpf_raw_tracepoint_args *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    struct syscall_enter_data d = {};
    d.enter_time = bpf_ktime_get_ns();
    d.syscall_nr = ctx->args[1];

    bpf_map_update_elem(&running_syscalls, &pid_tgid, &d, BPF_ANY);
    return 0;
}


struct syscall_nr_and_pid {
    int syscall_nr;
    int pid;
};

struct syscall_data {
    __u64 count;
    __u64 total_ns;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 10240);
    __type(key, struct syscall_nr_and_pid); // key: PID and syscall_nr
    __type(value, struct syscall_data);
} process_syscalls SEC(".maps");


struct proc_data {
    char cpu_num;
    __u64 on_cpu;
    __u64 off_cpu;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 512);
    __type(key, __u32); // key: PID
    __type(value, struct proc_data);
} processes SEC(".maps");


SEC("raw_tracepoint/sys_exit")
int catch_syscall_exit(struct bpf_raw_tracepoint_args *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    struct syscall_enter_data *e = bpf_map_lookup_elem(&running_syscalls, &pid_tgid);
    if (!e) {
        return 0;
    }

    __u32 syscall_nr = e->syscall_nr; 
    __u64 runtime = bpf_ktime_get_ns() - e->enter_time;
    bpf_map_delete_elem(&running_syscalls, &pid_tgid);

    //struct proc_data *p = bpf_map_lookup_elem(&processes, &pid);
    //if (p) {
        // Valami történik
   // }

    struct syscall_nr_and_pid sys_proc = {};
    sys_proc.syscall_nr = syscall_nr;
    sys_proc.pid = pid;
    
    struct syscall_data *d = bpf_map_lookup_elem(&process_syscalls, &sys_proc);    
    if (d) {
        d->count++;
        d->total_ns += runtime;
    }
    else {
        struct syscall_data new = {}; // Kinullázza a biztonság kedvéért
        new.count = 1;
        new.total_ns = runtime;
        bpf_map_update_elem(&process_syscalls, &sys_proc, &new, BPF_ANY);
    }

    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
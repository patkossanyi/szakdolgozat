#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "processes.skel.h"
#include "utils.h"

#define DURATION_SEC 10

struct syscall_nr_and_pid {
    int syscall_nr;
    int pid;
};

struct syscall_data {
    __u64 count;
    __u64 total_ns;
};

struct proc_data {
    char cpu_num;
    __u64 on_cpu;
    __u64 off_cpu;
};

void print_aggregated_data(struct processes_bpf *skel){
    int num_cpus = libbpf_num_possible_cpus();
    if (num_cpus < 0) {
        fprintf(stderr, "Hiba a CPU-k számának lekérdezésekor\n");
        return;
    }

    struct syscall_data *all_cpu_data = malloc(sizeof(struct syscall_data) * num_cpus); 
    if (!all_cpu_data) {
        fprintf(stderr, "Memóriafoglalási hiba");
        return;
    }

    int proc_map_fd = bpf_map__fd(skel->maps.processes);
    int sysc_pid_map_fd = bpf_map__fd(skel->maps.process_syscalls);

    __u32 next_proc_key;
    void *proc_prev = NULL;

    struct syscall_nr_and_pid sysc_pid_next_key;
    void *sysc_pid_prev;

    //printf("PID: %d\t [on-CPU: %f ms   off-CPU: %f ms   CPU: %d]\n", 1, 1.1, 1, 1);
    while (bpf_map_get_next_key(proc_map_fd, proc_prev, &next_proc_key) == 0) {
        sysc_pid_prev = NULL;
        __u32 pid = next_proc_key;
        printf("------------------------\n");
        printf("PID: %d\n", pid);
        while (bpf_map_get_next_key(sysc_pid_map_fd, sysc_pid_prev, &sysc_pid_next_key) == 0) {
            if (bpf_map_lookup_elem(sysc_pid_map_fd, &sysc_pid_next_key, all_cpu_data) == 0) {
                if (sysc_pid_next_key.pid == pid) {
                    __u64 count = 0;
                    __u64 total_ns = 0;

                    for (int i = 0; i < num_cpus; i++) {
                        count += all_cpu_data[i].count;
                        total_ns += all_cpu_data[i].total_ns;
                    }
            
                    printf("\t%s %d %llu, %llu\n\n",
                            get_syscall_name(sysc_pid_next_key.syscall_nr),
                            sysc_pid_next_key.syscall_nr,
                            count,
                            total_ns/count);
                }                
            }
            sysc_pid_prev = &sysc_pid_next_key;
        }
        proc_prev = &next_proc_key;
        printf("------------------------");
    }
}

int main() {
    struct processes_bpf *skel = processes_bpf__open_and_load();
    
    if (!skel) {
        fprintf(stderr, "Hhiba: Nem sikerült betölteni az eBPF programot.\n");
        return 1;
    }

    if (processes_bpf__attach(skel)) {
        fprintf(stderr, "Hiba: Nem sikerült csatolni a programot\n");
        processes_bpf__destroy(skel);
        return 2;
    }

    printf("Rendszerhívások elfogása (%d másodpercig) ", DURATION_SEC);
    fflush(stdout);
    for (int i = 0; i < DURATION_SEC; i++) {
        sleep(1);
        printf("#");
        fflush(stdout);
    }
    printf("\n");

    

    processes_bpf__detach(skel);
    print_aggregated_data(skel);
    return 0;
}

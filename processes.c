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

    int map_fd = bpf_map__fd(skel->maps.process_syscalls);
    struct syscall_nr_and_pid key;
    struct syscall_nr_and_pid next_key;
    void *prev = NULL;

    //printf("PID: %d\t [on-CPU: %f ms   off-CPU: %f ms   CPU: %d]\n", 1, 1.1, 1, 1);
    printf("\t syscall_name \t start_time \t end_time \t runtime\n");
    while (bpf_map_get_next_key(map_fd, prev, &next_key) == 0) {
        if (bpf_map_lookup_elem(map_fd, &next_key, all_cpu_data) == 0){
            __u64 count = 0;
            __u64 total_ns = 0;

            for (int i = 0; i < num_cpus; i++) {
                count += all_cpu_data[i].count;
                total_ns += all_cpu_data[i].total_ns;
            }
            
            printf("PID: %d - Syscall: %s\n", next_key.pid, get_syscall_name(next_key.syscall_nr));
            printf("\t%llu, %llu\n\n", count, total_ns/count);
            //printf("\t %d \t %f \t %f \t %f\n");

            bpf_map_delete_elem(map_fd, &next_key);
        }
        key = next_key;
        prev = &key;
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

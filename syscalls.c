#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

// eBPF userspace részének segédfüggvényeit tartalmazza: BPF programok betöltése, csatolása és mapek használata
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

// A Makefile által automatikusan generált "vázfájl", ami a program.bpf.c-ből készül
// Ez tartalmazza a program_bpf struktúrát és a betöltő/csatoló függvényeket
#include "syscalls.skel.h"

// Saját header, a rendszerhívás azonosítót számot alakítja a rendszerhívás nevére
// Kiíratáskor használatos 
#include "utils.h"

#define DURATION_SEC 10

struct syscall_data {
    __u64 count;
    __u64 total_ns;
};

void print_aggregated_data(struct syscalls_bpf *skel) {
    int num_cpus = libbpf_num_possible_cpus();
    if (num_cpus < 0) {
        fprintf(stderr, "Hiba a CPU-k számának lekérdezésekor\n");
        return;
    }

    struct syscall_data *all_cpu_data = malloc(sizeof(struct syscall_data) * num_cpus);
    if (!all_cpu_data) {
        perror("Memóriafoglalási hiba");
        return;
    }

     int map_fd = bpf_map__fd(skel->maps.syscalls);
    __u32 key = 0, next_key;
    __u32 *prev = NULL;
    
    printf("%-13s %-20s %12s %10s %12s\n", "syscall_nr", "syscall_name", "count", "rate/s", "avg_ns");
    while (bpf_map_get_next_key(map_fd, prev, &next_key) == 0) {
        // PERCPU map esetén a lookup-nak egy olyan pointert kell adni, 
        // ami elég nagy ahhoz, hogy MINDEN CPU adata beleférjen!          
        if (bpf_map_lookup_elem(map_fd, &next_key, all_cpu_data) == 0) {
            __u64 count = 0;
            __u64 total_ns = 0;

            for (int i = 0; i < num_cpus; i++) {
                count += all_cpu_data[i].count;
                total_ns += all_cpu_data[i].total_ns;
            }

            printf("%-13u %-20.20s %12llu %10.2f %12llu\n", 
                    next_key,
                    get_syscall_name(next_key),
                    count,
                    (double) count/DURATION_SEC,
                    total_ns / count);

            bpf_map_delete_elem(map_fd, &next_key);
        }
        key = next_key;
        prev = &key;
    }
    printf("\n\n\n");
    free(all_cpu_data);
}

int main() {
    struct syscalls_bpf *skel = syscalls_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Hiba: Nem sikerült betölteni az eBPF programot\n");
        return 1;
    }

    if (syscalls_bpf__attach(skel)) {
        fprintf(stderr, "Hiba: Nem sikerült csatolni a programot\n");
        syscalls_bpf__destroy(skel);
        return 1;
    }   

    printf("Rendszerhívások elfogása (%d másodpercig) ", DURATION_SEC);
    fflush(stdout);
    for (int i = 0; i < DURATION_SEC; i++) {
        sleep(1);
        printf("#");
        fflush(stdout);
    }
    printf("\n");
    
    syscalls_bpf__detach(skel); // Leválasztjuk, hogy a kiíratás alatt ne gyűjtsön rendszerhívásokat
    print_aggregated_data(skel);
    
    return 0;
}
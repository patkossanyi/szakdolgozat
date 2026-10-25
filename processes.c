#include <stdio.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "processes.skel.h"
#include "utils.h"

int main() {
    struct processes_bpf *skel = processes_bpf__open_and_load();
    


    printf("PID: %d\t [on-CPU: %f ms   off-CPU: %f ms   CPU: %d]\n");
    printf("\t syscall_name \t start_time \t end_time \t runtime\n");
    while (1) {
        printf("\t %d \t %f \t %f \t %f\n");
    }
    
    return 0;
}
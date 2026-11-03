make:
	cat Makefile

syscalls:
	@echo ' --- Compile syscalls program --- '

	clang -g -O2 -target bpf -c syscalls.bpf.c -o syscalls.bpf.o
	bpftool gen skeleton syscalls.bpf.o > syscalls.skel.h
	clang -g -O2 -Wall syscalls.c utils.c -lbpf -lelf -lz -o syscalls

processes:
	@echo ' --- Compile processes program --- '

	clang -g -O2 -target bpf -c processes.bpf.c -o processes.bpf.o
	bpftool gen skeleton processes.bpf.o > processes.skel.h
	clang -g -O2 -Wall processes.c utils.c -lbpf -lelf -lz -o processes

all:
	@echo ' --- Compile program --- '

	clang -g -O2 -target bpf -c syscalls.bpf.c -o syscalls.bpf.o
	bpftool gen skeleton syscalls.bpf.o > syscalls.skel.h
	clang -g -O2 -Wall syscalls.c utils.c -lbpf -lelf -lz -o syscalls

clean:
	@echo ' --- Delete every non-source code file --- '
	rm -f syscalls.bpf.o syscalls.skel.h utils.o syscalls processes.bpf.o processes.skel.h processes
	

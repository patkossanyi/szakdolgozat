make:
	cat Makefile

all:
	@echo ' --- Compile program --- '

	clang -g -O2 -target bpf -c syscalls.bpf.c -o syscalls.bpf.o
	bpftool gen skeleton syscalls.bpf.o > syscalls.skel.h
	clang -g -O2 -Wall syscalls.c utils.c -lbpf -lelf -lz -o syscalls

clean:
	@echo ' --- Delete every non-source code file --- '
	rm -f syscalls.bpf.o syscalls.skel.h utils.o syscalls
	

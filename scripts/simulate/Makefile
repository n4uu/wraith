CC ?= cc
CFLAGS ?= -O2 -Wall -Wextra

.PHONY: all clean

all: fileless_exec proc_injection preload_lib.so

fileless_exec: fileless_exec.c
	$(CC) $(CFLAGS) -o $@ $<

proc_injection: proc_injection.c
	$(CC) $(CFLAGS) -o $@ $<

preload_lib.so: preload_lib.c
	$(CC) $(CFLAGS) -shared -fPIC -o $@ $<

clean:
	rm -f fileless_exec proc_injection preload_lib.so

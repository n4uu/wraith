/*
 * A no-op shared object with a constructor, forced into another process via
 * LD_PRELOAD by preload_hijack.sh. Real hijackers use the constructor to
 * install hooks over libc functions (open, readdir, connect, ...); this one
 * only prints that it ran, to demonstrate the injection primitive without
 * actually hooking anything.
 */
#include <stdio.h>

__attribute__((constructor))
static void wraith_demo_init(void)
{
	fprintf(stderr, "[preload_hijack demo] constructor ran inside the target process\n");
}

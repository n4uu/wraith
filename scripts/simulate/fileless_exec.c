/*
 * Benign reproduction of "reflective code loading" (MITRE T1620): copy a
 * harmless binary (/bin/true) into an anonymous memfd and execute it
 * straight from that file descriptor, with no path ever touching disk.
 * This is the exact primitive wraith's fileless_exec rule watches for,
 * used here to run /bin/true instead of a payload.
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <unistd.h>

static void die(const char *what)
{
	perror(what);
	exit(1);
}

int main(void)
{
	int src = open("/bin/true", O_RDONLY);
	if (src < 0)
		die("open /bin/true");

	int fd = syscall(SYS_memfd_create, "wraith-demo", 0);
	if (fd < 0)
		die("memfd_create");

	char buf[65536];
	ssize_t n;
	while ((n = read(src, buf, sizeof(buf))) > 0) {
		if (write(fd, buf, n) != n)
			die("write to memfd");
	}
	close(src);

	fprintf(stderr, "[fileless_exec demo] executing memfd:wraith-demo (fd %d) via execveat\n", fd);

	char *const argv[] = {"wraith-demo", NULL};
	char *const envp[] = {NULL};
	syscall(SYS_execveat, fd, "", argv, envp, AT_EMPTY_PATH);

	die("execveat"); /* only reached on failure */
	return 1;
}

/*
 * Benign reproduction of the two userland primitives behind Linux process
 * injection (MITRE T1055.008 / T1055.009): a parent PTRACE_ATTACHes to its
 * own child and overwrites a buffer in the child's address space with
 * process_vm_writev. No shellcode and no execution redirection, just a
 * string swap, to give wraith's ptrace_inject and proc_mem_write rules
 * something real to fire on.
 *
 * Attaching only to a direct child means this works under the default
 * (ptrace_scope=1) Yama restriction with no extra capabilities.
 *
 * Two pipes hand-shake parent and child so the "before" line is always
 * printed before the attach and the "after" line always after the write.
 * Without them, PTRACE_ATTACH can stop the child before its first printf
 * ever runs, since it lands moments after fork().
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

static char victim_buf[64] = "untouched";

static void die(const char *what)
{
	perror(what);
	exit(1);
}

static void read_byte(int fd)
{
	char b;
	if (read(fd, &b, 1) != 1)
		die("read");
}

static void write_byte(int fd)
{
	char b = 0;
	if (write(fd, &b, 1) != 1)
		die("write");
}

static int run_child(int ready_wr, int go_rd)
{
	printf("[proc_injection demo] child %d: buffer before = \"%s\"\n", getpid(), victim_buf);
	fflush(stdout);
	write_byte(ready_wr); /* "I've printed, attach whenever you like" */

	read_byte(go_rd); /* blocks until the parent has attached, written, and detached */

	printf("[proc_injection demo] child %d: buffer after  = \"%s\"\n", getpid(), victim_buf);
	fflush(stdout);
	return 0;
}

static void run_parent(pid_t child, int ready_rd, int go_wr)
{
	int status;

	read_byte(ready_rd); /* wait for the child's "before" line */

	if (ptrace(PTRACE_ATTACH, child, NULL, NULL) < 0)
		die("ptrace(PTRACE_ATTACH)");
	waitpid(child, &status, 0);
	fprintf(stderr, "[proc_injection demo] parent: attached to child %d\n", child);

	const char *message = "hello from parent";
	struct iovec local = {.iov_base = (void *)message, .iov_len = strlen(message) + 1};
	struct iovec remote = {.iov_base = victim_buf, .iov_len = sizeof(victim_buf)};

	/*
	 * The child's address space holds victim_buf at an identical virtual
	 * address to the parent's own copy: they are still the same binary
	 * image, since fork() was never followed by exec().
	 */
	ssize_t written = process_vm_writev(child, &local, 1, &remote, 1, 0);
	if (written < 0)
		die("process_vm_writev");
	fprintf(stderr, "[proc_injection demo] parent: wrote %zd bytes into child's buffer\n", written);

	if (ptrace(PTRACE_DETACH, child, NULL, NULL) < 0)
		die("ptrace(PTRACE_DETACH)");

	write_byte(go_wr); /* let the child print "after" */
	waitpid(child, &status, 0);
}

int main(void)
{
	int ready[2], go[2];
	if (pipe(ready) < 0 || pipe(go) < 0)
		die("pipe");

	pid_t child = fork();
	if (child < 0)
		die("fork");

	if (child == 0) {
		close(ready[0]);
		close(go[1]);
		return run_child(ready[1], go[0]);
	}

	close(ready[1]);
	close(go[0]);
	run_parent(child, ready[0], go[1]);
	return 0;
}

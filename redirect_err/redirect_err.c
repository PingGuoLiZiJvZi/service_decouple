#include "redirect_err.skel.h"
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <signal.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#define PERF_BUFFER_PAGES 16
#define PERF_POLL_TIMEOUT_MS 100
static volatile sig_atomic_t exiting = 0;
static int libbpf_print_fn(enum libbpf_print_level level,
						   const char *format,
						   va_list args)
{
	return vfprintf(stderr, format, args);
	// return 0;
}
static void sig_int(int signo)
{
	exiting = 1;
}
void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	fprintf(stderr, "lost %llu events on CPU #%d\n", lost_cnt, cpu);
}

int main(int argc, char **argv)
{
	struct redirect_err_bpf *obj;
	int err;

	libbpf_set_print(libbpf_print_fn);
	obj = redirect_err_bpf__open();
	if (!obj)
	{
		fprintf(stderr, "failed to open BPF object\n");
		return 1;
	}
	printf("成功打开 BPF 对象\n");
	err = redirect_err_bpf__load(obj);
	if (err)
	{
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}
	err = redirect_err_bpf__attach(obj);
	if (err)
	{
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	if (signal(SIGINT, sig_int) == SIG_ERR)
	{
		fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	while (1)
		;

cleanup:
	redirect_err_bpf__destroy(obj);
	return -err;
}

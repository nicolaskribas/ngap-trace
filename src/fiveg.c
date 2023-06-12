// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2022 Hengqi Chen */

#include "bpf/libbpf.h"
#include <unistd.h>
#include <signal.h>
#include <net/if.h>
#include "fiveg.h"
#include "fiveg.skel.h"

static volatile sig_atomic_t exiting = 0;

static void sig_int(int signo)
{
	exiting = 1;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

int main(int argc, char **argv)
{
	if (argc > 2) {
		fprintf(stderr, "Too many arguments supplied.\n");
		return 1;
	} else if (argc == 1) {
		fprintf(stderr, "Expecting ifname as argument\n");
		return 1;
	}

	// enable debug printing for the libbpf functions
	libbpf_set_print(libbpf_print_fn);

	int err;
	int ifindex;
	bool hook_created = false;
	struct fiveg_bpf *skel;

	ifindex = if_nametoindex(argv[1]);
	if (ifindex == 0) {
		fprintf(stderr, "No interface found with given name.\n");
		return 1;
	}

	// LIBBPF_OPTS fills the struct with zeros
	// set the .sz field accordingly with the size of the struct
	// and set all the other fields with the provided values
	LIBBPF_OPTS(bpf_tc_hook, tc_ingress_hook, .ifindex = ifindex,
		    .attach_point = BPF_TC_INGRESS, );

	skel = fiveg_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	err = bpf_tc_hook_create(&tc_ingress_hook);
	if (!err)
		hook_created = true;
	if (err && err != -EEXIST) {
		fprintf(stderr, "Failed to create TC hook: %d\n", err);
		goto cleanup;
	}

	// struct bpf_tc_opts tc_ingress_opts;
	LIBBPF_OPTS(bpf_tc_opts, tc_ingress_opts,
		    .prog_fd = bpf_program__fd(skel->progs.tc_ingress), .handle = 1,
		    .priority = 1, );

	err = bpf_tc_attach(&tc_ingress_hook, &tc_ingress_opts);
	if (err) {
		fprintf(stderr, "Failed to attach TC: %d\n", err);
		goto cleanup;
	}

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		err = errno;
		fprintf(stderr, "Can't set signal handler: %s\n", strerror(errno));
		goto cleanup;
	}

	printf("Started!");

	while (!exiting) {
		fprintf(stderr, ".");
		sleep(1);
	}

	// Why the following zeroing is needed? I don't know, just following examples:
	// https://github.com/libbpf/libbpf-rs/blob/master/libbpf-rs/src/tc.rs
	// https://github.com/libbpf/libbpf-bootstrap/blob/master/examples/c/tc.c
	tc_ingress_opts.flags = 0;
	tc_ingress_opts.prog_fd = 0;
	tc_ingress_opts.prog_id = 0;

	err = bpf_tc_detach(&tc_ingress_hook, &tc_ingress_opts);
	if (err) {
		fprintf(stderr, "Failed to detach TC: %d\n", err);
		goto cleanup;
	}

cleanup:
	if (hook_created)
		bpf_tc_hook_destroy(&tc_ingress_hook);
	fiveg_bpf__destroy(skel);
	return -err;
}

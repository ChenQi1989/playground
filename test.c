/* test <function> <para1> <param2> ... */

#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <dirent.h>

#include "test.h"

#define PROG_NAME "test"

static int func_test(int argc, char **argv) {
	char **arg;
	printf("func_test:\n");
	arg = &argv[1];
	while (*arg != NULL) {
		printf("\t%s\n", *arg);
		++arg;
	}
	return 0;
}

/* chroot to path and list entries in path */
static int chroot_and_list(int argc, char **argv) {
	char *root;
	int r;
	struct dirent *dep;
	DIR *dirp;

	assert(argc == 2);

	root = argv[1];
	r = chroot(root);
	if (r < 0) {
		fprintf(stderr, "chroot to %s failed: %m\n", root);
		return -r;
	}

	dirp = opendir("/");
	if (dirp == NULL) {
		fprintf(stderr, "opendir on / failed: %m\n");
		return 1;
	}
	while ((dep = readdir(dirp)) != NULL)
		printf("%s\n", dep->d_name);
		
	return 0;
}

/* define the function table */
static struct func_tab functab[NFUNCS] = {
	{"func_test", func_test},
	{"chroot_and_list", chroot_and_list},
	{NULL, NULL},
};

/* usage */
static void usage(void) {
	struct func_tab *ftp;
	printf(PROG_NAME " funcname para1 param2 ...\n");
	printf("supported functions:\n");
	ftp = &functab[0];
	while (ftp->fp != NULL) {
		printf("\t%s\n", ftp->name);
		++ftp;
	}
}

/* get function from name */
static fn_t get_func(const char *name) {
	struct func_tab *ftp;

	ftp = &functab[0];
	while (ftp->fp != NULL) {
		if (!strcmp(ftp->name, name))
			return ftp->fp;
		++ftp;
	}

	/* no such function */
	return NULL;
}

int main(int argc, char *argv[]) {
	int ret;
	char *funcname;
	fn_t fp;

	if (argc == 1) {
		usage();
		return 0;
	}

	funcname = argv[1];
	fp = get_func(funcname);
	if (fp == NULL) {
		fprintf(stderr, "no such function\n");
		return 1;
	} else {
		return fp(argc-1, argv+1);
	}
	
	return 0;
}

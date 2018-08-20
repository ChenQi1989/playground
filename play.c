/* test <function> <para1> <param2> ... */

#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <dirent.h>
#include <stdlib.h>
#include <syslog.h>
#include <signal.h>

#include "play.h"

#define PROG_NAME "play"

/*
 **************************************************************
 *    HELP FUNCTIONS AND MACROS                               *
 **************************************************************
 */

#define error_and_exit(...)				\
do							\
{							\
	fprintf(stderr, __VA_ARGS__);			\
	exit(1);					\
} while (0)



/*
 **************************************************************
 *    MAIN FUNCTIONS                                          *
 **************************************************************
 */

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
	if (r < 0)
		error_and_exit("chroot to %s failed: %m\n", root);

	dirp = opendir("/");
	if (dirp == NULL)
		error_and_exit("opendir on / failed\n");

	while ((dep = readdir(dirp)) != NULL)
		printf("%s\n", dep->d_name);

	return 0;
}

#ifdef MEM_DEBUG
/* hack function for malloc and free */
void *_mymalloc(unsigned int bytes, const char *file, const char *func, int line) {
#undef malloc
#undef free
	printf("mymalloc, file = %s, func = %s, lineno = %d\n", file, func, line);
	return malloc(bytes);
#define malloc mymalloc
#define free myfree
}

#define mymalloc(bytes) _mymalloc(bytes, __FILE__, __func__, __LINE__)

void _myfree(void *mp, const char *file, const char *func, int line) {
#undef malloc
#undef free
	printf("myfree, file = %s, func = %s, lineno = %d\n", file, func, line);
	free(mp);
#define malloc mymalloc
#define free myfree
}

#define myfree(bytes) _myfree(mp, __FILE__, __func__, __LINE__)
#endif

/* malloc and free */
static int malloc_and_free(int argc, char **argv) {
	assert(argc == 3);
	int bytes = atoi(argv[1]);
	int times = atoi(argv[2]);
	printf("test malloc %d bytes and free for %d times\n", bytes, times);
	for (int i=0; i < times; i++) {
		char *mp = (char *)malloc(bytes);
		if (mp == NULL)
			error_and_exit("malloc failure: %m\n");
		else
			free(mp);
	}

	return 0;
}

/* create a zombie process */
static int create_zombie_process(int argc, char **argv) {
	pid_t pid;

	if ((pid = fork()) < 0)
		error_and_exit("Fork failed: %m\n");
	else if (pid > 0)
		exit(0);
	else {
		sleep(1);
	}
	return 0;
}

/*
 * simple daemon
 * daemon that monitor argv[1] and sync its contents with argv[2]
 */
static int simple_daemon(int argc, char **argv) {
	int i, status;
	status = daemon(0, 0);
	if (status < 0)
		error_and_exit("daemon() failed: %m\n");

	/* child process part */
	i = 0;
	for (;;) {
		syslog(LOG_INFO, "simple_daemon running: i = %d\n", i++);
		sleep(10);
	}

	return 0;
}

extern char **environ;
/*
 * simple tinyinit
 *
 * argv specifies the prog to execute
 *      if not specified, try to sh -l
 */
static int tinyinit(int argc, char **argv) {
	pid_t pid;
	int ret;

	printf("*****************************\n");
	printf("*        tiny   init        *\n");
	printf("*****************************\n");

	/* execute shell  */
	char *shell = getenv("SHELL");
	setenv("PS1", "[tinyinit] $ ", 1);
	execle(shell, NULL, environ);

	/* default to execute busybox sh  */
	execl("/sbin/busybox", "sh", "-l", NULL);
	execl("/bin/busybox", "sh", "-l", NULL);

	fprintf(stderr, "WE SHOULD NEVER GET HERE!\n");
	return 0;
}

/* define the function table */
static struct func_tab functab[NFUNCS] = {
	{"func_test", func_test},
	{"chroot_and_list", chroot_and_list},
	{"malloc_and_free", malloc_and_free},
	{"simple_daemon", simple_daemon},
	{"create_zombie", create_zombie_process},
	{"tinyinit", tinyinit},
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
	char *funcname;
	fn_t fp;

	if (argc == 1) {
		usage();
		return 0;
	}

	funcname = argv[1];
	fp = get_func(funcname);
	if (fp == NULL) {
		error_and_exit("no such function\n");
	} else {
		return fp(argc-1, argv+1);
	}

	return 0;
}

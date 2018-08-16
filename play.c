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

#include "play.h"

#define PROG_NAME "play"

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
		if (mp == NULL) {
			fprintf(stderr, "malloc failure: %m\n");
			return 1;
		} else {
			free(mp);
		}
	}

	return 0;
}

/*
 * simple daemon
 * daemon that monitor argv[1] and sync its contents with argv[2]
 */
static int simple_daemon(int argc, char **argv) {
	pid_t pid;

	pid = fork();
	if (pid < 0) {
		fprintf(stderr, "Fork failed: %m\n");
		exit(1);
	} else if (pid > 0) {
		printf("parent process exit\n");
		exit(0);
	} else {
		int i, status;
		status = daemon(0, 0);
		if (status < 0) {
			fprintf(stderr, "daemon() failed: %m\n");
			exit(1);
		}
		i = 0;
		for (;;) {
			syslog(LOG_INFO, "simple_daemon running: i = %d\n", i++);
			sleep(10);
		}
	}

	return 0;
}


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

	pid = fork();
	if (pid < 0) {
		fprintf(stderr, "Forking failed: %m\n");
		return pid;
	} else if (pid > 0) {
		/* in parent process  */
		ret = daemon(0, 0);
		if (ret < 0) {
			fprintf(stderr, "daemon() failed: %m\n");
			return ret;
		}
		for(;;) {
			/* run forever  */
			sleep(100);
		}
	} else {
		/* pid == 0, in child process  */
		printf("I'm the child running here ... \n");
		if (argc > 1) {
			printf("argc > 1; execve %s\n", argv[1]);
			ret = execve(argv[1], argv+2, NULL);
			if (ret < 0) {
				fprintf(stderr, "execve() failed: %m\n");
				return ret;
			}
		} else {
			/* try to execute sh -l  */
			printf("argc == 1, execute sh -l\n");
			ret = execl("/bin/sh", "-l", NULL);
			if (ret < 0)
				ret = execl("/sbin/busybox", "sh", "-l", NULL);
			if (ret < 0) {
				fprintf(stderr, "execute sh -l failed: %m\n");
			}
		}
	}

	fprintf(stderr, "WE SHOULD NEVER GET HERE!\n");
	return 0;
}

/* define the function table */
static struct func_tab functab[NFUNCS] = {
	{"func_test", func_test},
	{"chroot_and_list", chroot_and_list},
	{"malloc_and_free", malloc_and_free},
	{"simple_daemon", simple_daemon},
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
		fprintf(stderr, "no such function\n");
		return 1;
	} else {
		return fp(argc-1, argv+1);
	}

	return 0;
}

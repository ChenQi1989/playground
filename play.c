/* test <function> <para1> <param2> ... */

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
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

#define log_error_and_exit(...)				\
do							\
{							\
	syslog(LOG_ERR, __VA_ARGS__);			\
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
 * simple daemon using daemon call
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

/*
 * daemon that do all the tedious work itself
 *   - only allow one instance
 *   - catch SIGTERM and SIGABRT
 */
static void sighandler_complex_daemon(int sig) {
	/* catch SIGTERM and SIGABRT and do logging  */	
	switch(sig) {
		case SIGTERM:
		case SIGABRT:
			syslog(LOG_INFO, "%s caught\n", sig == SIGTERM ? "SIGTERM" : "SIGABRT"	);
			break;
		default:
			syslog(LOG_ERR, "unexpected signal %d caught!\n", sig);
			exit(1);
	}
}

static int complex_daemon(int argc, char **argv) {
	int fd, lfd;
	int i;
	char s[16];

	switch(fork()) {
		case -1:
			error_and_exit("fork() failed: %m\n");
		case 0:
			break;
		default:
			exit(0);	
	}

	/* obtain a new session */
	if (setsid() < 0)
		error_and_exit("setsid() failed: %m\n");

	/* change working directory  */
	if (chdir("/") < 0)
		error_and_exit("chdir to / failed: %m\n");

	/* close all other file descriptors  */
	for (int i=getdtablesize(); i>0; i--)
		close(i);

	/* handle standard I/O  */
	fd = open("/dev/null", O_RDWR);
	if (fd < 0)
		log_error_and_exit("open /dev/null faild: %m\n");
	dup2(fd, 0);
	dup2(fd, 1);
	dup2(fd, 2);
	if (fd > 2)
		close(fd);

	/* ensure one instance  */
	lfd = open("/tmp/complex_daemon.pid", O_RDWR|O_CREAT, 0640);
	if (lfd < 0)
		log_error_and_exit("open PID file failed: %m\n");
	if (lockf(lfd, F_TLOCK, 0) < 0)
		log_error_and_exit("already running, lockf failed: %m\n");
	sprintf(s, "%d\n", getpid());
	write(lfd, s, strlen(s));
	fsync(lfd);

	/* set file permission  */
	umask(0);

	/* handle signals  */
	signal(SIGCHLD, SIG_IGN);	/* ingore child termination  */
	signal(SIGTERM, sighandler_complex_daemon);
	signal(SIGABRT, sighandler_complex_daemon);
	
	/* service logic below  */
	for (i=0;;i++) {
		syslog(LOG_INFO, "complex_daemon: %d\n", i);
		sleep(10);
	}
}


/*
 * get information about a process
 */
static int get_proc_info(int argc, char **argv) {
	
}

/*
 * use inotify to monitor the creation/removal of a file
 * and sync it with the other
 */
static int _monitor_and_sync(const char *srcf, const char *dstf) {
	return 0;
} 

static int monitor_and_sync(int argc, char **argv) {
	char *srcf, *dstf;	

	assert(argc == 3);
	srcf = argv[1];
	dstf = argv[2];
	
	return _monitor_and_sync(srcf, dstf);
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
	{"create_zombie", create_zombie_process},
	{"simple_daemon", simple_daemon},
	{"complex_daemon", complex_daemon},
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

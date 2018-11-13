/* test <function> <para1> <param2> ... */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
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
#include <sys/syscall.h>
#include <linux/limits.h>
#include <dirent.h>
#include <libgen.h>
#include <termios.h>
#include <sys/wait.h>
#include <netdb.h>

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

static int test_dirname(int argc, char **argv) {
	char *path, *base_dir;

	if (argc != 2)
		error_and_exit("test_dirname <path>\n");

	if ((path = strdup(argv[1])) == NULL)
		error_and_exit("strdup %s failed: %m\n", argv[1]);
	base_dir = strdup(dirname(path));
	if (base_dir == NULL)
		error_and_exit("strdup dirname %s failed: %m\n", path);
	else
		printf("base_dir = %s\n", base_dir);
	return 0;
}

static void show_hostent(struct hostent *hp) {
	assert(hp);
	
	/* official name of the host  */
	printf("h_name = %s\n", hp->h_name);
	/* alternative names of the host  */
	char **alias;
	for (alias = hp->h_aliases; *alias; alias++) {
		if (alias == hp->h_aliases)
			printf("h_aliases = %s\n", *alias);
		else
			printf("          = %s\n", *alias);
	}
	/* host address type  */
	if (hp->h_addrtype == AF_INET)
		printf("h_addrtype = AFINET\n");
	else if (hp->h_addrtype == AF_INET6)
		printf("h_addrtype = AFINET6\n");
	else
		printf("h_addrtype = UNKNOWN\n");
	/* length, in bytes, of each address  */
	printf("h_length = %d\n", hp->h_length);
	/* addresses for the host  */
	char **addr;
	int i;
	for (addr = hp->h_addr_list; *addr; addr++) {
		if (addr == hp->h_addr_list) {
			printf("h_addr_list = ");
			for (i = 0; i < hp->h_length; i++)
				if (i == 0)
					printf("%u", (unsigned char)(*addr)[i]);
				else
					printf(".%u", (unsigned char)(*addr)[i]);
			printf("\n");
		} else {
			printf("            = ");
			for (i = 0; i < hp->h_length; i++)
				if (i == 0)
					printf("%u", (unsigned char)(*addr)[i]);
				else
					printf(".%u", (unsigned char)(*addr)[i]);
			printf("\n");
		}
	}
}

/* test hostname related functions  */
static int test_hostname(int argc, char **argv) {
	struct hostent *hp;
	
	if (argc < 2)
		error_and_exit("test_hostname <hostname>\n");
	hp = gethostbyname(argv[1]);
	show_hostent(hp);
	return 0;
}

/* output contents of argv[1], starting from postition argv[2] with length of argv[3]  */
/*
 * FILE: 0 ... pa_offset ... offset ... offset + length
 * MMAP: (addr)pa_offset ... offset ... offset + length
 * so the mapped file is a little longer than required to meet the page aligning requirement
 */
static int test_mmap(int argc, char **argv) {
	char *addr;
	int fd;
	struct stat sb;
	off_t offset, pa_offset;
	size_t length;
	ssize_t s;

	if (argc < 3 || argc > 4)
		error_and_exit("test_mmap FILE OFFSET [LENGTH]\n");

	if ((fd = open(argv[1], O_RDONLY)) < 0)
		error_and_exit("open %s failed: %m\n", argv[1]);

	/* get file size  */
	if (fstat(fd, &sb) < 0)
		error_and_exit("fstat %s failed: %m\n", argv[1]);

	/* get offset and check validity  */
	offset = atoi(argv[2]);
	pa_offset = offset & ~(sysconf(_SC_PAGE_SIZE) - 1);	/* mmap's offset must be page aligned  */
	if (offset >= sb.st_size)
		error_and_exit("%ld has passed the file end\n", offset);

	/* get length and adjust it  */
	if (argc == 4) {
		length = atoi(argv[3]);
		if (offset + length > sb.st_size)
			length = sb.st_size - offset;
	} else {
		length = sb.st_size - offset;
	}

	/* mmap file  */
	addr = mmap(NULL, length + offset - pa_offset, PROT_READ, MAP_PRIVATE, fd, pa_offset);
	if (addr == MAP_FAILED)
		error_and_exit("mmap failed: %m\n");

	/* write out  */
	s = write(1, addr + offset - pa_offset, length);
	if (s < 0)
		error_and_exit("write failed: %m\n");
	if (s != length)
		error_and_exit("partial write\n");

	/* munmap file  */
	munmap(addr, length + offset - pa_offset);

	/* close the file  */
	close(fd);

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
	for (int i=getdtablesize(); i>=0; i--)
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
 * output to stdout or file specified by argv[1]
 */
static int show_proc_info(int argc, char **argv) {
	pid_t p;
	FILE *f;		/* file for output stream  */
	FILE *ftemp;
	DIR *dirp;		/* directory stream  */
	char *linep;		/* line pointer  */
	struct dirent *dentp;	/* directory entry  */
	char entry[PATH_MAX];	/* hold entry in /proc/pid/xxx  */
	char buf[PATH_MAX];
	char c;
	int len;
	int i;			/* for iteration  */
	size_t n;		/* for size_t vars  */

	if (argc == 1)
		f = stdout;
	else
		if ((f = fopen(argv[1], "w")) == NULL)
			error_and_exit("fopen %s failed: %m\n", argv[1]);

	/* IDs: pid, tid, ppid, pgid, sid  */
	p = getpid();
	if (p < 0)
		error_and_exit("getpid failed: %m\n");
	fprintf(f, "               pid : %d\n", p);

	p = syscall(SYS_gettid);
	if (p < 0)
		error_and_exit("gettid failed: %m\n");
	fprintf(f, "               tid : %d\n", p);

	p = getppid();
	if (p < 0)
		error_and_exit("getppid failed: %m\n");
	fprintf(f, "              ppid : %d\n", p);

	p = getpgid(0);
	if (p < 0)
		error_and_exit("getpgid failed: %m\n");
	fprintf(f, "              pgid : %d\n", p);

	p = getsid(0);
	if (p < 0)
		error_and_exit("getsid failed: %m\n");
	fprintf(f, "               sid : %d\n", p);

	/* comm and cmdline  */
	/* we could use prctl as an alternative  */
	sprintf(entry, "/proc/%d/task/%ld/comm", getpid(), syscall(SYS_gettid));
	ftemp = fopen(entry, "r");
	if (ftemp == NULL)
		error_and_exit("open %s failed: %m\n", entry);
	fprintf(f, "              comm : ");
	while (fread(&c, 1, 1, ftemp)) {
		if (c == '\0')
			c = ' ';
		if (!fwrite(&c, 1, 1, f))
			error_and_exit("fwrite (c = %c) failed: %m\n", c);
	}
	if (!feof(ftemp))
		error_and_exit("something failed when reading %s: %m\n", entry);
	fclose(ftemp);

	/* almost dumplicate with the above, should convert to a function  */
	sprintf(entry, "/proc/%d/cmdline", getpid());
	ftemp = fopen(entry, "r");
	if (ftemp == NULL)
		error_and_exit("open %s failed: %m\n", entry);
	fprintf(f, "           cmdline : ");
	while (fread(&c, 1, 1, ftemp)) {
		if (c == '\0')
			c = ' ';
		if (!fwrite(&c, 1, 1, f))
			error_and_exit("fwrite (c = %c) failed: %m\n", c);
	}
	fprintf(f, "\n");
	if (!feof(ftemp))
		error_and_exit("something failed when reading %s: %m\n", entry);
	fclose(ftemp);

	/* cwd  */
	p = getpid();
	sprintf(entry, "/proc/%d/cwd", p);
	len = readlink(entry, buf, PATH_MAX-1);
	if (len > 0)
		buf[len] = 0;
	else
		error_and_exit("readlink %s failed: %m\n", entry);
	fprintf(f, "               cwd : %s\n", buf);

	/* _initial_ environment  */
	sprintf(entry, "/proc/%d/environ", p);
	ftemp = fopen(entry, "r");
	if (ftemp == NULL)
		error_and_exit("open %s failed: %m\n", entry);
	fprintf(f, "      init environ : [START]\n");
	while (fread(&c, 1, 1, ftemp)) {
		if (c == '\0')
			fprintf(f, "\n");
		if (!fwrite(&c, 1, 1, f))
			error_and_exit("fwrite (c = %c) failed: %m\n", c);
	}
	fprintf(f, "      init environ : [END]\n");
	if (!feof(ftemp))
		error_and_exit("something failed when reading %s: %m\n", entry);
	fclose(ftemp);

	/* exe  */
	sprintf(entry, "/proc/%d/cwd", p);
	len = readlink(entry, buf, PATH_MAX-1);
	if (len > 0)
		buf[len] = 0;
	else
		error_and_exit("readlink %s failed: %m\n", entry);
	fprintf(f, "               exe : %s\n", buf);

	/* fd  */
	/* dummy method for easier ordering  */
	fprintf(f, "                fd : [START]\n");
	for (i=0; i<=getdtablesize(); i++) {
		sprintf(entry, "/proc/%d/fd/%d", p, i);
		if ((len = readlink(entry, buf, PATH_MAX-1)) > 0) {
			buf[len] = 0;
			fprintf(f, "                   : %d -> %s\n", i, buf);
		}
	}
	fprintf(f, "                fd : [END]\n");

	/* fdinfo  */
	/* we might need to do more, but for now, output entries is enough  */
	sprintf(entry, "/proc/%d/fdinfo", p);
	dirp = opendir(entry);
	if (dirp == NULL)
		error_and_exit("open dir %s failed: %m\n", entry);
	fprintf(f, "            fdinfo :");
	while ((dentp = readdir(dirp)) != NULL) {
		if (!(!strcmp(dentp->d_name, ".") || !strcmp(dentp->d_name, "..")))
			fprintf(f, " %s", dentp->d_name);
	}
	fprintf(f, "\n");
	closedir(dirp);
	dirp = NULL;

	/* examining uid_map and gid_map of the same process does not make much sense  */
	/* see user_namespaces(7)  */

	/* io  */
	sprintf(entry, "/proc/%d/io", p);
	ftemp = fopen(entry, "r");
	if (ftemp == NULL)
		error_and_exit("open %s failed: %m\n", entry);
	fprintf(f, "                io : [START]\n");
	fprintf(f, "                   : ");
	while (fread(&c, 1, 1, ftemp)) {
		if (c == '\n') {
			fprintf(f, "\n");
			fprintf(f, "                   : ");
		} else if (!fwrite(&c, 1, 1, f))
			error_and_exit("fwrite (c = %c) failed: %m\n", c);
	}
	fprintf(f, "\b\b\b\b\bio : [END]\n");
	if (!feof(ftemp))
		error_and_exit("something failed when reading %s: %m\n", entry);
	fclose(ftemp);

	/* limits  */
	/* why use getline here? just to demonstrate another way  */
	sprintf(entry, "/proc/%d/limits", p);
	if ((ftemp = fopen(entry, "r")) == NULL)
		error_and_exit("fopen %s failed: %m\n", entry);
	fprintf(f, "            limits : [START]\n");
	linep = NULL;
	n = 0;
	while (getline(&linep, &n, ftemp) > 0) {
		fprintf(f, "                   : %s", linep);
	}
	fprintf(f, "            limits : [END]\n");
	fclose(ftemp);
	if (linep) {
		free(linep);
		linep = NULL;
	}

	/* loginuid  */
	/* why use getdelim? just to demonstrate another way  */
	sprintf(entry, "/proc/%d/loginuid", p);
	if ((ftemp = fopen(entry, "r")) == NULL)
		error_and_exit("fopen %s failed: %m\n", entry);
	fprintf(f, "          loginuid : ");
	linep = NULL;
	n = 0;
	if (getdelim(&linep, &n, 0, ftemp) <= 0)
		error_and_exit("getline %s failed: %m\n", entry);
	fprintf(f, "%s\n", linep);
	free(linep);
	linep = NULL;

	/* map_files/  */
	sprintf(entry, "/proc/%d/map_files", p);
	dirp = opendir(entry);
	if (dirp == NULL)
		error_and_exit("opendir %s failed: %m\n", entry);
	fprintf(f, "         map_files : [START]\n");
	while ((dentp = readdir(dirp)) != NULL) {
		sprintf(entry, "/proc/%d/map_files/%s", p, dentp->d_name);
		if (!strcmp(dentp->d_name, ".") || !strcmp(dentp->d_name, ".."))
			continue;
		if ((len = readlink(entry, buf, PATH_MAX-1)) > 0) {
			buf[len] = 0;
			fprintf(f, "                   : %s -> %s\n", dentp->d_name, buf);
		}
	}
	fprintf(f, "         map_files : [END]\n");
	closedir(dirp);
	dirp = NULL;

	/* maps  */
	sprintf(entry, "/proc/%d/maps", p);
	ftemp = fopen(entry, "r");
	if (ftemp == NULL)
		error_and_exit("fopen %s failed: %m\n", entry);
	fprintf(f, "              maps : [START]\n");
	while(getline(&linep, &n, ftemp) > 0) {
		fprintf(f, "                   : %s", linep);
	}
	fclose(ftemp);
	if (linep) {
		free(linep);
		linep = NULL;
	}
	fprintf(f, "              maps : [END]\n");

	/* mem  */
	/* it mostly needs to be used together with /proc/pid/maps  */
	sprintf(entry, "/proc/%d/mem", p);
	ftemp = fopen(entry, "r");
	if (ftemp == NULL)
		error_and_exit("fopen %s failed: %m\n", entry);
	fprintf(f, "               mem : [available]\n");
	fclose(ftemp);

	/* mountinfo  */
	sprintf(entry, "/proc/%d/mountinfo", p);
	ftemp = fopen(entry, "r");
	if (ftemp == NULL)
		error_and_exit("fopen %s failed: %m\n", entry);
	fprintf(f, "         mountinfo : [START]\n");
	while(getline(&linep, &n, ftemp) > 0) {
		fprintf(f, "                   : %s", linep);
	}
	fclose(ftemp);
	if (linep) {
		free(linep);
		linep = NULL;
	}
	fprintf(f, "         mountinfo : [END]\n");

	/* mounts  */
	sprintf(entry, "/proc/%d/mounts", p);
	ftemp = fopen(entry, "r");
	if (ftemp == NULL)
		error_and_exit("fopen %s failed: %m\n", entry);
	fprintf(f, "            mounts : [START]\n");
	while(getline(&linep, &n, ftemp) > 0) {
		fprintf(f, "                   : %s", linep);
	}
	fclose(ftemp);
	if (linep) {
		free(linep);
		linep = NULL;
	}
	fprintf(f, "            mounts : [END]\n");

	/* mountstats  */
	sprintf(entry, "/proc/%d/mountstats", p);
	ftemp = fopen(entry, "r");
	if (ftemp == NULL)
		error_and_exit("fopen %s failed: %m\n", entry);
	fprintf(f, "        mountstats : [START]\n");
	while(getline(&linep, &n, ftemp) > 0) {
		fprintf(f, "                   : %s", linep);
	}
	fclose(ftemp);
	if (linep) {
		free(linep);
		linep = NULL;
	}
	fprintf(f, "        mountstats : [END]\n");

	/* net/: TODO  */
	
	/* ns/  */
	sprintf(entry, "/proc/%d/ns", p);
	dirp = opendir(entry);
	if (dirp == NULL)
		error_and_exit("opendir %s failed: %m\n", entry);
	fprintf(f, "                ns : [START]\n");
	while ((dentp = readdir(dirp)) != NULL) {
		sprintf(entry, "/proc/%d/ns/%s", p, dentp->d_name);
		if (!strcmp(dentp->d_name, ".") || !strcmp(dentp->d_name, ".."))
			continue;
		if ((len = readlink(entry, buf, PATH_MAX-1)) > 0) {
			buf[len] = 0;
			fprintf(f, "                   : %s -> %s\n", dentp->d_name, buf);
		}
	}
	fprintf(f, "                ns : [END]\n");
	closedir(dirp);
	dirp = NULL;

	/* oom_adj  */
	sprintf(entry, "/proc/%d/oom_adj", p);
	ftemp = fopen(entry, "r");
	if (ftemp == NULL)
		error_and_exit("fopen %s failed: %m\n", entry);
	fprintf(f, "           oom_adj : ");
	if (getline(&linep, &n, ftemp) < 0)
		error_and_exit("getline %s failed: %m\n", entry);
	fprintf(f, "%s", linep);
	if (linep) {
		free(linep);
		linep = NULL;	
	}
	fclose(ftemp);

	/* oom_score  */
	sprintf(entry, "/proc/%d/oom_score", p);
	ftemp = fopen(entry, "r");
	if (ftemp == NULL)
		error_and_exit("fopen %s failed: %m\n", entry);
	fprintf(f, "         oom_score : ");
	if (getline(&linep, &n, ftemp) < 0)
		error_and_exit("getline %s failed: %m\n", entry);
	fprintf(f, "%s", linep);
	if (linep) {
		free(linep);
		linep = NULL;	
	}
	fclose(ftemp);

	/* oom_score_adj  */
	sprintf(entry, "/proc/%d/oom_score_adj", p);
	ftemp = fopen(entry, "r");
	if (ftemp == NULL)
		error_and_exit("fopen %s failed: %m\n", entry);
	fprintf(f, "     oom_score_adj : ");
	if (getline(&linep, &n, ftemp) < 0)
		error_and_exit("getline %s failed: %m\n", entry);
	fprintf(f, "%s", linep);
	if (linep) {
		free(linep);
		linep = NULL;	
	}
	fclose(ftemp);

	/* pagemap: TODO  */
	
	/* projid_map  */
	/* similar to uid_map and gid_map, do self examining does not make much sense  */
	
	/* root  */
	sprintf(entry, "/proc/%d/root", p);
	len = readlink(entry, buf, PATH_MAX-1);
	if (len > 0)
		buf[len] = 0;
	else
		error_and_exit("readlink %s failed: %m\n", entry);
	fprintf(f, "              root : %s\n", buf);
	
	/* sched  */
	sprintf(entry, "/proc/%d/sched", p);
	ftemp = fopen(entry, "r");
	if (ftemp == NULL)
		error_and_exit("fopen %s failed: %m\n", entry);
	fprintf(f, "             sched : [START]\n");
	while(getline(&linep, &n, ftemp) > 0) {
		fprintf(f, "                   : %s", linep);
	}
	fclose(ftemp);
	if (linep) {
		free(linep);
		linep = NULL;
	}
	fprintf(f, "             sched : [END]\n");
	
	/* schedstats  */
	sprintf(entry, "/proc/%d/schedstat", p);
	ftemp = fopen(entry, "r");
	if (ftemp == NULL)
		error_and_exit("fopen %s failed: %m\n", entry);
	fprintf(f, "         schedstat : ");
	if (getline(&linep, &n, ftemp) < 0)
		error_and_exit("getline %s failed: %m\n", entry);
	fprintf(f, "%s", linep);
	if (linep) {
		free(linep);
		linep = NULL;	
	}
	fclose(ftemp);

	/* sessionid  */
	sprintf(entry, "/proc/%d/sessionid", p);
	ftemp = fopen(entry, "r");
	if (ftemp == NULL)
		error_and_exit("fopen %s failed: %m\n", entry);
	fprintf(f, "         sessionid : ");
	if (getline(&linep, &n, ftemp) < 0)
		error_and_exit("getline %s failed: %m\n", entry);
	fprintf(f, "%s\n", linep);
	if (linep) {
		free(linep);
		linep = NULL;	
	}
	fclose(ftemp);

	/* setgroups  */
	sprintf(entry, "/proc/%d/setgroups", p);
	ftemp = fopen(entry, "r");
	if (ftemp == NULL)
		error_and_exit("fopen %s failed: %m\n", entry);
	fprintf(f, "         setgroups : ");
	if (getline(&linep, &n, ftemp) < 0)
		error_and_exit("getline %s failed: %m\n", entry);
	fprintf(f, "%s", linep);
	if (linep) {
		free(linep);
		linep = NULL;	
	}
	fclose(ftemp);

	/* smaps  */
	sprintf(entry, "/proc/%d/smaps", p);
	ftemp = fopen(entry, "r");
	if (ftemp == NULL)
		error_and_exit("fopen %s failed: %m\n", entry);
	fprintf(f, "             smaps : [shows memory consumption for each of the process's mappings, too long thus snipped]\n");
	fclose(ftemp);

	/* stack*/
	sprintf(entry, "/proc/%d/stack", p);
	ftemp = fopen(entry, "r");
	if (ftemp == NULL)
		error_and_exit("fopen %s failed: %m\n", entry);
	fprintf(f, "             stack : [START]\n");
	while(getline(&linep, &n, ftemp) > 0) {
		fprintf(f, "                   : %s", linep);
	}
	fclose(ftemp);
	if (linep) {
		free(linep);
		linep = NULL;
	}
	fprintf(f, "             stack : [END]\n");

	/* stat  */
	fprintf(f, "              stat : [to do]\n");
	
	/* statm  */
	int statm_size, statm_resident, statm_shared;
	int statm_text, statm_lib, statm_data, statm_dt;	/* lib and dt are obsolete since 2.6  */
	int num_scanf;
	sprintf(entry, "/proc/%d/statm", p);
	ftemp = fopen(entry, "r");
	if (ftemp == NULL)
		error_and_exit("fopen %s failed: %m\n", entry);
	num_scanf = fscanf(ftemp, "%i %i %i %i %i %i %i", &statm_size, &statm_resident,
			&statm_shared, &statm_text, &statm_lib, &statm_data, &statm_dt);
	if (num_scanf != 7)
		error_and_exit("fscanf %s failed, num_scanf = %u\n", entry, num_scanf);
	fprintf(f, "             statm : [START]\n");
	fprintf(f, "                   : %-10d(size)\n", statm_size);
	fprintf(f, "                   : %-10d(resident)\n", statm_resident);
	fprintf(f, "                   : %-10d(shared)\n", statm_shared);
	fprintf(f, "                   : %-10d(text)\n", statm_text);
	fprintf(f, "                   : %-10d(lib, obsolete)\n", statm_lib);
	fprintf(f, "                   : %-10d(data)\n", statm_data);
	fprintf(f, "                   : %-10d(dt, obsolete)\n", statm_dt);
	fprintf(f, "             statm : [END]\n");
	fclose(ftemp);
	
	/* status  */
	sprintf(entry, "/proc/%d/status", p);
	ftemp = fopen(entry, "r");
	if (ftemp == NULL)
		error_and_exit("fopen %s failed: %m\n", entry);
	fprintf(f, "            status : [START]\n");
	while(getline(&linep, &n, ftemp) > 0) {
		fprintf(f, "                   : %s", linep);
	}
	fclose(ftemp);
	if (linep) {
		free(linep);
		linep = NULL;
	}
	fprintf(f, "            status : [END]\n");

	/* syscall  */
	sprintf(entry, "/proc/%d/syscall", p);
	ftemp = fopen(entry, "r");
	if (ftemp == NULL)
		error_and_exit("fopen %s failed: %m\n", entry);
	fprintf(f, "           syscall : ");
	if (getline(&linep, &n, ftemp) < 0)
		error_and_exit("getline %s failed: %m\n", entry);
	fprintf(f, "%s", linep);
	if (linep) {
		free(linep);
		linep = NULL;	
	}
	fclose(ftemp);

	/* task/: TODO  */

	/* wchan  */
	sprintf(entry, "/proc/%d/wchan", p);
	ftemp = fopen(entry, "r");
	if (ftemp == NULL)
		error_and_exit("fopen %s failed: %m\n", entry);
	fprintf(f, "             wchan : ");
	if (getline(&linep, &n, ftemp) < 0)
		error_and_exit("getline %s failed: %m\n", entry);
	fprintf(f, "%s\n", linep);
	if (linep) {
		free(linep);
		linep = NULL;	
	}
	fclose(ftemp);

	return 0;
}

/*
 * output process info to @outfile when receiving SIGINT
 */
static void sig_handler_process_info(int sig) {
	show_proc_info(1, NULL);
}

/*
 * use inotify to monitor the creation/removal of a file
 * and sync it with the other
 */
static int _monitor_and_sync(const char *srcf, const char *dstf) {
	while(1) {
		sleep(10);	
	}
	return 0;
}

static int monitor_and_sync(int argc, char **argv) {
	char *srcf, *dstf;

	assert(argc == 3);
	srcf = argv[1];
	dstf = argv[2];

	signal(SIGINT, sig_handler_process_info);

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
	printf("*****************************\n");
	printf("*        tiny   init        *\n");
	printf("*****************************\n");

	/* execute shell  */
	char *shell = getenv("SHELL");
	setenv("PS1", "[tinyinit] $ ", 1);
	execle(shell, shell, NULL, environ);

	/* default to execute busybox sh  */
	execl("/sbin/busybox", "sh", "-l", NULL);
	execl("/bin/busybox", "sh", "-l", NULL);

	fprintf(stderr, "WE SHOULD NEVER GET HERE!\n");
	return 0;
}

/* the active jobs are linked into a list, this is its head  */
static job *first_job = NULL;
/* keep track of the shell attributes  */
static pid_t shell_pgid;
static struct termios shell_tmodes;
static int shell_terminal;
static int shell_is_interactive;

/* declaration of some functions  */
static void put_job_in_foreground(job *j, int count);
static void put_job_in_background(job *j, int count);
static void wait_for_job(job *j);
static void format_job_info(job *j, const char *status);
static void free_job(job *j);

static void free_job(job *j) {
	if (j == NULL)
		return;
		
	if (j->command)
		free(j->command);

	free(j);	
}

/* Find the active job with indicated pgid  */
static job *find_job(pid_t pgid) {
	job *j;
	for (j=first_job; j; j=j->next) {
		if (j->pgid == pgid)
			return j;	
	}
	return NULL;
}

/* Return true if all processes in the job have completed or stopped  */
static int job_is_stopped(job *j) {
	process *p;
	for (p=j->first_process; p; p=p->next) {
		if (!p->completed && !p->stopped)
			return 0;
	}
	return 1;
}

/* Return true if all processes in the job have completed  */
static int job_is_completed(job *j) {
	process *p;
	for (p=j->first_process; p; p=p->next) {
		if (!p->completed)
			return 0;
	}
	return 1;
}

/* Make sure the shell is running interactively as the foreground job before proceeding  */
static void init_shell(void) {
	/* See if we are running interactively  */
	shell_terminal = STDIN_FILENO;
	shell_is_interactive = isatty(shell_terminal);
	if (!shell_is_interactive)
		return;

	/* interactive shell; do below setups  */

	/* loop until we are in the foreground  */
	while (tcgetpgrp(shell_terminal) != (shell_pgid = getpgrp()))
		kill(-shell_pgid, SIGTTIN);
	/* ignore interactive and job-control signals  */
	signal(SIGTTIN, SIG_IGN);
	signal(SIGTTOU, SIG_IGN);
	signal(SIGQUIT, SIG_IGN);
	signal(SIGTSTP, SIG_IGN);
	signal(SIGINT, SIG_IGN);
	signal(SIGCHLD, SIG_IGN);
	/* put ourselves in our own process group  */
	shell_pgid = getpid();
	if (setpgid(shell_pgid, shell_pgid) < 0)
		error_and_exit("setpgid(%d, %d) failed: %m\n", shell_pgid, shell_pgid);	
	/* grab control of the terminal  */
	if (tcsetpgrp(shell_terminal, shell_pgid) < 0)
		error_and_exit("tcsetpgrp failed: %m\n");
	/* save the terminal attributes  */
	if (tcgetattr(shell_terminal, &shell_tmodes) < 0)
		error_and_exit("tcgetattr failed: %m\n");
}

static void launch_process(process *p, pid_t pgid, int infile, int outfile, int errfile, int foreground) {
	pid_t pid;
	
	/*
	 * if launched by interactive shell,
	 * - set to be the process group header
	 * - set to be the foreground process of the controlling terminal
	 * - reset the signal handlers
	 */
	if (shell_is_interactive) {
		pid = getpid();
		if (pgid == 0)
			pgid = pid;
		if (setpgid(pid, pgid) < 0)
			error_and_exit("launch_process: setpgid(%d, %d) failed: %m\n", pid, pgid);
		if (foreground)
			if (tcsetpgrp(shell_terminal, pgid) < 0)
				error_and_exit("launch_process: tcsetpgrp failed: %m\n");
		signal(SIGTTIN, SIG_IGN);
		signal(SIGTTOU, SIG_IGN);
		signal(SIGQUIT, SIG_IGN);
		signal(SIGTSTP, SIG_IGN);
		signal(SIGINT, SIG_IGN);
		signal(SIGCHLD, SIG_IGN);
	}
	
	/* set the standard input/output channels  */
	if (infile != STDIN_FILENO) {
		dup2(infile, STDIN_FILENO);
		close(infile);
	}
	if (outfile != STDOUT_FILENO) {
		dup2(outfile, STDOUT_FILENO);
		close(outfile);	
	}
	if (errfile != STDERR_FILENO) {
		dup2(errfile, STDERR_FILENO);
		close(errfile);	
	}
	
	/* exec the new process  */
	execvp(p->argv[0], p->argv);
	error_and_exit("execvp failed: %m\n");
}

static void launch_job(job *j, int foreground) {
	process *p;
	pid_t pid;
	int mypipe[2], infile, outfile;
	
	/*
	 * For a job (p1 | p2 | p3 | ... | pN),
	 * p1's infile is stdin of job; outfile in pipe's write end;
	 * p2 ... pN-1's infile is pipe's read end; outfile is pipe's write end;
	 * pN's infile is pipe's read end; outfile is stdout of job
	 *
	 * Also, all processes in a job are child processes of shell.
	 */
	for (p = j->first_process; p; p=p->next) {
		/* for every process, set its pgid and its input/output  */
		if (p == j->first_process)
			infile = j->stdin;
		else
			infile = mypipe[0];
		if (p->next) {
			if (pipe(mypipe) < 0)
				error_and_exit("launch_job: creating pipe failed: %m\n");
			outfile = mypipe[1];
		} else
			outfile = j->stdout;
		pid = fork();
		if (pid == 0) {
			/* child process; do exec;  */	
			launch_process(p, j->pgid, infile, outfile, j->stderr, foreground);
		} else if (pid < 0) {
			error_and_exit("launch_job: fork failed: %m\n");
		} else {
			p->pid = pid;
			if (shell_is_interactive) {
				if (!j->pgid) {
					/* in this way, all proccess in the same job has the same pgid, which equals to the pid of the first child  */	
					j->pgid = pid;
				}
				if (setpgid(pid, j->pgid) < 0)
					error_and_exit("launch_job: setpgid(%d, %d) failed: %m\n", pid, j->pgid);
			}	
		}
		/* parent process (shell): clean up the pipes (note: launch_process never returns)  */
		/* the logic is, if infile (outfile) is a file descriptor related to pipe, clean it up as it has been used by child  */
		if (infile != j->stdin)
			close(infile);
		if (outfile != j->stdout)
			close(outfile);
	}
	
	format_job_info(j, "launched");

	if (!shell_is_interactive)
		wait_for_job(j);
	else if(foreground)
		put_job_in_foreground(j, 0);
	else
		put_job_in_background(j, 0);
}

/*
 * put job in foreground
 * if count is nonzero, restore the job's terminal modes, send it SIGCONT
 */
static void put_job_in_foreground(job *j, int count) {
	if (tcsetpgrp(shell_terminal, j->pgid) < 0)
		error_and_exit("put_job_in_foreground: put job to foreground failed: %m\n");
	if (count) {
		tcsetattr(shell_terminal, TCSADRAIN, &j->tmodes);
		if (kill(-j->pgid, SIGCONT) < 0)
			error_and_exit("put_job_in_foreground: sending SIGCONT failed: %m\n");
	}
	
	/* wait for job to report  */
	wait_for_job(j);
	
	/* put shell back to foreground  */
	if (tcsetpgrp(shell_terminal, shell_pgid) < 0)
		error_and_exit("put_job_in_foreground: put shell back to foreground failed: %m\n");
	tcgetattr(shell_terminal, &j->tmodes);
	tcsetattr(shell_terminal, TCSADRAIN, &shell_tmodes);
}

/*
 * this function will only be called when shell is in foreground
 * so do nothing except sending SIGCONT when count is nonzero
 */
static void put_job_in_background(job *j, int count) {
	if (count) {
		if (kill(-j->pgid, SIGCONT) < 0)
			error_and_exit("put_job_in_background: sending SIGCONT failed: %m\n");
	}
}

/*
 * store status of process pid that was returned by waitpid.
 * return 0 if all went well; nonzero otherwise.
 */
static int make_process_status(pid_t pid, int status) {
	job *j;
	process *p;
	
	if (pid == 0)
		/* no process ready to report  */
		return -1;
	else if (pid < 0 && errno == ECHILD)
		/* no process ready to report  */
		return -1;
	else if (pid < 0) {
		fprintf(stderr, "waitpid\n");
		return -1;
	}
	
	/* pid > 0  */
	for (j=first_job; j; j=j->next) {
		for (p=j->first_process; p; p=p->next) {
			if (p->pid != pid)
				continue;
			/* found the specified process  */
			p->status = status;
			if (WIFSTOPPED(status))
				p->stopped = 1;
			else {
				p->completed = 1;
				if (WIFSIGNALED(status))
					fprintf(stderr, "%d: Terminated by signal %d.\n",
						(int)pid, WTERMSIG(status));	
			}
			return 0;
		}	
	}
	fprintf(stderr, "No child process %d.\n", pid);
	return -1;
}

/*
 * check for process that have status information available without blocking
 */
static void update_status(void) {
	int status;
	pid_t pid;
	
	do {
		pid = waitpid(-1, &status, WNOHANG|WUNTRACED);
	} while(!make_process_status(pid, status));	
}

/*
 * check for processes that have status information available
 * blocking until all process in the given job have all reported
 */
static void wait_for_job(job *j) {
	int status;
	pid_t pid;
	
	do {
		pid = waitpid(-1, &status, WUNTRACED);
	} while (!make_process_status(pid, status)
		&& !job_is_stopped(j)
		&& !job_is_completed(j));
}

/* format job status information for the user to look at  */
static void format_job_info(job *j, const char *status) {
	fprintf(stderr, "%d (%s): %s\n", j->pgid, status, j->command);
}

/* notify the user about stopped or terminated jobs  */
static void do_job_notification(void) {
	job *j, *jnext;
	job *jlast;		/* last non-terminated job  */
	
	/* update status for child processes  */
	update_status();
	
	/* iterate over the active job list
	   report stopped or terminated jobs
	   and free terminated job  */
	jlast = NULL;
	for (j=first_job; j; j=j->next) {
		jnext = j->next;
		if (job_is_completed(j)) {
			format_job_info(j, "completed");
			if (!jlast)
				first_job = jnext;
			else
				jlast->next = jnext;
			free_job(j);
		} else if (job_is_stopped(j) && !j->notified) {
			format_job_info(j, "stopped");
			j->notified = 1;
			jlast = j;
		} else {
			/* report nothing about running jobs  */
			jlast = j;
		}	
	}
}

/* mark a stopped job as running again  */
static void mark_job_as_running(job *j) {
	process *p;
	
	for (p=j->first_process; p; p=p->next) {
		p->stopped = 0;	
	}
	j->notified = 0;
}

/* continue the job  */
static void continue_job(job *j, int foreground) {
	mark_job_as_running(j);
	if (foreground)
		put_job_in_foreground(j, 1);
	else
		put_job_in_background(j, 1);
}

static int simpleshell(int argc, char **argv) {
	fprintf(stderr, "TO BE IMPLEMENTED\n");
	return 1;	
}

/* define the function table */
static struct func_tab functab[NFUNCS] = {
	{"func_test", func_test},
	{"test_hostname", test_hostname},
	{"test_mmap", test_mmap},
	{"test_dirname", test_dirname},
	{"chroot_and_list", chroot_and_list},
	{"malloc_and_free", malloc_and_free},
	{"create_zombie", create_zombie_process},
	{"simple_daemon", simple_daemon},
	{"complex_daemon", complex_daemon},
	{"show_process_info", show_proc_info},
	{"monitor_and_sync", monitor_and_sync},
	{"simpleshell", simpleshell},
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

/*
 * C codes to illustrate systemd daemon paradigm and traditional sysv daemon paradigm
 *
 * COMPILE: 
 * 	gcc -lsystemd -o mydaemon small-talk-daemon-types.c
 *      Note that systemd-devel package is needed.
 * RUNTIME:
 *      START: 1) Write a simple unit file and start it
 *                `./mydaemon gen-TYPE' for convenience
 *             2) Or use systemd-run as a quick way to start.
 *                e.g.
 *                  systemd-run --unit=mydaemon.service --property=Type=TYPE /path/to/mydaemon --type-TYPE
 *      CHECK: journal -n 10
 *             systemctl  status  mydeamon.service
 *             systemctl  cat     mydaemon.service
 *      STOP:  systemctl  stop    mydaemon.service
 *      For more details, checkt the comments for each type.
 */


#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <stdarg.h>
#include <string.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <limits.h>
#include <systemd/sd-daemon.h>

/* mydaemon logs "mydaemon: TYPE - counts" every INTERVAL seconds  */
#define INTERVAL 10
const char *PROGNAME = "mydaemon";
int counts = 0;

/* for dbus type service, refer to previous small talk  */
const char *dbus_url = "http://twiki.wrs.com/pub/PBUeng/CoreLinuxDevTeam/small-talk-dbus-intro.txt";

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

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

void gen_unit_under_run(char *type) {
	FILE *f;
	char progpath[PATH_MAX];
	const char *fname = "/run/systemd/system/mydaemon.service";

	if (getcwd(progpath, PATH_MAX) == NULL)
		error_and_exit("getcwd failed: %m\n");
	strcat(progpath, "/mydaemon");
	if ((f = fopen(fname, "w")) == NULL)
		error_and_exit("failed to open %s: %m\n", fname);
	fprintf(f, "[Unit]\n");
	fprintf(f, "Description=mydaemon\n");
	fprintf(f, "[Service]\n");
	if (!strcmp(type, "simple")) {
		fprintf(f, "Type=simple\n");
	} else if (!strcmp(type, "forking")) {
		fprintf(f, "Type=forking\n");
		fprintf(f, "PIDFile=/tmp/mydaemon.pid\n");
	} else if (!strcmp(type, "oneshot")) {
		fprintf(f, "Type=oneshot\n");
		fprintf(f, "RemainAfterExit=yes\n");
	} else if (!strcmp(type, "dbus")) {
		error_and_exit("For dbus type service, refer to %s\n", dbus_url);
	} else if (!strcmp(type, "notify")) {
		fprintf(f, "Type=notify\n");
	} else if (!strcmp(type, "idle")) {
		fprintf(f, "Type=idle\n");
	} else
		error_and_exit("unknown type %s to generate\n", type);
	fprintf(f, "ExecStart=%s --type-%s\n", progpath, type);
	printf("%s generated!\n", fname);

	fclose(f);
}

/*
 **************************************************************
 *    MAIN FUNCTIONS                                          *
 **************************************************************
 */

/*
 * Type=simple
 * 
 * This is the default type for systemd services.
 * As you can see, no daemonization needs to be considered.
 * This is actually a foreground program. systemd takes care of daemonization.
 * Some packages use '-f' ('--foreground') when working with this Type setting.
 */
void type_simple(void) {
	for(;;) {
		syslog(LOG_INFO, "%s: simple - %d\n", PROGNAME, counts);
		sleep(INTERVAL);
		counts++;	
	}
}

/*
 * Type=forking
 * PIDFile=/tmp/mydaemon.pid
 * 
 * This is the type for traditional sysv daemons that do fork-and-exit and
 * put the actuanl daemon service in child process.
 * Below is actually a typical traditional sysv daemon.
 */
void type_forking(void) {
	pid_t pid;
	int fd;
	int i;
	char spid[16];

	pid = fork();
	if (pid < 0)
		log_error_and_exit("fork() failed; %m\n");
	else if (pid > 0) {
		/* parent process  */
		/*
		 * For traidional sysv daemons, we can just exit(0) here.
		 * However, the PIDFile handling must be here when cooperating
		 * with systemd. (for sysv implementation, it's optional, i.e. the
		 * pid file handling could be in child process.)
		 * Otherwise, we will have complaints from systemd about PID file not readable yet.
		 */
		fd = open("/tmp/mydaemon.pid", O_RDWR|O_CREAT, 0640);
		if (fd < 0)
			log_error_and_exit("open PID file failed: %m\n");
		if (flock(fd, LOCK_EX) < 0)
			log_error_and_exit("Already Running, flock failed: %m\n");
		sprintf(spid, "%d\n", pid);
		write(fd, spid, strlen(spid));
		fsync(fd);
		if (flock(fd, LOCK_UN) < 0)
			log_error_and_exit("failed to unlock pid file: %m\n");
		close(fd);
		exit(0);
	}
	
	/* below is the child process part, it's the the real daemon  */

	/* obtain a new session */
	if (setsid() < 0)
		log_error_and_exit("setsid() failed: %m\n");

	/* change working directory  */
	if (chdir("/") < 0)
		log_error_and_exit("chdir to / failed: %m\n");

	/* close all other file descriptors  */
	for (i=getdtablesize(); i>=0; i--)
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
	fd = open("/tmp/mydaemon.pid", O_RDWR);
	if (fd < 0)
		log_error_and_exit("open PID file failed: %m\n");
	if (read(fd, spid, 16) < 0)
		log_error_and_exit("failed to read PID file: %m\n");
	if (atoi(spid) != (int)getpid())
		log_error_and_exit("PID file contents not match the actual daemon pid! EXIT!\n");
	if (flock(fd, LOCK_EX) < 0)
		log_error_and_exit("trying to ensure one instance failed, flock failed: %m\n");

	/* set file permission  */
	umask(0);

	/* handle signals  */
	/* placeholder here, just for completeness of traditional sysv daemon  */
	/* typical implemenation is some cleanups on SIGTERM  */

	/* service logic below  */
	for (;;) {
		syslog(LOG_INFO, "mydaemon: forking - %d\n", counts);
		sleep(INTERVAL);
		counts++;
	}
}

/*
 * Type=oneshot
 * RemainAfterExit=yes
 *
 * oneshot type service runs once and exits.
 * Strictly speaking, it's not daemon. It just starts to finish something and exits.
 */
void type_oneshot(void) {
	syslog(LOG_INFO, "mydaemon: oneshot - %d [Bye Bye]\n", counts);
}

/*
 * Type=dbus
 * BusName=xxx.xxx.xxx
 *
 * dbus type is actually like simple type, that is, it's coded as if it's running
 * in foreground. systemd takes care of daemonization for it.
 * However, it is expected that the daemon acquires a name on the D-Bus bus, as configured by BusName=.
 */
void type_dbus(void) {
	log_error_and_exit("For dbus type service, refer to %s\n", dbus_url);
}

/*
 * Type=notify
 *
 * notify type is like simple type, except that it will send notification to systemd
 * manager to announce it has finished starting up.
 */
void type_notify(void) {
	/* do whatever is needed before announcing started up  */
	/* e.g. privilege checking, resource checking, etc.  */
	
	/* check sd_notify(3) for more info  */
	sd_notify(0, "READY=1");

	for(;;) {
		syslog(LOG_INFO, "%s: notify - %d\n", PROGNAME, counts);
		sleep(INTERVAL);
		counts++;	
	}
}

void type_idle(void) {
	return;	
}

int main(int argc, char **argv) {
	if (argc != 2)
		log_error_and_exit("%s --type-TYPE (TYPE: simple, forking, oneshot, dbus, notify, idle)\n", PROGNAME);
	if (!strcmp(argv[1], "--type-simple"))
		type_simple();
	else if (!strcmp(argv[1], "--type-forking"))
		type_forking();
	else if (!strcmp(argv[1], "--type-oneshot"))
		type_oneshot();
	else if (!strcmp(argv[1], "--type-dbus"))
		type_dbus();
	else if (!strcmp(argv[1], "--type-notify"))
		type_notify();
	else if (!strcmp(argv[1], "--type-idle"))
		type_idle();
	else if (!strncmp(argv[1], "gen-", 4))
		gen_unit_under_run(argv[1]+4);
	else
		log_error_and_exit("%s --type-TYPE (TYPE: simple, forking, oneshot, dbus, notify, idle)\n", PROGNAME);

	return 0;
}

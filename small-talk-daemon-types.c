/*
 * C codes to illustrate systemd daemon paradigm and traditional sysv daemon paradigm
 *
 * COMPILE: 
 * 	gcc -o mydaemon small-talk-daemon-types.c
 * RUNTIME:
 *      mydaemon --type-xxx
 *      See comments for each type
 */


#include <unistd.h>
#include <stdio.h>
#include <syslog.h>

/* mydaemon logs "mydaemon: TYPE - counts" every INTERVAL seconds  */
#define INTERVAL 10
const char *PROGNAME = "mydaemon";
int counts = 0;


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

void type_simple(void) {
	for(;;) {
		syslog(LOG_INFO, "%s: simple - %d\n", PROGNAME, counts);
		sleep(INTERVAL);
		counts++;	
	}
}

int main(int argc, char **argv) {
	if (argc != 2)
		error_and_exit("%s --type-TYPE (TYPE: simple, forking, oneshot, dbus, notify, idle)\n");
	if (!strcmp(argv[1], "--type-simple"))
		type_simple();
	else
		error_and_exit("type not supported\n");

	return 0;
}

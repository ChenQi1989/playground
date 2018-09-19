#ifndef _PLAYGROUND_TEST_H
#define _PLAYGROUND_TEST_H

/* maxinum number of funcs */
#define NFUNCS 256

typedef int (*fn_t)(int, char**);

/* Struct to handle name-function mapping */
struct func_tab {
	char *name;
	fn_t fp;
};

#ifdef MEM_DEBUG
#define malloc mymalloc
#define free myfree
#endif

/* simple shell  */

typedef struct process {
	struct process *next;		/* next process in pipeline  */
	char **argv;			/* for exec  */
	pid_t pid;			/* process ID  */
	char completed;			/* true if process has completed  */
	char stopped;			/* true if process has stopped  */
	int status;			/* reported status vlue  */
} process;

typedef struct job {
	struct job *next;		/* next active job  */	
	char *command;			/* command line, used for messages  */
	process *first_process;		/* list of processes in this job  */
	pid_t pgid;			/* process group id  */
	char notified;			/* true if user told about stopped job  */
	struct termios tmodes;		/* saved terminal modes  */
	int stdin, stdout, stderr;	/* standard i/o channels  */
} job;

#endif

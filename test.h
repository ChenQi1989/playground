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

#endif

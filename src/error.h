/*
 * our own error function, borrowed from APUE (my Bible)
 */

#ifndef _TCT_ERROR
#define _TCT_ERROR

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdarg.h> 

#define MAXLINE 1024

/*
 * Nonfatal error related to a system call.
 * Print a message and return.
 */
void err_ret(const char *fmt, ...);

/*
 * fatal error related to a system call.
 * print a message and terminate.
 */
void err_sys(const char *fmt, ...);


/*
 * fatal error unrelated to a system call
 * Error code passed as explict parameter.
 * print a message and terminate.
 */
void err_exit(int error,const char *fmt, ...);

/*
 * fatal error related to a system call
 * print a message, dump core, and terminate
 */
void err_dump(const char *fmt, ...);


/*
 * Nonfatal error unrelated to system call.
 * Print a message and return.
 */
void err_msg(const char *fmt, ...);

/*
 * fatal error unrelated to a system call.
 * print a message and terminate.
 */
void err_quit(const char *fmt, ...);

#endif /* _TCT_ERROR */

#ifndef _TCT__APPCLASS
#define _TCT__APPCLASS

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

/* 
 * headers for network programming
 */
#include <netdb.h>	/* for uint16_t */

/* Classification output flags */
#define CLASS_OUT_ERR		1	/* classification error */
#define CLASS_OUT_REDO		2	/* classifier wants to re-examine session
					   when new data is available */
#define CLASS_OUT_NOMORE	4	/* classifier will not re-examine this session */

struct tct_group_class {
	uint16_t group_id;		/* should equ to the index of the group array */
	char *group_name;
	char *description;
};

struct tct_sub_class {
	uint16_t sub_id;
	char *sub_name;
	char *description;
	int flags;
	char classifier[36];	/* which classifier identified this class */
};

struct tct_app_class {
	uint16_t group_id;
	uint16_t app_id;
	struct tct_sub_class *sub;
	uint16_t sub_count;

	char *app_name;
	char *description;
};


/*
 * data struct for result of classification given by a classifier
 */
struct tct_result {
	short group_id;
	short app_id;
	short sub_id;
	short confidence;
	uint32_t flags;
	char name[64];		/* which classifier */
};

/* 
 * globle variables to store class information, declaration here
 */
extern struct tct_group_class *tct_group;
extern int group_size;

extern struct tct_app_class *tct_app;
extern int app_size;

/* and routines */
int load_class_def();

#endif /* _appclass */

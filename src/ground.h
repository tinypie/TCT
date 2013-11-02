#ifndef _TCT_GROUND
#define _TCT_GROUND

#include <time.h>
#include "struct.h"

#define PRE_SIZE 90007

struct class_info {
	struct five_tuple addr;
	short group_id;
	short app_id;
	short sub_id;
	struct timeval time;
	struct class_info *next;
	char name[64];
};

struct hash_table {
	struct hash_table *next;
	struct class_info *entry;
};

extern struct hash_table *tct_ground[PRE_SIZE];

int load_ground_truth();
struct class_info *find_ground_truth(struct five_tuple key, struct timeval start_time);
#endif /* _tct_ground */

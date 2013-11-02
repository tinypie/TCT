#ifndef _TCT_FREE
#define _TCT_FREE

#include "struct.h"

//#define MAX_TCP_PAIRS 18983
#define LIST_SEARCH_DEPT 200

struct connection **tct_ttp;	/* array of pointers to allocated tcp pairs */

struct double_list_free {
	struct double_list_free *next;
	struct double_list_free *prev;
	struct connection *ete;
};

struct memory_manage {
	int num_bflow;		/* the number of free struct bflow memory blocks ,in memory pool*/
	int num_bflow_use;	/* in use */
	int num_conn;
	int num_conn_use;
	int num_flow;
	int num_segment;
	int num_segment_use;
	int num_quadrant;
	int num_quadrant_use;
};

extern struct memory_manage tct_mm;

/* routines in memory.c */
void segment_release(struct segment * rel_segment);
struct segment *segment_alloc(void);
struct quadrant *quadrant_alloc(void);
void free_quad(struct quadrant ** ppquad);
struct connection *init_bflow(struct connection *prev);
struct connection *new_conn();
struct bflow_entry *new_bflow();
void bflow_dump_data();
void hash_pool();

void free_conn();
void free_bflow();
void free_class();
void free_others();

#endif /* _TCT_FREE */

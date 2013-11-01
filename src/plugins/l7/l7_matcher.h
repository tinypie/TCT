#ifndef L7_REGEXPR_H
#define L7_REGEXPR_H

#include "../plugin.h"

extern int add_pattern(const char *proto_name, const char *pattern, int eflags,
		       int cflags, int app_id, int app_sub_id);
extern bool init_matcher();
extern void try_match(void *s, struct tct_result *result);
extern void deinit_matcher();

#endif				// L7_REGEXPR_H

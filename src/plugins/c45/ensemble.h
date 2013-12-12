#ifndef _C45_ENSEMBLE
#define _C45_ENSEMBLE

#define NUM_ENSEMBLE 5
#define SCALE	0.3

extern union attribute_value **en_item;
int initial_ensemble();
int ada_boost();
int free_ensemble();
#endif

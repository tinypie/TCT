#ifndef _TCT_plugin
#define _TCT_plugin
#include "../tct.h"

#define CLASS_ENABLE 1

/* Functions and properties of a classification engine (classifier) */
struct tct_classifier {
	int (*disable) ();
	int (*enable) ();			/* whether the required features is satisfied */
	int (*load_signatures) (char *);
	int (*train) (char *);
	struct tct_result *(*classify_session) (void *session);
	int (*dump_statistics) (FILE *);
	Bool (*is_session_classifiable) (void *session);
	int (*session_sign) (void *session); 	//, void *packet);

	char *name;			/* string representing the name of the classification engine */
	char *version;			/* string representing the version of the engine */
	u_int32_t *flags;
};

struct tct_plugin {
	int num_classifiers;		/* the number of classifiers */
	int enabled_classifiers;	/* the number of enabled_classifiers */
	void **class_handle;		/* Dynamic array of classifiers handles */
	struct tct_classifier *classifiers;	/* Dynamic array of classifiers */
};

extern struct tct_plugin tct_plg;

/* routines in plugin.c */
int load_plugins();
int unload_plugins();
int load_signatures();
int train();
int session_sign(void *s);

#endif /* tct_plugin */

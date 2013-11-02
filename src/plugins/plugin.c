#include <dlfcn.h>	/* for dlopen and dlclose */
#include "plugin.h"

#define MAX_PLUGINS	9
#define PLUGIN_FILE	"config/enabled_plugins"

struct tct_plugin tct_plg;
/*
 * Parse enabled_plugins file
 * Return: 2 lists containing names and paths of effectively existing plugins
 * and the number of enabled plugins
 */
int enabled_plugins(char **namelist, char **pathlist)
{
	char row[255];		/* Buffer to store file rows */
	char path[255];
	FILE *fp;
	int n = 0;

	snprintf(path, 255, "%s/%s", tct_gb.path, PLUGIN_FILE);
	/* Open enabled_plugins file */
	if ((fp = fopen(path, "r")) == NULL) {
		err_sys("cann't open enabled_plugins file ");
	}

	/*Parse plugins list */
	while (fgets(row, 255, fp)) {
		char *name, *sptr = row;
		FILE *tfp;
		Bool skip = FALSE;

		/* Skip initial spaces */
		while (*sptr <= ' ') {
			if (*sptr != '\0') {
				sptr++;
			} else {
				skip = TRUE;
				break;
			}
		}

		/* Skip commented lines */
		if (*sptr == '#' || skip)
			continue;

		/* Get plug-in name */
		name = sptr;
		while (*sptr != ' ' && *sptr != '\0' && *sptr != '\n')
			sptr++;
		*sptr = '\0';

		/* Add plug-in name to namelist only if really exists */
		snprintf(path, 255, "%s/plugins/%s/class_%s.so",tct_gb.path,  name, name);
		if ((tfp = fopen(path, "r")) != NULL) {
			fclose(tfp);
			namelist[n] = malloc(strlen(name) + 1);
			pathlist[n] = malloc(strlen(path) + 1);
			strncpy(namelist[n], name, strlen(name));
			strncpy(pathlist[n], path, strlen(path));
			namelist[n][strlen(name)] = '\0';
			pathlist[n][strlen(path)] = '\0';
			n++;
		}
	}

	fclose(fp);
	return n;
}

int load_plugins()
{
	const char *error;
	char *namelist[MAX_PLUGINS];
	char *pathlist[MAX_PLUGINS];
	int i, n;

	/* Obtain the list of enabled plug-ins */
	n = enabled_plugins(namelist, pathlist);
	if (n > 0) {
		/*Allocate classifiers related dynamic arrays */
		tct_plg.classifiers = (struct tct_classifier *) calloc(n, sizeof(struct tct_classifier));
		tct_plg.class_handle = calloc(n, sizeof(void *));

		for (i = 0; i < n; i++) {
			int (*class_init) (struct tct_classifier *);	/* Classifiers initialization function pointer */

			/* Set classifier name */
			tct_plg.classifiers[i].name = (char *)malloc(strlen(namelist[i]+1));
			strncpy(tct_plg.classifiers[i].name, namelist[i], strlen(namelist[i])+1);
			
			/* Load classifier plug-in module */
			tct_plg.class_handle[i] = dlopen(pathlist[i], RTLD_LAZY);
			if (tct_plg.class_handle[i] == NULL) {
				err_msg("%s\n", dlerror());
				return 0;
			}
			dlerror();		/* Clear any existing error */

			/* Search class_init pointer and save it */
			class_init = dlsym(tct_plg.class_handle[i], "class_init");
			if ((error = dlerror()) != NULL) {
				err_msg("%s\n", error);
				return 0;
			}

			class_init(&tct_plg.classifiers[i]);	/* Initialize classifier */
			if (tct_plg.classifiers[i].enable()) {
				/* Enable classifier */
				printf("classifier Engine %s-%s initialized and enabled.\n", 
					tct_plg.classifiers[i].name, tct_plg.classifiers[i].version);
				tct_plg.enabled_classifiers++;
			} else {
				/* Disable classifier */
				printf("classifier Engine %s-%s initialized but disabled (some requisites not satisfied).\n", 
					tct_plg.classifiers[i].name, tct_plg.classifiers[i].version);
			}

			free(pathlist[i]);
			free(namelist[i]);
		}
	} else {
		err_msg("No classification engines found!\n");
	}
	return n;
}


/*
 * Unload plug-ins and free related dynamic memory
 */
int unload_plugins()
{
	int i;

	for (i = 0; i < tct_plg.num_classifiers; i++) {
		if (tct_plg.class_handle[i] != NULL) 
			/* disable classifier and free the memory that allocated */
			tct_plg.classifiers[i].disable();
			dlclose(tct_plg.class_handle[i]);
	}

	free(tct_plg.classifiers);
	free(tct_plg.class_handle);
	return 0;
}

int train() 
{
	int i;
	char path[256];

	for (i = 0; i < tct_plg.num_classifiers; i++) {
		if (strcmp(tct_opts.classifier_name, tct_plg.classifiers[i].name) == 0) {	
			if (TEST_BIT(*(tct_plg.classifiers[i].flags), CLASS_ENABLE, 1)) {
				printf("\n\nStarting %s-%s training...", tct_plg.classifiers[i].name, tct_plg.classifiers[i].version);
				sprintf(path, "config/%s.txt", tct_plg.classifiers[i].name);
				tct_plg.classifiers[i].train(path);
				printf("done\n");
			}
		}
	}

	return 0;
}

/*
 * Load classification signatures for each enabled plug-in
 */
int load_signatures()
{
	char error[MAXLINE];
	int i;

	for (i = 0; i < tct_plg.num_classifiers; i++) {
		error[0] = '\0';
		if (TEST_BIT(*(tct_plg.classifiers[i].flags),  CLASS_ENABLE, 1)) {
			printf("Loading %s-%s signatures...", tct_plg.classifiers[i].name, tct_plg.classifiers[i].version);
			if (tct_plg.classifiers[i].load_signatures(error) == 0) {
				printf("done\n");
			} else {
				printf("%s => plugin disabled\n", error);
				tct_plg.classifiers[i].disable();
				tct_plg.enabled_classifiers--;
			}
		}
	}
	printf("\n");
	return 0;
}

/*
 * Collects signatures for each enabled plug-in
 */
int session_sign(void *s)
{
	int i;

	for (i = 0; i < tct_plg.num_classifiers; i++) {
		if (TEST_BIT(*(tct_plg.classifiers[i].flags), CLASS_ENABLE, 1)) {
			
			tct_plg.classifiers[i].session_sign(s); 
		}
	}

	return 0;
}


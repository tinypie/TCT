#include "class.h"
#include "error.h"
#include "debug.h"

#define GROUP_FILE	"config/group.txt"
#define APPS_FILE	"config/apps.txt"

/* 
 * globle variables to store class information
 */
struct tct_group_class *tct_group;
int group_size;

struct tct_app_class *tct_app;
int app_size;

int load_group_def()
{
	FILE *fp;
	char line[MAXLINE];

	char *id, *name, *descr,  *p, *sptr = NULL;
	int i = 0;

	if ((fp=fopen(GROUP_FILE,"r")) == NULL) {
		err_msg("unable to open group.txt");
		return -1;
	}

	/* first pass--> find max group id */
	while (fgets(line, MAXLINE, fp) != NULL) {
		/* skip comment line  and  blank line */
		if (line[0] == '#' || line[0] == '\n')
			continue;
		p = line;
		/* skip space */
		while (*p == ' ' || *p == '\t')
			p++;

		if (isdigit(*p) == 0) {
			err_quit("config/group.txt format error");
		}

		id = strtok_r(p, "\t", &sptr);
		if ( atoi(id) != i) {
			err_quit("check id field in group.txt");
		}

		i++;
	}
	group_size = i;

	tct_group=(struct tct_group_class *)malloc(group_size * sizeof(struct tct_group_class));
	if (tct_group == NULL) 
		err_sys("malloc for struct group_class error");

	/* second pass --> fill the struct */
	rewind(fp);
	i = 0;
	while (fgets(line, MAXLINE, fp) != NULL) {
		/* skip comment line and blank line*/
		if (line[0] == '#'|| line[0] == '\n')
			continue;

		p = line;
		/* skip space */
		while (*p == ' ' || *p == '\t')
			p++;

		if (isdigit(*p) == 0) {
			err_quit("config/group.txt format error");
		}

		id = strtok_r(p, "\t", &sptr);
		tct_group[i].group_id = atoi(id);

		name = strtok_r(NULL, "\t", &sptr);
		tct_group[i].group_name = strdup(name);

		descr = strtok_r(NULL, "\t", &sptr);
		tct_group[i].description = strdup(descr);

		i++;
	}

	fclose(fp);
	return 0;
}


/* 
 * load class definitions 
 * 3 levels.
 * first --> group --> 15
 * second--> app  --> 99
 * third --> sub app --> 141
 */
int load_class_def()
{
	FILE *fp;
	char line[MAXLINE];
	int i, j;
	char *appid, *subid, *gid, *label, *sub_label, *descr, *tmp;
	char *ptr = NULL;
	char save_appid[4];
	int flag = 0, index;

	/* load the group class information */
	if (load_group_def() < 0) {
		return -1;
	}

	/* open apps.txt */
	if ((fp=fopen(APPS_FILE, "r")) == NULL) {
		err_sys("count open config/apps.txt");
	}


	/* first past --> find the number of  apps and app_count */
	while (fgets(line, MAXLINE, fp) != NULL) {
		/* skip comment line */
		if (line[0] == '#' || line[0] == '\n')
			continue;

		tmp = line;
		/* skip space */
		while (*tmp == ' ' || *tmp == '\t')
			tmp++;

		if (isdigit(*tmp) == 0) {
			err_quit("config/app.txt format error");
		}
		
		appid = strtok_r(tmp, "\t", &ptr);
		i = atoi(appid);
		if (app_size < i) 
			app_size = i;
	}
	app_size++;		/* since array is from 0 */

	tct_app = (struct tct_app_class *) calloc(app_size, sizeof(struct tct_app_class));
	if (tct_app == NULL) {
		err_sys("calloc for struct app class error");
	}

	/*
	 * second pass --> fill  the array app 
	 */
	rewind(fp);
	flag = 0;
	while (fgets(line, MAXLINE, fp) != NULL) {
		/* skip comment line  and blank line */
		if (line[0] == '#' || line[0] == '\n')
			continue;

		tmp = line;
		/* skip space */
		while (*tmp == ' ' || *tmp == '\t')
			tmp++;

		appid = strtok_r(tmp, "\t", &ptr);
		subid = strtok_r(NULL, "\t", &ptr);
		gid = strtok_r(NULL, "\t", &ptr);
		label = strtok_r(NULL, "\t", &ptr);
		sub_label = strtok_r(NULL, "\t", &ptr);
		descr = strtok_r(NULL, "\t", &ptr);
		index = atoi(subid);

		if (flag == 0) {
			strncpy(save_appid, appid, 4);
			i = atoi(appid);
			tct_app[i].app_id = i;
			tct_app[i].group_id = atoi(gid);
			tct_app[i].app_name = strdup(label);
			tct_app[i].description = strdup(descr);
			tct_app[i].sub_count = index;
			flag =1;
		}

		/* find how many appids that have the same gid */
		if (strncmp(save_appid, appid, 4) != 0) {
			strncpy(save_appid, appid, 4);
			i = atoi(appid);
			tct_app[i].app_id = i;
			tct_app[i].group_id = atoi(gid);
			tct_app[i].app_name = strdup(label);
			tct_app[i].description = strdup(descr);
			tct_app[i].sub_count = index;
		} else {
			if (tct_app[i].sub_count < index)
				tct_app[i].sub_count = index;
		}

	}

	/* allocate sub array */
	for (i = 0; i < app_size; i++) {
		if (tct_app[i].sub_count > 0) {
			tct_app[i].sub = (struct tct_sub_class *) 
				malloc((tct_app[i].sub_count+1) * sizeof(struct tct_sub_class));
		}
	}

	/* 3rd pass fill the sub array */

	rewind(fp);
	while (fgets(line, MAXLINE, fp) != NULL) {
		/* skip comment line  and blank line */
		if (line[0] == '#' || line[0] == '\n')
			continue;

		tmp = line;
		/* skip space */
		while (*tmp == ' ' || *tmp == '\t')
			tmp++;

		appid = strtok_r(tmp, "\t", &ptr);
		subid = strtok_r(NULL, "\t", &ptr);
		gid = strtok_r(NULL, "\t", &ptr);
		label = strtok_r(NULL, "\t", &ptr);
		sub_label = strtok_r(NULL, "\t", &ptr);
		descr = strtok_r(NULL, "\t", &ptr);

		i = atoi(appid);
		j = atoi(subid);

		if (tct_app[i].sub_count > 0) {
			tct_app[i].sub[j].sub_id = j;
			tct_app[i].sub[j].sub_name = strdup(sub_label);
			tct_app[i].sub[j].description = strdup(descr);
		}
	}


#if DEBUG > 4
	printf("\napp_size:%d\t group_size:%d\n", app_size, group_size);
	print_class();
#endif
	fclose(fp);
	return 0;
}

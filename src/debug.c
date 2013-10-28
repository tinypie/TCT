#include "class.h"

/* print the app,sub,group array */
void print_class()
{
	int i, j;
	printf("\n group class infomation\n");
	printf("#groupid\t#name\n");		
	for (i = 0; i < group_size; i++) {
		printf("%d\t\t%s\n", tct_group[i].group_id, tct_group[i].group_name);
	}

	printf("\n app class infomation\n");
	printf("#appid\t #groupid\t #appname\n");
	for (i = 0; i < app_size; i++) {
		printf("%d\t%d\t\t%s\n", 
			tct_app[i].app_id, tct_app[i].group_id, tct_app[i].app_name);
		if (tct_app[i].sub_count > 0) {
			printf("\t#appid\t #subid\t #subname\n");
			for (j = 0; j <= tct_app[i].sub_count; j++) {
				printf("\t%d\t%d\t%s\n", 
					tct_app[i].app_id, tct_app[i].sub[j].sub_id, tct_app[i].sub[j].sub_name);
			}
		}
	}
}

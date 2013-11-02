#include "tct.h"

struct hash_table *tct_ground[PRE_SIZE];

int get_address(struct ipaddr *addr, char *p) 
{
	if (strlen(p) > 15) {	/* an ipv6 address */
		inet_pton(AF_INET6, p, &(addr->un.ipv6));
		addr->version = 6;
	}
	else {
		inet_pton(AF_INET, p, &(addr->un.ipv4));
		addr->version = 4;
	}

	return 0;
}


int get_time(struct timeval *time, const char *p)
{
	char buffer[64];
	char *tmp;

	if (strchr(p, '.') == NULL) {
		err_quit("ground truth time format error");
	}

	strncpy(buffer, p, 64);
	tmp = strchr(buffer, '.');
	*tmp++ = '\0';
	time->tv_sec = atol(buffer);
	time->tv_usec = atol(tmp);

	return 0;
}

int get_id(const char *p)
{
	int i;

	for (i = 0; i < app_size; i++) {
		if (tct_app[i].app_name != NULL) {
			if (strcmp(p, tct_app[i].app_name) == 0) {
				return i;
			}
		}
	}
	if (i >= app_size) {
		err_quit("get id error:%s", p);
	}
	return 0;
}


static int hash_cmp(const struct five_tuple *key1, const struct five_tuple *key2)
{
	if (key1->a_port == key2->a_port && key1->b_port == key2->b_port) {
		if (key1->a_addr.version == key2->a_addr.version) {
			if (key1->a_addr.version == 4) {
				if(memcmp(&(key1->a_addr.un.ipv4), &(key2->a_addr.un.ipv4), sizeof(struct in_addr)) == 0) {
					if(memcmp(&(key1->b_addr.un.ipv4), &(key2->b_addr.un.ipv4), sizeof(struct in_addr)) == 0) {
						return 1;
					}
				} else {
					return 0;
				}
			} else {	/* ipv6 */
				if(memcmp(&(key1->a_addr.un.ipv6), &(key2->a_addr.un.ipv6), sizeof(struct in6_addr)) == 0) {
					if(memcmp(&(key1->b_addr.un.ipv6), &(key2->b_addr.un.ipv6), sizeof(struct in6_addr)) == 0) {
						return 1;
					}
				} else {
					return 0;
				}
			}
		} else {
			return 0;
		}
	} else {
		return 0;
	}
	return 0;
}

int add_hash_entry(struct class_info *truth)
{
	unsigned long n;
	int i;
	struct hash_table *ptr, *table;

	/* calculate the key */
	n = truth->addr.a_port + truth->addr.b_port;
	if (truth->addr.a_addr.version == 4) {
		n += truth->addr.a_addr.un.ipv4.s_addr + truth->addr.b_addr.un.ipv4.s_addr;
	} else if (truth->addr.a_addr.version == 6) {
		for (i = 0; i< 16; i++) {	
			n += truth->addr.a_addr.un.ipv6.s6_addr[i];
			n += truth->addr.b_addr.un.ipv6.s6_addr[i];
		}
	}
	n = n % PRE_SIZE;
	
	if (tct_ground[n] == NULL) {	/* first item */
		table=(struct hash_table *)malloc(sizeof(struct hash_table));
		if(table == NULL) {
			err_sys("malloc for hash_table error");
		}
		table->next = NULL;
		table->entry = truth;
		tct_ground[n] = table;
	} else {
		ptr = tct_ground[n];
		while(ptr != NULL) {
			if (hash_cmp(&(ptr->entry->addr), &(truth->addr)) == 1) {
			//if (memcmp(&(ptr->entry->addr), &(truth->addr), sizeof(struct five_tuple)) == 0) {
				truth->next = ptr->entry;
				ptr->entry = truth;
				break;
			}
			ptr = ptr->next;
		}

		if (ptr == NULL) {	/* there is no duplicated */
			table=(struct hash_table *)malloc(sizeof(struct hash_table));
			if(table == NULL) 
				err_sys("malloc for hash_table error");

			table->entry = truth;
			/* insert to the head */
			table->next = tct_ground[n];
			tct_ground[n] = table;
			return 0;
		}
	}

	return 0;
}

/* 
 * load ground truth file. The file should have the session type in comment.
 * We will check that, if it's voilated, then refuse to work.
 *
 */
int load_ground_truth()
{
	FILE *fp;
	char buffer[MAXLINE];
	char *p, *sptr = NULL;
	int type = 0;
	struct class_info *entry;

	/* open the ground truth file */
	if ((fp=fopen(tct_opts.ground_truth, "r")) == NULL) {
		err_sys("open file ground truth error");
	}

	while (fgets(buffer, MAXLINE, fp) != NULL) {
		/* skip blank line */
		if (buffer[0] == '\n') 
			continue;

		/* the sesion type is in the comment line */
		if (buffer[0] == '#') {
			if (strstr(buffer, "session type") != NULL) {
				if ((p=strstr(buffer, "flow")) != NULL) {	/* flow and biflow */
					if (*(p-1) == 'i' && *(p-2) == 'b') {	/* biflow */
						type = SESSION_TYPE_BFLOW;
					} else {
						type = SESSION_TYPE_FLOW;
					}
				} else {
					type = SESSION_TYPE_PKT;
				}

				if (type != tct_opts.work_mode) {
					fclose(fp);
					err_quit("ground truth has incorrect session type");
				}
			}
			continue;
		}

		entry = (struct class_info *) malloc(sizeof(struct class_info));

		entry->next = NULL;

		/* get src ip */
		p = strtok_r(buffer, "\t", &sptr);
		get_address(&(entry->addr.a_addr), p);

		/* get src port */
		p = strtok_r(NULL, "\t", &sptr);
		entry->addr.a_port = htons(atoi(p));

		/* get dst ip */
		p = strtok_r(NULL, "\t", &sptr);
		get_address((&entry->addr.b_addr), p);

		/* get dst port */
		p = strtok_r(NULL, "\t", &sptr);
		entry->addr.b_port = htons(atoi(p));

		/* get protocal */
		p = strtok_r(NULL, "\t", &sptr);
		entry->addr.l4proto = atoi(p);

		/* get timestamp (start time) */
		p = strtok_r(NULL, "\t", &sptr);
		get_time(&entry->time, p);
#if 0
		/* skip endtime and total pkts  and root app*/
		for (i = 0; i < 3; i++) {
			strtok_r(NULL, "\t", &sptr);
		}
#endif

		p = strtok_r(NULL, "\t", &sptr);
		char *tmp;
		if ((tmp = strchr(p, '\n')) != NULL)
			*tmp = '\0';

#if 0
		strcpy(entry->name, p);
#endif

		entry->app_id = get_id(p);

		add_hash_entry(entry);
	}

	fclose(fp);
	return 0;
}

/* 
 * find the class type of the traffic (identified by a 5 tuple)
 */
struct class_info *find_ground_truth(struct five_tuple key, struct timeval start_time)
{
	unsigned long n;
	int i;
	struct hash_table *prev, *table;
	struct class_info *pclass;

	/* calculate the key */
	n = key.a_port + key.b_port;
	if (key.a_addr.version == 4) {
		n += key.a_addr.un.ipv4.s_addr + key.b_addr.un.ipv4.s_addr;
	} else if (key.a_addr.version == 6) {
		for (i = 0; i< 16; i++) {	
			n += key.a_addr.un.ipv6.s6_addr[i];
			n += key.b_addr.un.ipv6.s6_addr[i];
		}
	}
	n = n % PRE_SIZE;
	
	table = tct_ground[n];
	if (table == NULL) {
		return NULL;
	} else {
		while (table != NULL) {
			prev = table;
			if (hash_cmp(&(table->entry->addr), &key) == 1) {
				pclass = table->entry;
				i = 0;
				while (pclass != NULL) {
					if (pclass->time.tv_sec == start_time.tv_sec) {
						break;
					}
					pclass = pclass->next;
					i++;
				}
				if (pclass == NULL) {
					return table->entry;
	#if 0
					printf("sport:%d, dport:%d, time:%lu.%06lu\n", 
						ntohs(key.a_port), ntohs(key.b_port), start_time.tv_sec, start_time.tv_usec);
					err_msg("panic, ground truth time stamp wrong");
					if (i <= 20)
					//if (i == 1)
						return table->entry;
					else {	
						err_msg("return NULL\n");
						return NULL;
					}
	#endif 
				} 
	#if 0		// to do some kind of optimization 	
				else {
					/* move entry to header */
					if (prev != table) {
						prev->next = table->next;
						table->next = tct_ground[n];
						tct_ground[n] = table;
					}
				}
	#endif
				return pclass;
			}
			table = table->next;
		}
	}
	return NULL;			
}

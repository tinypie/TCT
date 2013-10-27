#include "tct.h"
#define MM_FREE_SIZE 400

/* pointer to the top of the "bflow_entry" free list */
struct bflow_entry *top_bflow_flist = NULL;
struct double_list_free *last_conn_flist = NULL;
struct double_list_free *top_conn_flist = NULL;

struct memory_manage tct_mm;

/* garbage collector for the segment list */
static struct segment *segment_flist = NULL;	/* Pointer to the top of the 'segment' free list.  */
struct segment *segment_alloc(void)
{
	struct segment *pseg;

	tct_mm.num_segment_use++;
	if (segment_flist == NULL) {
		pseg = (struct segment *) calloc(1, sizeof (struct segment));
		if (pseg == NULL) {
			err_sys("calloc for pseg error");
		}
	} else {
		tct_mm.num_segment--;
		pseg = segment_flist;
		segment_flist = segment_flist->next;
	}
	return pseg;
}

void segment_release(struct segment * rel_segment)
{
	tct_mm.num_segment++;
	tct_mm.num_segment_use--;

	memset(rel_segment, 0, sizeof (struct segment));
	rel_segment->next = segment_flist;
	segment_flist = rel_segment;
}

/* 
 * garbage collector for the Quadrant 
 * Pointer to the top of the 'quadrant' free list.
 */
static struct quadrant *quadrant_flist = NULL;	

struct quadrant *quadrant_alloc(void)
{
	struct quadrant *pquad;

	tct_mm.num_quadrant_use++;
	if (quadrant_flist == NULL) {
		pquad = (struct quadrant *) calloc(1, sizeof (struct quadrant));
		if (pquad == NULL) {
			err_sys("calloc for pquad error");
		}
	} else {
		tct_mm.num_quadrant--;
		pquad = quadrant_flist;
		quadrant_flist = quadrant_flist->next;
	}
	return pquad;
}

void quadrant_release(struct quadrant * rel_quadrant)
{
	tct_mm.num_quadrant_use--;
	tct_mm.num_quadrant++;

	memset(rel_quadrant, 0, sizeof (struct quadrant));
	rel_quadrant->next = quadrant_flist;
	quadrant_flist = rel_quadrant;
}

void free_quad(struct quadrant ** ppquad)
{
	struct segment *pseg;
	struct segment *pseg_next;

	pseg = (*ppquad)->seglist_head;
	while (pseg && pseg->next) {
		pseg_next = pseg->next;
		segment_release(pseg);
		pseg = pseg_next;
	}
	if (pseg)
		segment_release(pseg);

	(*ppquad)->no_of_segments = 0;
	quadrant_release(*ppquad);
	*ppquad = NULL;
}

struct bflow_entry *new_bflow()
{
	struct bflow_entry *p;

	tct_mm.num_bflow_use++;
	if(top_bflow_flist == NULL) {
		p = (struct bflow_entry *) calloc(1, sizeof(struct bflow_entry));
	} else {
		p = top_bflow_flist;
		top_bflow_flist = top_bflow_flist->next;
/*
 * here is a bug if without the next line. This bug caused me a half day to find it.
 * If without the next line, the buffer poor with be all linked to the bflow_hashtable[n],
 * then produced a linked list with a ring in bflow_dump_data(). 
 * finally the programm with stack into a infinite loop. so sad :(
 */
		p->next = NULL;

		tct_mm.num_bflow--;
	}

	return p;
}

struct connection *new_conn()
{
	struct connection *ptr;

	tct_mm.num_conn_use++;

	if ((last_conn_flist == NULL) || (last_conn_flist->ete == NULL)) {	/* The LinkList stack is empty. */
		ptr = (struct connection *) calloc(1, sizeof (struct connection));
		if (ptr == NULL)
			err_sys("calloc for struct connection error");

		return ptr;
	} else {		/* The 'tplist' stack is not empty.   */
		ptr = last_conn_flist->ete;
		last_conn_flist->ete = NULL;
		if (last_conn_flist->next != NULL)
			last_conn_flist = last_conn_flist->next;
		tct_mm.num_conn--;
		return ptr;
	}
}

/* Allocate and initialize a biflow */
struct connection *init_bflow(struct connection *prev)
{
	struct connection *ptr;

	/* create a new TCP pair record and remember where you put it */
	ptr =  new_conn();

	ptr->s2c.closed = FALSE;
	ptr->c2s.closed = FALSE;

	ptr->c2s.parent = ptr;
	ptr->s2c.parent = ptr;

	if (ptr != NULL) {
		ptr->prev = prev;
	}
	return ptr;
}

void free_conn(struct connection *conn)
{
	int i;
	struct double_list_free* new_dlf; 
	
	tct_mm.num_conn_use--;
	tct_mm.num_conn++;

	/* free each quad then for each segment in each quad (for rexmit.c stolen from tcptrace)*/
	for (i = 0; i < 4; i++) {
		if (conn->c2s.ss.pquad[i] != NULL) {
			free_quad(&(conn->c2s.ss.pquad[i]));
		}
	}
	for (i = 0; i < 4; i++) {
		if (conn->s2c.ss.pquad[i] != NULL) {
			free_quad(&(conn->s2c.ss.pquad[i]));
		}
	}

	if (conn->payload != NULL)
		free(conn->payload);

	memset(conn, 0, sizeof(struct connection));

	/* put them to the double list to manage memory */
	if ((last_conn_flist == NULL)
	    || ((last_conn_flist->ete != NULL) && (last_conn_flist->prev == NULL))) {

		new_dlf = (struct double_list_free *) malloc(sizeof (struct double_list_free));
		new_dlf->ete = conn;
		new_dlf->prev = NULL;
		new_dlf->next = top_conn_flist;
		if (new_dlf->next != NULL)
			new_dlf->next->prev = new_dlf;
		top_conn_flist = new_dlf;
		last_conn_flist = new_dlf;
	} else {
		if (last_conn_flist->ete == NULL)
			new_dlf = last_conn_flist;
		else
			new_dlf = last_conn_flist->prev;
		new_dlf->ete = conn;
		last_conn_flist = new_dlf;
	}
}


/* needed */
void free_bflow(struct bflow_entry *bflow)
{
	unsigned long n;
	int i;
	struct bflow_entry *p;
	struct bflow_entry *pre, **head;
	struct five_tuple key;
	struct connection *conn;

	/* 
	 * if ete has a pre item then just free ete 
	 * else free both bflow(struct bflow_entry) and ete(struct connection)
	 */
	if (bflow->ete->prev == NULL) {
		/* take it down from bflow_hashtable */
	 	key = bflow->key1;
		n = key.a_port + key.b_port + bflow->ete->addr_pair.l4proto;	
		if (key.a_addr.version == 4) {
			n += key.a_addr.un.ipv4.s_addr + key.b_addr.un.ipv4.s_addr;
		} else if (key.a_addr.version == 6) {
			for (i = 0; i< 16; i++) {	
				n += key.a_addr.un.ipv6.s6_addr[i];
				n += key.b_addr.un.ipv6.s6_addr[i];
			}
		}
		n = n % HASH_TABLE_SIZE;
		
		p = bflow_hashtable[n];
		head = &bflow_hashtable[n];
		while (p) {
			pre = p;
#if 0
			if (memcmp(&(p->key1), &(bflow->key1), sizeof(struct ipaddr)) == 0) { 
			/* move to the head of the access list */
				if (p != *head) {
					pre->next = p->next;
				} else {
					*head = NULL;
				}
				break;
			}
#endif
			if (p == bflow) {
				if (p == *head) 
					*head = p->next;
				else
					pre->next = p->next;

				break;
			}

			p = p->next;
		}

		/* fee the struct connection that it points */
		if (bflow->ete != NULL)
			free_conn(bflow->ete);

		memset(bflow, 0, sizeof(struct bflow_entry));
		bflow->next = top_bflow_flist;
		top_bflow_flist = bflow;
		tct_mm.num_bflow++;
		tct_mm.num_bflow_use--;

	} else {
		conn = bflow->ete;
		bflow->ete = conn->prev;

		free_conn(conn);
	}
		
}

/* free the memory allocated for group, app and sub */
void free_class()
{
	int i, j;
	if (tct_group != NULL) {
		for (i = 0; i < group_size; i++) {
			if (tct_group[i].description != NULL)
				free(tct_group[i].description);
			if (tct_group[i].group_name != NULL);
				free(tct_group[i].group_name);
		}
		free(tct_group);
	}
		
	if (tct_app != NULL) {
		for (i = 0; i < app_size; i++) {
			if (tct_app[i].app_name != NULL)
				free(tct_app[i].app_name);
			if (tct_app[i].description != NULL)
				free(tct_app[i].description);
			if (tct_app[i].sub_count > 0) {
				for (j = 0; j <= tct_app[i].sub_count; j++) {
					if (tct_app[i].sub[j].sub_name != NULL) 
						free(tct_app[i].sub[j].sub_name);
					if (tct_app[i].sub[j].description != NULL)
						free(tct_app[i].sub[j].description);
				}
				free(tct_app[i].sub);
			}
		}
		free(tct_app);
	}
}

/* free the ground truth hash */
static void free_ground()
{
	int i;
	struct hash_table *pht;
	struct class_info *pci;

	for (i = 0; i < PRE_SIZE; i++) {
		if (tct_ground[i] != NULL) {
			pht = tct_ground[i];
			while(pht != NULL) {
				
				pci = pht->entry;
				while(pci != NULL) {
					struct class_info *tmp;
					tmp = pci->next;
					free(pci);
					pci = tmp;
				}

				struct hash_table *p = pht->next;
				free(pht);
				pht = p;
			}
		}
	}
}

/* free other static variables that allocted through malloc or rellac */
void free_others()
{
	/* free the memory of tct_opts */
	if (tct_opts.ground_truth != NULL)
		free(tct_opts.ground_truth);
	if (tct_opts.dump_file != NULL)
		free(tct_opts.dump_file);
	if (tct_opts.output_file != NULL)
		free(tct_opts.output_file);
	if (tct_opts.classifier_name != NULL)
		free(tct_opts.classifier_name);
	if (tct_opts.filter_file != NULL)
		free(tct_opts.filter_file);

	/* free tct_gb */
	if (tct_gb.phys != NULL) 
		free(tct_gb.phys);
	
	/* free the ground truth table if it exists */
	if (tct_opts.ground == 1) {
		free_ground();
	}
}

void hash_pool()
{
	int i;
	struct bflow_entry *entry, *btmp;
	struct flow_entry *fentry, *ftmp;
	struct connection *sb, *ctmp;
	struct double_list_free  *dtmp;
	struct quadrant *qtmp;
	struct segment *stmp;

	/*
	 * free the memory that has been used.
	 * items in  hash table 
	 */
	for (i = 0; i < HASH_TABLE_SIZE; i++) {
		/* bflow */
		entry = bflow_hashtable[i];
		while(entry != NULL) {
			btmp = entry;
			entry = entry->next;

			sb = btmp->ete;
			while (sb != NULL) {
				ctmp = sb;
				sb = sb->prev;
				if (TEST_BIT(ctmp->flags, SESS_EXPIRED, 1)) {
					make_tcp_conn(btmp, 1);
				}
				btmp->ete = sb;
				free(ctmp);
			}
			free(btmp);
		}
		bflow_hashtable[i] = NULL;

		/* free flow_hashtable[i] if it exits */
		fentry = flow_hashtable[i];
		while (fentry != NULL) {
			ftmp = fentry;
			fentry = fentry->next;

			sb = ftmp->ete;
			while (sb != NULL) {
				ctmp = sb;
				sb = sb->prev;
				if (TEST_BIT(ctmp->flags, SESS_EXPIRED, 1)) {
					make_tcp_conn(btmp, 1);
				}
				btmp->ete = sb;
				free(ctmp);
			}
			free(ftmp);
		}
		flow_hashtable[i] = NULL;

	}

	/* 
	 * free the memory that in the memory pool 
	 * There are 4 lists as follows 
	 * 	1) top_bflow_flist
	 * 	2) last_conn_flist and top_conn_flist
	 * 	3) quadrant_flist
	 * 	4) segment_flist
	 */
	 /* free top_bflow list */
	while (top_bflow_flist != NULL) {
		btmp = top_bflow_flist;
		top_bflow_flist = top_bflow_flist->next;
		free(btmp);
	}

	/* free last_conn_flist and itself */
	while(last_conn_flist != NULL) {
		ctmp = last_conn_flist->ete;
		if (ctmp != NULL)
			free(ctmp);
		last_conn_flist = last_conn_flist->next;
	}
	while(top_conn_flist != NULL) {
		dtmp = top_conn_flist;
		top_conn_flist = top_conn_flist->next;
		free(dtmp);
	}
	
	/* free  quadrant flist */
	while (quadrant_flist != NULL) {
		qtmp = quadrant_flist;
		quadrant_flist = quadrant_flist->next;
		free(qtmp);
	}
	
	/* free segment_flist */
	while (segment_flist != NULL) {
		stmp = segment_flist;
		segment_flist = segment_flist->next;
		free(stmp);
	}

}

void bflow_dump_data()
{
	int i;
	struct bflow_entry **head, *entry, *prev, *tmp;

#if 1
	struct connection *sb, *next;
	
	for (i = 0; i < HASH_TABLE_SIZE; i++) {
		entry = bflow_hashtable[i];
		head = &bflow_hashtable[i];

		while (entry != NULL) {
			prev = entry;
			sb = entry->ete;
			while(sb != NULL) {
				next = sb;
				sb = sb->prev;
			#if 0
				if (!TEST_BIT(next->flags, (SESS_EXPIRED | SESS_RESET | SESS_CLOSED | SESS_SKIP), 0)) {
					if (TEST_BIT(next->flags, SESS_EXPIRED, 1) &&
						tct_tm.current_time.tv_sec - next->last_time.tv_sec > SESSION_TIMEOUT) {
						make_tcp_conn(entry, 0);

						free_conn(next);
						entry->ete = sb;
					}
				}
			#endif
				/*
				 * if it's SESS_CLOSED or SESS_RESET, it has already called make_tcp_conn.
				 * Then we just free the struct ete memory.
				 * If it's SESS_EXPIED, we call the make_tcp_conn function and free the memory
				 */
				if (!TEST_BIT(next->flags, (SESS_CLOSED | SESS_RESET), 0)) {
					free_conn(next);
					entry->ete = sb;
				} 
			
		#if 0
				else if (TEST_BIT(next->flags, SESS_EXPIRED, 1)) {
					make_tcp_conn(entry,0);
					free_conn(next);
					entry->ete = sb;
				}
		#endif
	
			}

			/* then we free the memory of entry */
			if (entry->ete == NULL) {
				/* if it is the first item of the list */
				if (*head == entry) {
					*head = entry->next;
					//*head = NULL;
					memset(entry, 0, sizeof(struct bflow_entry));
					entry->next = top_bflow_flist;
					top_bflow_flist = entry;
					tct_mm.num_bflow++;
					tct_mm.num_bflow_use--;

					entry = *head;
					continue;
				} else {
					tmp = entry;
					prev->next = entry->next;
					entry = prev;

					memset(tmp, 0, sizeof(struct bflow_entry));
					tmp->next = top_bflow_flist;
					top_bflow_flist = tmp;
					tct_mm.num_bflow++;
					tct_mm.num_bflow_use--;
				}
			}

			entry = entry->next;
		}
	}

#endif

	struct quadrant *qtmp;
	struct segment *stmp;

	/* free some memory blocks if it is too large */
	if (tct_mm.num_bflow > MM_FREE_SIZE) {
		/* free half */
		for (i = 0; i < tct_mm.num_bflow/2; i++) {
			tmp = top_bflow_flist;
			top_bflow_flist = tmp->next;
			if (tmp != NULL)
				free(tmp);
			else 
				err_quit("mm free top_bflow_flist panic");
		}

		tct_mm.num_bflow -= tct_mm.num_bflow / 2;
	}

	if (tct_mm.num_conn > MM_FREE_SIZE) {
		for (i = 0; i < tct_mm.num_conn/2; i++) {
			if (last_conn_flist->ete != NULL) {
				free(last_conn_flist->ete);
				last_conn_flist->ete = NULL;
				last_conn_flist = last_conn_flist->next;
			} else {
				err_quit("mm free last_conn_flist panic");
			}

		}
	}
	if (tct_mm.num_quadrant > MM_FREE_SIZE) {
		/* free half */
		for (i = 0; i < tct_mm.num_quadrant/2; i++) {
			qtmp = quadrant_flist;
			quadrant_flist = quadrant_flist->next;
			if (qtmp != NULL)
				free(qtmp);
			else 
				err_quit("mm free quadrant flist panic");
		}

		tct_mm.num_quadrant -= tct_mm.num_quadrant / 2;
	}

	if (tct_mm.num_segment > MM_FREE_SIZE) {
		/* free half */
		for (i = 0; i < tct_mm.num_segment/2; i++) {
			stmp = segment_flist;
			segment_flist = stmp->next;
			if (stmp != NULL)
				free(stmp);
			else 
				err_quit("mm free segment_flist panic");
		}

		tct_mm.num_segment -= tct_mm.num_segment / 2;
	}

}

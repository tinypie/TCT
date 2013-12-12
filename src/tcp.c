#include "tct.h"
#include "plugins/plugin.h"

/* local routines */
static u_short get_short_opt(void *ptr);
static u_long get_long_opt(void *ptr);
static struct tcp_options *parse_options(struct tcphdr *ptcp, void *plast);

static int extract_bflow_features(
			struct connection *sb,
			struct end_to_end *thisdir, 
			struct end_to_end *otherdir, 
			struct ip *pip, 
			struct tcphdr *ptcp,
			void *plast)
{
	struct tcp_options *ptcpo;
	Bool retrans;
	int retrans_num_bytes;
	Bool out_order;

	u_short sport;		/* source port */
	u_short dport;		/* destination port */
	uint32_t seq;		/* sequence number */
	uint32_t ack;		/* acknowledgement number */
	u_short win;		/* window */
	u_long eff_win;		/* window after scaling */
	short ip_len;		/* total length */
	u_long start, end;
	double iat;

	int tcp_len;
	int tcp_data_len;

	/* convert interesting fields to local byte order */
	seq = ntohl(ptcp->seq);
	ack = ntohl(ptcp->ack_seq);
	sport = ntohs(ptcp->source);
	dport = ntohs(ptcp->dest);
	win = ntohs(ptcp->window);

	ip_len = gethdr_length(pip, plast) + get_payload_length(pip, plast);

	if ((ptcp->ack) && (otherdir->fin_count >= 1) && (ack >= (otherdir->fin_seqno + 1))) {
		/* this is the ACK to the FIN */
		otherdir->closed = 1;
	}

	/* compute the "effective window", which is the advertised window */
	/* with scaling */
	if (ptcp->ack || ptcp->syn) {
		eff_win = (u_long) win;

		/* N.B., the window_scale stored for the connection DURING 3way */
		/* handshaking is the REQUESTED scale.  It's only valid if both */
		/* sides request scaling.  AFTER we've seen both SYNs, that field */
		/* is reset (above) to contain zero.  Note that if we */
		/* DIDN'T see the SYNs, the windows will be off. */
		if (thisdir->f1323_ws && otherdir->f1323_ws)
			eff_win <<= thisdir->window_scale;
	} else {
		eff_win = 0;
	}

	/* calculate data length */
	tcp_len = get_payload_length(pip, plast);
	tcp_data_len = tcp_len - (4 * ptcp->doff);

	/* calc. data range */
	start = seq;
	end = start + tcp_data_len;

	/* record sequence limits */
	if (ptcp->syn) {
		/* error checking - better not change! */
		if ((thisdir->syn_count > 1) && (thisdir->syn != start)) {
#if DEBUG > 3
			/* it changed, that shouldn't happen! may be syn flood ): */
			err_msg("\nrexmitted SYN had diff. seqnum! (was %lu, now %lu, etime: %d sec)\n",
					thisdir->syn, start,
					(int) (elapsed(sb->first_time,tct_tm.current_time) / 1000000));
#endif
			thisdir->bad_behavior = TRUE;
		}
		thisdir->syn = start;
		otherdir->ack = start;
	}
	if (ptcp->fin) {
		/* bug fix, if there's data here too, we need to bump up the FIN */
		/* (psc data file shows example) */
		u_long fin = start + tcp_data_len;
		/* error checking - better not change! */
		if ((thisdir->fin_count > 1) && (thisdir->fin != fin)) {
#if DEBUG > 3
			/* it changed, that shouldn't happen! */
			err_msg("rexmitted FIN had diff. seqnum! (was %lu, now %lu, etime: %d sec)\n",
				thisdir->fin, fin, (int) (elapsed(sb->first_time, tct_tm.current_time) / 1000000));
#endif
			thisdir->bad_behavior = TRUE;
		}
		thisdir->fin = fin;
	}

	/* check the options */
	ptcpo = parse_options(ptcp, plast);
	if (ptcpo->mss != -1)
		thisdir->mss = ptcpo->mss;
	if (ptcpo->ws != -1) {
		thisdir->window_scale = ptcpo->ws;
		thisdir->f1323_ws = TRUE;
	}
	if (ptcpo->tsval != -1) {
		thisdir->f1323_ts = TRUE;
	}

	/* NOW, unless BOTH sides asked for window scaling in their SYN     */
	/* segments, we aren't using window scaling */
	if ((!ptcp->syn) && ((!thisdir->f1323_ws) || (!otherdir->f1323_ws))) {
		thisdir->window_scale = otherdir->window_scale = 0;
	}

	/* check sacks */
	if (ptcpo->sack_req) {
		thisdir->fsack_req = 1;
	}
	if (ptcpo->sack_count > 0) {
		++thisdir->sacks_sent;
	}

	/* do data stats */
	if (tcp_data_len > 0) {
		thisdir->data_pkts += 1;
		if (ptcp->psh)
			thisdir->data_pkts_push += 1;
		thisdir->data_bytes += tcp_data_len;
		if (tcp_data_len > thisdir->max_seg_size)
			thisdir->max_seg_size = tcp_data_len;
		if ((thisdir->min_seg_size == 0) ||
		    (tcp_data_len < thisdir->min_seg_size))
			thisdir->min_seg_size = tcp_data_len;

		thisdir->seg_size_sum += tcp_data_len;
		thisdir->seg_size_sum2 += tcp_data_len * tcp_data_len;

		/* check if this segment is carrying the first data */
		if (ZERO_TIME(&thisdir->payload_start_time)) {
			thisdir->payload_start_time = tct_tm.current_time;
		} else {
			/* iat (inter arrival time stat */
			iat = elapsed(thisdir->payload_end_time, tct_tm.current_time);
			thisdir->iat_sum += iat;
			thisdir->iat_sum2 += iat*iat;
			thisdir->iat_count++;

			if (iat > thisdir->max_iat)
				thisdir->max_iat = iat;
			if ((thisdir->min_iat == 0) || (iat < thisdir->min_iat))
				thisdir->min_iat = iat;
			/* array of IATS(inter arrival time */
			if (thisdir->iat_size < 10) {
				thisdir->iat_array[thisdir->iat_size] =iat;
				thisdir->iat_size++;
			}
		}
		thisdir->payload_end_time = tct_tm.current_time;
#if 1
		/* store the payload include both up and down stream into payload */
		/* allocate payload vector only once */
		if (sb->payload_len == 0) {
			sb->payload = (u_char *) malloc(tct_opts.stream_len*sizeof(u_char));
			if (sb->payload == NULL) {
				err_sys("malloc for payload size error\n");
			}
		}
		if (sb->payload_len < tct_opts.stream_len) {
			char *p;	
			p = (char *)ptcp + 4 * ptcp->doff;	/* pointer to the first byte of payload */
			if (sb->payload_len + tcp_data_len < tct_opts.stream_len) {
				memcpy(&(sb->payload[sb->payload_len]), p, tcp_data_len);
				sb->payload_len += tcp_data_len;
			} else {
				memcpy(&(sb->payload[sb->payload_len]), p, tct_opts.stream_len - sb->payload_len);
				sb->payload_len = tct_opts.stream_len;
			}
		}
#endif

		/* store the first 10 payload length */
		if (thisdir->ps_size < 10) {
			thisdir->ps_array[thisdir->ps_size] = tcp_data_len;
			thisdir->ps_size++;
		}

	}

	thisdir->last_time = tct_tm.current_time; 
	++sb->total_pkts;		/* total packets stats */
	++thisdir->packets;		/* this directory */

	/* do rexmit stats */
	retrans = FALSE;
	out_order = FALSE;
	retrans_num_bytes = 0;
	if (ptcp->syn || ptcp->fin || tcp_data_len > 0) {
		int len = tcp_data_len;
		int retrans;
		if (ptcp->syn)
			++len;
		if (ptcp->fin)
			++len;

		retrans = retrans_num_bytes =
		    rexmit(thisdir, start, len, &out_order, pip->ip_id);

		/* count anything NOT retransmitted as "unique" */
		/* exclude SYN and FIN */
		if (ptcp->syn) {
			/* don't count the SYN as data */
			--len;
			/* if the SYN was rexmitted, then don't count it */
			if (thisdir->syn_count > 1)
				--retrans;
		}
		if (ptcp->fin) {
			/* don't count the FIN as data */
			--len;
			/* if the FIN was rexmitted, then don't count it */
			if (thisdir->fin_count > 1)
				--retrans;
		}
		if (retrans < len)
			thisdir->unique_bytes += (len - retrans);

	}

	/* stats for rexmitted data */
	if (retrans_num_bytes > 0) {
		retrans = TRUE;
		thisdir->rexmit_pkts += 1;
		thisdir->rexmit_bytes += retrans_num_bytes;
	} else {
		thisdir->seq = end;
	}

	/* do rtt stats */
	if (ptcp->ack) {
		ack_in(otherdir, ack, tcp_data_len);
	}

	/* do window stats (include first SYN too!) */
	if (ptcp->ack || ptcp->syn) {
		thisdir->win_curr = eff_win;
		if (eff_win > thisdir->win_max)
			thisdir->win_max = eff_win;
		if ((eff_win > 0) &&
		    ((thisdir->win_min == 0) || (eff_win < thisdir->win_min)))
			thisdir->win_min = eff_win;
	}

	if (ptcp->ack) {
		++thisdir->ack_pkts;
		if ((tcp_data_len == 0) &&
		    !ptcp->syn && !ptcp->fin && !ptcp->rst) {
			++thisdir->pure_ack_pkts;
		}
		thisdir->ack = ack;
	}

	/* do stats for initial window (first slow start) */
	/* (if there's data in this and we've NEVER seen */
	/*  an ACK coming back from the other side) */
	/* this is for Mark Allman for slow start testing -- Mon Mar 10, 1997 */
	if (!otherdir->data_acked && ptcp->ack
	    && ((otherdir->syn + 1) != ack)) {
		otherdir->data_acked = TRUE;
	}
	if ((tcp_data_len > 0) && (!thisdir->data_acked)) {
		if (!retrans) {
			/* don't count it if it was retransmitted */
			thisdir->initial_win_bytes += tcp_data_len;
			thisdir->initial_win_segs += 1;
		}
	}

	if (ptcp->ack && !ptcp->syn) {
		if (ZERO_TIME(&(thisdir->ack_start_time))) {
			thisdir->ack_start_time = tct_tm.current_time;
		}
	}

	/* do stats for congestion window (estimated) */
	/* estimate the congestion window as the number of outstanding */
	/* un-acked bytes */
	if (!ptcp->syn && !out_order && !retrans) {
		u_int32_t cwin = end - otherdir->ack;

		if ((int32_t) cwin > 0 && cwin > thisdir->cwin_max) {
			thisdir->cwin_max = cwin;
		}
		if ((int32_t) cwin > 0
		    && ((thisdir->cwin_min == 0) || (cwin < thisdir->cwin_min)))
			thisdir->cwin_min = cwin;
	}

	return 0;
}


int tcp_bflow_stat(struct ip *pip, struct tcphdr *ptcp, void *plast)
{
	struct bflow_entry *entry;
	struct connection *sb;
	struct connection *tmp;
	struct end_to_end *thisdir;
	struct end_to_end *otherdir;
	int dir;			/* the direction of the connection */
	int ret;
	Bool new_session = FALSE;

	/* make sure we have enough of the packet, at least a tcp header */
	if ((u_long)ptcp + sizeof(struct tcphdr) -1 > (u_long)plast) {
		tct_stat.trunc_pkts++;
		return FLOW_STAT_SHORT;
	}

	/* get the corresponding table entry for the given packet */
	entry = bf_get_entry(pip, ptcp->source, ptcp->dest, &dir, L4_PROTO_TCP);
	if (entry == NULL) {
		err_quit("get_entry for bflow error");
	}

	/*
	 * if a new session should be created 
	 * a SYN flag is forcing a new session or the session time out is expired(60 s)
	 */
	if (dir == C2S && ptcp->syn) {
		new_session = true;
	}

	if (entry->ete != NULL) {
		int expire = tct_tm.current_time.tv_sec - entry->ete->last_time.tv_sec;
		if (expire > SESSION_TIMEOUT) {
#if 0
			make_conn(entry, 1, 0);
			tmp = entry->ete;
			entry->ete = tmp->prev;
			free_conn(tmp);
#endif
			new_session = true;
			SET_BIT(entry->ete->flags, SESS_EXPIRED, 1);
		}
	}

	/* create a new session */
	if (new_session) {
	   	tmp = entry->ete;
		entry->ete = init_bflow(tmp);
		if (entry->ete == NULL) {
			err_msg("get ete error, maybe have no memory");
			return FLOW_STAT_NULL;
		}
		tct_stat.tot_conn_tcp++;
		tct_stat.cur_conn_tcp++;
		entry->num_bflows++;

#if 0
	if (entry->num_bflows > 10)
		err_quit("fuck >10 ");
#endif
		tct_stat.sessions++;

		entry->ete->first_time = tct_tm.current_time;
		sb = entry->ete;

		if (dir == C2S) {
			memcpy(&(sb->addr_pair), &(entry->key1), sizeof(struct five_tuple));
		} else {
			memcpy(&(sb->addr_pair), &(entry->key1), sizeof(struct five_tuple));
			//err_quit("when start a new_session the direction is s2c, panic\n");
			//err_msg("when start a new_session the direction is s2c, panic\n");
		}

		sb->addr_pair.l4proto = L4_PROTO_TCP;

		/* inspect TCP syn flag */
		if (ptcp->syn) {
			SET_BIT(sb->flags, SESS_TCP_SYN, 1);
		}

		/* if training then find the app id */
		if (tct_opts.ground) {
			struct class_info *truth = find_ground_truth(sb->addr_pair, sb->first_time);
			if (truth != NULL) {
				sb->label.app_id = truth->app_id;
			//	strcpy(sb->label.name, truth->name);
			} 
		#if 0
			else { 
				char addr[64], addr2[64];
				err_msg("%s:%d <==> %s:%d %lu.%06lu\n", 
					host_addr(sb->addr_pair.a_addr, addr, sizeof(addr)), 	
					ntohs(sb->addr_pair.a_port),
					host_addr(sb->addr_pair.b_addr, addr2, sizeof(addr2)), 	
					ntohs(sb->addr_pair.b_port),
					sb->first_time.tv_sec,
					sb->first_time.tv_usec);
			}
		#endif
					
		}
	}
	
	sb = entry->ete;
	if (sb == NULL) {
#if 0
		char str[64];
		printf("%s", inet_ntop(AF_INET, &entry->key1.a_addr.un.ipv4, str, sizeof(str)));
		printf(":%d", ntohs(entry->key1.a_port));
		printf(" %s", inet_ntop(AF_INET, &entry->key1.b_addr.un.ipv4, str, sizeof(str)));
		printf(":%d\n", ntohs(entry->key1.b_port));
		printf("%ld\n", tct_stat.tcp_pkts);
		
		printf("%d\t%d\n", entry->key1.a_port,entry->key1.b_port);
		err_msg("sb --> struct connection is NULL, panic");
#endif
		return FLOW_STAT_NULL;
	}

	/* do time stats. sb->firt_time is initialized when the session is built*/
	sb->last_time =  tct_tm.current_time;

	if (dir == C2S) {
		thisdir = &(sb->c2s);
		otherdir = &(sb->s2c);
	} else {
		thisdir = &(sb->s2c);
		otherdir = &(sb->c2s);
	}

	/* check if this is a dupe tcp */
	if (dup_check(pip, ptcp->check, thisdir)) {
		return FLOW_STAT_DUP;
	}
	
	/* meta connection stats */
	if (ptcp->syn)
		thisdir->syn_count++;
	if (ptcp->rst) 
		thisdir->reset_count++;
	if(ptcp->fin) {
		SET_BIT(sb->flags, ((dir == C2S) ? SESS_TCP_FIN_UP : SESS_TCP_FIN_DW), 1);
		thisdir->fin_count++;
		thisdir->fin_seqno = ntohl(ptcp->seq);
	}

	/* 
	 * skip tcp sessions without 3-way handshake. if we got a syn from
	 * the client, but no syn+ack from the server, and this a data packet from
	 * the client. then this must be an half flow
	 */
	if ((dir == C2S) && (!(ptcp->syn)) && (otherdir->syn_count == 0) 
	     &&  TEST_BIT(sb->flags, SESS_SKIP, 0)) {
		tct_stat.skipped_sessions++;
		tct_stat.cur_conn_tcp--;
		SET_BIT(sb->flags, SESS_SKIP, 1);
	}

	if (TEST_BIT(sb->flags, SESS_SKIP, 1)) { 
		tct_stat.skiped_pkts++;	
		return FLOW_STAT_NULL;
	}

#ifdef  QUICK
	//if (sb->total_pkts >= 5) {
	//if (thisdir->data_pkts + otherdir->data_pkts >= 2) {
	if (thisdir->packets + otherdir->packets >= QUICK_NUM) {
		SET_BIT(sb->flags, SESS_SKIP, 1);
		SET_BIT(sb->flags, SESS_EXPIRED, 1);
		return FLOW_STAT_NULL;
	}
#endif

	ret = extract_bflow_features(sb, thisdir, otherdir, pip, ptcp, plast);

	/* check for RESET */
	if (ptcp->rst) {
		if (sb->c2s.reset_count+sb->s2c.reset_count != 0) {
			if (TEST_BIT(sb->flags, SESS_RESET, 0)) {
				SET_BIT(sb->flags, SESS_RESET, 1);
			}
			make_conn(entry, (sb->s2c.syn_count > 0 && sb->c2s.syn_count > 0), 1);

		} else {
			err_quit("reset should > 1, but not.So panic");
		}
		return FLOW_STAT_OK;
	}

	/* Check if the connection is completed */
	if (sb->c2s.closed && sb->s2c.closed) {
		SET_BIT(sb->flags, SESS_CLOSED, 1);
		make_conn(entry, TRUE, 1);
		return FLOW_STAT_OK;
	}

	/* real time work mode classify as quick as possible  */
	if (tct_opts.work_mode == MODE_REALTIME) {
		/* Classification */
		if (tct_opts.classify && TEST_BIT(sb->flags, (SESS_DONT_CLASSIFY|SESS_CLASSIFIED), 0)) {
			if (is_session_classifiable(sb)) {
				/* Take classification decision */
				classify(entry);
				/* REALTIME mode: we immediately output the classification result */
				if (!TEST_BIT(sb->flags, (SESS_DONT_CLASSIFY|SESS_CLASSIFIED), 0))
					store_result(sb);
			}
		}

	}

	return ret;
}

/*-------------------------------------------------------------------------------/
 *from  here to end stolen from tcptrace					  
 */

/* get a short (2 byte) option (to avoid address alignment problems) */
static u_short get_short_opt(void *ptr)
{
	u_short s;
	memcpy(&s, ptr, sizeof (u_short));
	return (s);
}

/* get a long (4 byte) option (to avoid address alignment problems) */
static u_long get_long_opt(void *ptr)
{
	u_long l;
	memcpy(&l, ptr, sizeof (u_long));
	return (l);
}
/* 
 * this function is stolen from tcptrace where is called ParseOptions()
 * I change the name, cause I perfer Linux kernel style, and the struct tcphdr from
 * bsd to normal linux :)
 */
static struct tcp_options *parse_options(struct tcphdr *ptcp, void *plast)
{
	static struct tcp_options tcpo;
	struct sack_block *psack;
	u_char *pdata;
	u_char *popt;
	u_char *plen;

	popt = (u_char *) ptcp + sizeof (struct tcphdr);
	pdata = (u_char *) ptcp + ptcp->doff * 4;
	/* init the options structure */
	memset(&tcpo, 0, sizeof (tcpo));
	tcpo.mss = tcpo.ws = tcpo.tsval = tcpo.tsecr = -1;
	tcpo.sack_req = 0;
	tcpo.sack_count = -1;
	tcpo.echo_req = tcpo.echo_repl = -1;
	tcpo.cc = tcpo.ccnew = tcpo.ccecho = -1;

	Bool warn_printtrunc = TRUE; 

	/* a quick sanity check, the unused (MBZ) bits must BZ! */
#if DEBUG > 3
	if (ptcp->res1) {
		fprintf(stderr,
			"TCP packet %lu: 4 reserved bits are not zero (0x%01x)\n",
			tct_stat.tcp_pkts, ptcp->res1);
	}
	if ((ptcp->res2) != 0) {
		fprintf(stderr,
			"TCP packet %lu: upper flag bits are not zero (0x%02x)\n",
			tct_stat.tcp_pkts, ptcp->res2);
	}
#else 
	static int warned = 0;
	if (!warned && (ptcp->res1 || ptcp->res2)) {
		warned = 1;
		fprintf(stderr, "TCP packet %lu: reserved bits are not all zero.\n"
			"\tFurther warnings disabled, use '-w' for more info\n", tct_stat.tcp_pkts);
	}
#endif
	/* looks good, now check each option in turn */
	while (popt < pdata) {
		plen = popt + 1;
		/* check for truncation error */
		if ((unsigned long) popt >= (unsigned long) plast) {
#if DEBUG > 4
	fprintf(stderr, "ParseOptions: packet %lu too short (%lu) to parse remaining options\n", 
		tct_stat.tcp_pkts, (unsigned long) popt - (unsigned long) plast + 1);
#endif
			++tct_stat.trunc_pkts;
			break;
		}
#define CHECK_O_LEN(opt) \
	if (*plen == 0) { \
	    if (warn_printtrunc) \
	    	fprintf (stderr, "ParseOptions: packet %lu %s option has length 0, skipping other options\n", \
                                           tct_stat.tcp_pkts,opt); \
	    popt = pdata; break;} \
	if ((unsigned long)popt + *plen - 1 > (unsigned long)(plast)) { \
	    if (warn_printtrunc) \
		fprintf (stderr, "ParseOptions: packet %lu %s option truncated, skipping other options\n", \
              tct_stat.tcp_pkts,opt); \
	    ++tct_stat.trunc_pkts; \
	    popt = pdata; break;} \


		switch (*popt) {
		case TCPOPT_EOL:
			++popt;
			break;
		case TCPOPT_NOP:
			++popt;
			break;
		case TCPOPT_MAXSEG:
			CHECK_O_LEN("TCPOPT_MAXSEG");
			tcpo.mss = ntohs(get_short_opt(popt + 2));
			popt += *plen;
			break;
		case TCPOPT_WS:
			CHECK_O_LEN("TCPOPT_WS");
			tcpo.ws = *((u_char *) (popt + 2));
			popt += *plen;
			break;
		case TCPOPT_TS:
			CHECK_O_LEN("TCPOPT_TS");
			tcpo.tsval = ntohl(get_long_opt(popt + 2));
			tcpo.tsecr = ntohl(get_long_opt(popt + 6));
			popt += *plen;
			break;
		case TCPOPT_ECHO:
			CHECK_O_LEN("TCPOPT_ECHO");
			tcpo.echo_req = ntohl(get_long_opt(popt + 2));
			popt += *plen;
			break;
		case TCPOPT_ECHOREPLY:
			CHECK_O_LEN("TCPOPT_ECHOREPLY");
			tcpo.echo_repl = ntohl(get_long_opt(popt + 2));
			popt += *plen;
			break;
		case TCPOPT_CC:
			CHECK_O_LEN("TCPOPT_CC");
			tcpo.cc = ntohl(get_long_opt(popt + 2));
			popt += *plen;
			break;
		case TCPOPT_CCNEW:
			CHECK_O_LEN("TCPOPT_CCNEW");
			tcpo.ccnew = ntohl(get_long_opt(popt + 2));
			popt += *plen;
			break;
		case TCPOPT_CCECHO:
			CHECK_O_LEN("TCPOPT_CCECHO");
			tcpo.ccecho = ntohl(get_long_opt(popt + 2));
			popt += *plen;
			break;
		case TCPOPT_SACK_PERM:
			CHECK_O_LEN("TCPOPT_SACK_PERM");
			tcpo.sack_req = 1;
			popt += *plen;
			break;
		case TCPOPT_SACK:
			/* see which bytes are acked */
			CHECK_O_LEN("TCPOPT_SACK");
			tcpo.sack_count = 0;
			psack = (struct sack_block *) (popt + 2);	/* past the kind and length */
			popt += *plen;
			while ((unsigned long) psack < (unsigned long) popt) {
				struct sack_block *psack_local =
				    &tcpo.sacks[(unsigned) tcpo.sack_count];
				/* warning, possible alignment problem here, so we'll
				   use memcpy() and hope for the best */
				/* better use -fno-builtin to avoid gcc alignment error
				   in GCC 2.7.2 */
				memcpy(psack_local, psack, sizeof (struct sack_block));

				/* convert to local byte order (Jamshid Mahdavi) */
				psack_local->sack_left =
				    ntohl(psack_local->sack_left);
				psack_local->sack_right =
				    ntohl(psack_local->sack_right);

				++psack;
				if ((unsigned long) psack >
						((unsigned long) plast + 1)) {
					/* this SACK block isn't all here */
					if (warn_printtrunc)
						fprintf(stderr,
							"packet %lu: SACK block truncated\n",
							tct_stat.tcp_pkts);
					++tct_stat.trunc_pkts;
					break;
				}
				++tcpo.sack_count;
				if (tcpo.sack_count > MAX_SACKS) {
					/* this isn't supposed to be able to happen */
					fprintf(stderr,
						"Warning, internal error, too many sacks!!\n");
					tcpo.sack_count = MAX_SACKS;
				}
			}
			break;
		default:
#if DEBUG > 2
	fprintf(stderr, "Warning, ignoring unknown TCP option 0x%x\n", *popt);
#endif
			CHECK_O_LEN("TCPOPT_UNKNOWN");

			/* record it anyway... */
			if (tcpo.unknown_count < MAX_UNKNOWN) {
				int ix = tcpo.unknown_count;	/* make lint happy */
				tcpo.unknowns[ix].unkn_opt = *popt;
				tcpo.unknowns[ix].unkn_len = *plen;
			}
			++tcpo.unknown_count;

			popt += *plen;
			break;
		}
	}
	return (&tcpo);
}

/*-------------------------------------------------------------------------------*/

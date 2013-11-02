#ifndef _STRUCT
#define _STRUCT

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>	/* for ipv4 and ipv6 address struct */
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include "class.h"


/* Session Flags */
#define SESS_SKIP			0x1	/* 1 => skip session processing */
#define SESS_CLOSED			0x2	/* 1 => first packet with payload received */
#define SESS_RESET			0x4	/* 1 => payload is not alpha-numeric */
#define SESS_DONT_CLASSIFY		0x8	/* 1 => session is not to be classified */

#define SESS_CLASSIFIED			0x10	/* 1 => session has been classified */
#define SESS_RECLASSIFY			0x20	/* 1 => session is to be reclassified */
#define SESS_SIGNED			0x40	/* 1 => signature saved */
#define SESS_EXPIRED			0x80	/* 1 => session expired */

/* TCP FLAGS */
#define SESS_TCP_SYN			0x100	/* 1 => SYN flag seen for this session */
#define SESS_TCP_FIN			0x200	/* 1 => FIN flag seen for this session */
#define SESS_TCP_FIN_UP			0x200	/* 1 => FIN flag seen in upstream for this session */
#define SESS_TCP_FIN_DW			0x400	/* 1 => FIN flag seen in dwstream for this session */
#define SESS_TCP_RST			0x800	/* 1 => RST flag seen for this session */


typedef enum {
	FALSE,
	TRUE
} Bool;

/*
 * for ipaddress, can be a ipv4 or a ipv6 address.
 */
struct ipaddr {
	char version;	/* 4 or 6 */
	union {
		struct in_addr ipv4;
		struct in6_addr ipv6;
	}un;
};

/* 
 * define the five tuple structure
 */
struct five_tuple {
	struct ipaddr a_addr;
	struct ipaddr b_addr;
	in_port_t a_port;
	in_port_t b_port;
	uint16_t l4proto;
};


/******************************************************************** 
 * here is from tcptrace for rexmit 
 * It looks so unprofessional to use typedef :( . so I change them.
 */

struct segment {
	uint32_t seq_firstbyte;	/* seqnumber of first byte */
	uint32_t seq_lastbyte;	/* seqnumber of last byte */
	u_char retrans;		/* retransmit count */
	u_int acked;		/* how MANY times has has it been acked? */
	struct timeval time;		/* time the segment was sent */
	/* LM start - add field to implement an heuristic to identify 
	   loss packets within a flow
	 */
	u_short ip_id;		/* 16 bit ip identification field  */
	char type_of_segment;
	/* LM stop */
	struct segment *next;
	struct segment *prev;
};

struct quadrant {
	struct segment *seglist_head;
	struct segment *seglist_tail;
	Bool full;
	u_long no_of_segments;
	struct quadrant *prev;
	struct quadrant *next;
};

struct seqspace {
	struct quadrant *pquad[4];
};
/********************************************************************/



struct end_to_end {
	/* statistics for a tcp connection */
	u_long packets;		/* the number of packets sent from this end (3)*/	
	u_long data_pkts_push;	/* number of payload packets with the push flag */
	u_long ack_pkts;	/* number of packets with the ack flag */
	u_long pure_ack_pkts;	/* pure acks, no data */
	u_long unique_bytes;	/* bytes sent (-FIN/SYN) excluding retransimission */
	u_long data_pkts;	/* number of packets with payload data */
	u_long data_bytes;	/* payload bytes including retransmission  */

	/* tcp options */
	Bool f1323_ws;	/* request 1323 window scaling or not ?*/
	Bool f1323_ts;	/* request 1323 timestamps or not */
	u_char window_scale;	/* scaling values negotiated */
	Bool fsack_req;	/* request SACKS */
	uint32_t sacks_sent;	/* number of sacks messages sent */
	uint32_t mss;		/* mss declared */

	uint32_t max_seg_size;	/* maximum segment size observed */
	uint32_t min_seg_size;	/* minimum segment size observed */
	u_long seg_size_sum;	/* the sum of the seg_size */
	u_long seg_size_sum2;	/* the sum of the seg_size square */
	/*seg1 ~ seg 10 */
	u_int ps_array[10];
	short ps_size;

	uint32_t win_max;		/* maximum receiver window announced */
	uint32_t win_min;		/* minimum receiver window announced */
	u_int win_curr;

	/* congestions window statistics */
	/*
	 * maximum [minmum] in-flight-size computed as the difference between the largest sequence number
	 * so far, and the corresponding last ACK message on the reverse path
	 */
	u_long cwin_max;	
	u_long cwin_min;

	/* initial window */
	uint32_t initial_win_bytes;	/* in bytes */
	uint32_t initial_win_segs;		/* in segments */
	Bool data_acked;		/* has any non_syn data been acked? */

	/* rtt stats */
	u_long rtt_min;		/*minimum RTT observed */
	u_long rtt_max;		/* maxmum RTT observed */
	double rtt_sum;		/* for average RTT */
	double rtt_sum2;	/* for stdev */
	uint32_t rtt_count;	/* for average and stdev */


	/* inter-arrival time */
	u_long min_iat;		/* minmum inter-arrival time (ms)*/
	u_long max_iat;		/* maxmum inter-arrival time (ms)*/
	double iat_sum;			/* for average IAT */
	double iat_sum2;
	uint32_t iat_count;
	uint32_t iat_array[10];
	short iat_size;
	
	struct timeval payload_start_time;	/* time of the first data packets. for 'first payload time' */
	struct timeval payload_end_time;	/* time of the last valid ack */
	struct timeval ack_start_time;		/* time of the first ack (not syn) */
	Bool bad_behavior;	
	/* for tracking unidirectional idle time */
	struct timeval last_time;	/* last packet SENT from this side */

	/* dupe verify */
	u_short last_ip_id;	/* 16 bit ip identification field  */
	u_short last_len;	/* length of the last packet  */
	u_short last_checksum;	/* checksum of the last packet */

	/* TCP information */
	uint32_t ack;
	uint32_t seq;
	uint32_t syn;
	uint32_t fin;
	uint32_t fin_seqno;
	uint32_t windowend;

	uint32_t syn_count;	/* number of syn flags */
	uint32_t fin_count;	/* number of fin flags */
	uint32_t reset_count;

/*---------------------------------------------------------------*/
	/* retransmission information */
	struct seqspace ss;		/* the sequence space */
	u_long retr_max;	/* maximum retransmissions ct */
	u_long retr_min_tm;	/* minimum retransmissions time */
	u_long retr_max_tm;	/* maximum retransmissions time */
	double retr_tm_sum;	/* for averages */
	double retr_tm_sum2;	/* sum of squares, for stdev */
	u_long retr_tm_count;	/* for averages */
	/* Duplicated and rtx counters */
	u_int rtx_RTO;
	u_int rtx_FR;
	u_int reordering;
	u_int net_dup;
	u_int unknown;
	u_int flow_control;
	u_int unnecessary_rtx_FR;
	u_int unnecessary_rtx_RTO;

	u_int rexmit_bytes;
	u_int rexmit_pkts;
	struct connection *parent;	

	/* rtt used in rexmit.c */
	/* ACK Counters */
	u_long rtt_cumack;	/* segments only cumulativly ACKed */
	u_long rtt_nosample;	/* segments ACKED, but after retransmission */
	/* of earlier segments, so sample isn't */
	/* valid */
	u_long rtt_unkack;	/* unknown ACKs  ??? */
	u_long rtt_dupack;	/* duplicate ACKs */
	u_long rtt_triple_dupack;	/* triple duplicate ACKs */
	double rtt_last;		/* RTT as of last good ACK */
	double srtt;			/* smoothed RTT estimation */
	double rttvar;			/* smoothed stdev estimation */
/*---------------------------------------------------------------*/

#if 0	/* packet level */
	/* Count TCP messages, as separated by PSH or FIN */
	u_int msg_count;
	u_int msg_size[10];
	seqnum msg_last_seq;
	u_char *payload;	/* vector containing payloads stream */
	uint32_t payload_len;	/* number of bytes collected into payload vector */
#endif

	int closed;

};


struct connection {
	struct five_tuple addr_pair;	/* endpoint identification */

	/*feature information */
	struct end_to_end c2s;
	struct end_to_end s2c;

	struct timeval first_time;	/* timestamp of the first packet */
	struct timeval last_time;
	u_long total_pkts;		/* total pkts */
	struct connection *prev;	/* */

	u_char *payload;	/* vector containing payloads stream */
	uint32_t payload_len;	/* number of bytes collected into payload vector */

	int flags;			/* session flags */
	float confidence;	/* confidence associated with match */
	struct tct_result type[5];
	struct tct_result label;
};


struct bflow_entry {
	struct bflow_entry *next;	/* pointer to the next entry with different key but the same mapping. */
	struct connection *ete;		/* pointer to the linked list of sessions (biflow) */
	uint32_t num_bflows;		/* numbers of bflows with this key , the same connetion but with different time*/
	struct five_tuple key1;		/* key of this entry (src_ip, dst_ip, src_port, dst_port) */
	struct five_tuple key2;		/* key of this entry (src_ip, dst_ip, src_port, dst_port) */

};

struct flow_entry {
	struct flow_entry *next;	/* pointer to the next entry with different key but the same mapping. */
	struct connection *ete;		/* pointer to the linked list of sessions (iflow) */
	uint32_t num_bfows;		/* numbers of bflows with this key , the same connetion but with different time*/
	struct five_tuple key1;		/* key of this entry (src_ip, dst_ip, src_port, dst_port) */
};

/*****************************************************************************************/
/* stolen from tcptrace */

/*macros for maintaining the seqspace used for rexmit*/
#define QUADSIZE	(0x40000000)
#define QUADNUM(seq)	((seq>>30)+1)
#define IN_Q1(seq)	(QUADNUM(seq)==1)
#define IN_Q2(seq)	(QUADNUM(seq)==2)
#define IN_Q3(seq)	(QUADNUM(seq)==3)
#define IN_Q4(seq)	(QUADNUM(seq)==4)
#define FIRST_SEQ(quadnum)	(QUADSIZE*(quadnum-1))
#define LAST_SEQ(quadnum)	((QUADSIZE-1)*quadnum)
#define BOUNDARY(beg,fin) (QUADNUM((beg)) != QUADNUM((fin)))

/* physical layers currently understood					*/
#define PHYS_ETHER	1
#define PHYS_FDDI       2

/*
 * SEQCMP - sequence space comparator
 *	This handles sequence space wrap-around. Overlow/Underflow makes
 * the result below correct ( -, 0, + ) for any a, b in the sequence
 * space. Results:	result	implies
 *			  - 	 a < b
 *			  0 	 a = b
 *			  + 	 a > b
 */
#define	SEQCMP(a, b)		((long)(a) - (long)(b))
#define	SEQ_LESSTHAN(a, b)	(SEQCMP(a,b) < 0)
#define	SEQ_GREATERTHAN(a, b)	(SEQCMP(a,b) > 0)

/* SACK TCP options (not an RFC yet, mostly from draft and RFC 1072) */
/* I'm assuming, for now, that the draft version is correct */
/* sdo -- Tue Aug 20, 1996 */
#define	TCPOPT_SACK_PERM 4	/* sack-permitted option */
#define	TCPOPT_SACK      5	/* sack attached option */
#define	MAX_SACKS       10	/* max number of sacks per segment (rfc1072) */
struct sack_block {
	uint32_t sack_left;	/* left edge */
	uint32_t sack_right;	/* right edge */
};

#define MAX_UNKNOWN 16
struct opt_unknown {
	u_char unkn_opt;
	u_char unkn_len;
};

/* RFC 1323 TCP options (not usually in tcp.h yet) */
#define	TCPOPT_WS	3	/* window scaling */
#define	TCPOPT_TS	8	/* timestamp */

/* other options... */
#define	TCPOPT_ECHO		6	/* echo (rfc1072) */
#define	TCPOPT_ECHOREPLY	7	/* echo (rfc1072) */
#define TCPOPT_TIMESTAMP	8	/* timestamps (rfc1323) */
#define TCPOPT_CC		11	/* T/TCP CC options (rfc1644) */
#define TCPOPT_CCNEW		12	/* T/TCP CC options (rfc1644) */
#define TCPOPT_CCECHO		13	/* T/TCP CC options (rfc1644) */

/* RFC 2481 (ECN) IP and TCP flags (not usually defined yet) */
#define IPTOS_ECT	0x02	/* ECN-Capable Transport */
#define IPTOS_CE	0x01	/* Experienced Congestion */

#define TH_ECN_ECHO	0x02	/* Used by receiver to echo CE bit */
#ifndef TH_CWR
#define TH_CWR		0x01	/* Congestion Window Reduced */
#endif

struct tcp_options {
	short mss;		/* maximum segment size         */
	char ws;		/* window scale (1323)          */
	long tsval;		/* Time Stamp Val (1323)        */
	long tsecr;		/* Time Stamp Echo Reply (1323) */

	Bool sack_req;		/* sacks requested              */
	char sack_count;	/* sack count in this packet */
	struct sack_block sacks[MAX_SACKS];	/* sack blocks */

	/* echo request and reply */
	/* assume that value of -1 means unused  (?) */
	u_long echo_req;
	u_long echo_repl;

	/* T/TCP stuff */
	/* assume that value of -1 means unused  (?) */
	u_long cc;
	u_long ccnew;
	u_long ccecho;

	/* record the stuff we don't understand, too */
	char unknown_count;	/* number of unknown options */
	struct opt_unknown unknowns[MAX_UNKNOWN];	/* unknown options */
};

int rexmit(struct end_to_end * ptcb, uint32_t seq, u_long len, Bool * pout_order,
       u_short this_ip_id);

/*****************************************************************************************/
#endif /* _STRUCT */

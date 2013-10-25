/*
 * our own header to be incuded before all standard system headers
 */
#ifndef _TCT
#define _TCT

/*
 * the basis headers for C
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <stdarg.h> 
#include <signal.h>
#include <time.h>
#include <errno.h>
#include <ctype.h>
#include <stdbool.h>
#include <getopt.h>

/*
 * headers for unix programming environment
 */
#include <unistd.h>
#include <fcntl.h>	/* for open etc. system call */
#include <pthread.h>	/* for thread library */
#include <sys/stat.h>	/* for stat */
#include <sys/types.h>	/* for type like int8_t uint32_t etc. */
#include <sys/time.h>

/* 
 * headers for network programming
 */
#include <pcap.h>	/* include the pcap library */
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>	/* for ipv4 and ipv6 address struct */
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

/*
 * headers of our own need to be include by all *.c files 
 */
#include "error.h"
#include "class.h"
#include "macros.h"
#include "ipv6.h"
#include "struct.h"
#include "memory.h"
#include "plugins/combine.h"
#include "debug.h"
#include "ground.h"

/*
 * to invoke quick classification or not
 */
// #define QUICK

/*
 * our own manifest constant
 */
#define	DEFAULT_SNAPLEN		1518
#define	DEFAULT_STREAMLEN	2048
#define	CLEAN_INTERVAL		20000	/* the number of pkts when do garbage collection  default is 10,000 */
#define SESSION_TIMEOUT 60
//#define	SESSION_TIMEOUT		 120

#define	MODE_OFFLINE		1
#define	MODE_REALTIME		2
#define	SESSION_TYPE_FLOW	1
#define	SESSION_TYPE_BFLOW	2
#define	SESSION_TYPE_PKT	3

#define MAX_SRCF		10
#define HASH_TABLE_SIZE		123457 	//2345617	/* must be a primer */

/* 
 * Return values for tcp_flow_stat() and udp_flow_stat() 
 */
#define	FLOW_STAT_NULL	0	/* not able to check flow */
#define	FLOW_STAT_OK	1
#define	FLOW_STAT_DUP	2
#define	FLOW_STAT_NONE	3	/* no flow have check done yet */
#define	FLOW_STAT_SHORT	4

#define	C2S	1
#define	S2C	-1

#define	L4_PROTO_TCP	0x6
#define	L4_PROTO_UDP	0x11


/* 
 * for options! use structure to store the options.
 */
struct tct_options {
	int work_mode;		/* work mode:(1) offline (2) real time [-m [o|r], default is offline */
	int session_type;	/* session type: (1) flow, (2) biflow, (3) packet [-s [f|b|p], default is biflow */
	int read_mode;		/* read packets form pcap file >0 or from interface (0) */
	char *pcap_file[MAX_SRCF];	/* specified by [-r file] */

	int ground;		/* have ground truth or not */	
	char *ground_truth;	/* ground truth file name [-g file] */
	int write_mode;		/* dump packets to a tcpdump file */
	char *dump_file;	/* specified by [-w file] */
	char *output_file;	/* result output file, default is output/result.**.log */
	char *device;		/* interface name [-i interface] */
	int train;		/* */
	char *classifier_name;	/* specify the classifier to be trained [-t name] */
	char *filter_file;	/* specified the filer file [-D file] */
	int filter_disable;	/* disable the filter -d */

	/*  other variables; */
	int snaplen;		/* capture only #bytes from each packets, default set to 1500 [-f num]*/
	int stream_len;	/* set the number bytes of payload to store per session [-F num]*/
	int thread;		/* enable thread or not default is enable */
	int classify;		/* default is yes */
};

/*
 * for globle statistics. Like the number of packs have seen etc.
 */
struct tct_statistics {
	struct timeval wallclock_start;		/* wall clock when the program start */
	struct timeval wallclock_finished;	/* wall clock when the program finished */
#if 0
	struct timeval ts_start;		/* timestamp of the first packet read */
	struct timeval ts_end;			/* timestamp of the last packet read */
#endif
	u_long pkts;				/* the number of packets read. u_quad_t --> u_long long */
	u_long tcp_pkts;			/* tcp pkts traced */
	u_long udp_pkts;			/* udp pkts traced */
	u_long icmp_pkts;
	u_long skiped_pkts;			/* the number of pakcets that skipped (not ip etc.)*/
	u_long trunc_pkts;

	uint32_t tot_conn_tcp;			/* total connect tcps */
	uint32_t tot_conn_udp;			/* total connect udps */
	uint32_t cur_conn_tcp;
	uint32_t cur_conn_udp;
};

/*
 * globle timestamps structure
 */
struct tct_time {
	struct timeval first_time;
	struct timeval last_time;
	struct timeval current_time;		/* the timestamps of the current processing packet */
};

struct tct_global {
	uint32_t location;			/* the current location of the reading pcap file */
	u_long cur_filesize;			/* used to print ticks */
	u_long total_bytes;			/* the total Bytes thats have been processed */
	char *phys;				/* the physical name of the linktype */
	char *cur_filename;			/* in work mode, point to the current pcap_file */
	pcap_dumper_t *dumpd;			/* handle to dump traffic to local file */
	char path[256];				/* the path of working directory */
};


/* 
 * global variables which define in tct.c,
 * but declaration here, so other module can see it 
 */
extern struct tct_options tct_opts;		/* store information of the options for the program */
extern struct tct_time tct_tm;			/* globle time statistics */
extern struct tct_global tct_gb;
extern struct tct_statistics tct_stat;		/* program statistics */
extern struct bflow_entry *bflow_hashtable[HASH_TABLE_SIZE];
extern struct flow_entry *flow_hashtable[HASH_TABLE_SIZE];
extern struct session_statistics session_stat;

extern int g_argc;
extern char **g_argv;

/* 
 * global in output.c 
 */
extern FILE *class_out;		/* file pointer point to the class result file */
extern FILE *flow_outc;	/* file pointer point to the biflow features file with complete connection*/
extern FILE *flow_outnc;	/* file pointer point to the biflow features file without complete connection*/

/*
 * routines prototype  in other .c files
 */

/* routines type in output.c */
void open_log_file(const char *pcap_file);
void store_result(void *session);
void close_file();

/* routines in common.c */
unsigned long elapsed(struct timeval time1, struct timeval time2);
char *elasped2str(unsigned long etime);
struct bflow_entry *bf_get_entry(struct ip *pip, in_port_t source, in_port_t dest, int *dir, int l4);
Bool dup_check(struct ip *pip, uint16_t check, struct end_to_end *thisdir);
int catch_sig(int signo, void(*handler)());
void clean_quit(int signo);
struct connection *init_bflow(struct connection *prev);
int time_cmp(struct timeval time1, struct timeval time2);
double stdev(double sum, double sum2, int n);
double average(double sum, int count);
int same_connect(struct bflow_entry *p, struct ip *pip, in_port_t source, in_port_t dest, int *dir);
char *host_addr(struct ipaddr addr, char *str, int size);

/*  routines in tcp.c */
void tcp_trace_init();
int tcp_bflow_stat(struct ip *pip, struct tcphdr *ptcp, void *plast);
int log_tct_features(struct connection *sb, int complete);
int make_tcp_conn(void *session, Bool complete);

/*  routines in udp.c  */
int udp_flow_stat(struct ip *pip, struct udphdr *pudp, void *plast);

/*  routines in debug.c */
void print_class();

/* routines in rexmit.c this file is from tcptrace */
int rexmit(struct end_to_end * ptcb, uint32_t seq, u_long len, Bool * pout_order, u_short this_ip_id);
int ack_in(struct end_to_end * ptcb, uint32_t ack, unsigned tcp_data_length);



//stolen from tcptrace 
/*------------------------------------------------------------------------------------------*/
/*
 * fixes for various systems that aren't exactly like Solaris
 */
#ifndef IP_MAXPACKET
#define IP_MAXPACKET 65535
#endif				/* IP_MAXPACKET */

#ifndef ETHERTYPE_REVARP
#define ETHERTYPE_REVARP        0x8035
#endif				/* ETHERTYPE_REVARP */

#ifndef ETHERTYPE_VLAN
#define ETHERTYPE_VLAN		0x8100
#endif				/* 802.1Q Virtual LAN */

#ifndef ETHERTYPE_8021Q
#define ETHERTYPE_8021Q 0x8100	/* Ethernet type for VLAN */
#endif

/* support for vlan tagging */
#ifndef IEEE8021Q_SIZE
#define IEEE8021Q_SIZE		18
#endif				/* VLAN header size */

/* support for MPLS over ETH */
#ifndef ETHERTYPE_MPLS
#define ETHERTYPE_MPLS	0x8847
#endif				/* MPLS ether type */

#ifndef MPLS_SIZE
#define MPLS_SIZE		18
#endif				/* MPLS over ETH header size */

#ifndef MPLS8021Q_SIZE
#define MPLS8021Q_SIZE		22
#endif				/* MPLS over VLAN header size */

/* support for PPPoE encapsulation added by Yann Samama (ysamama@nortelnetworks.com)*/
#ifndef ETHERTYPE_PPPOE_SESSION
#define ETHERTYPE_PPPOE_SESSION	0x8864
#endif				/* PPPoE ether type */
#ifndef PPPOE_SIZE
#define PPPOE_SIZE		22
#endif				/* PPPOE header size */

#ifndef ETHERTYPE_IPV6
#define ETHERTYPE_IPV6 0x86DD	/* Ethernet type for ipv6 */
#endif

/* May be useful when the original trace has some NETWORK dups*/
/* Discard tcp/udp packets with: */
/* - same IP_ID */
/* - same TCP/UDP checksum */
/* - interarrival time smaller than MIN_DELTA_T_XXX_DUP_PKT */
/* - same IP length */

#define MIN_DELTA_T_UDP_DUP_PKT 1000	/* microsec (previously 50us) */
#define MIN_DELTA_T_TCP_DUP_PKT 2000	/* microsec (previously 50us) */
/*------------------------------------------------------------------------------------------*/

#endif /* _TCT */

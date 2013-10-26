/*------------------------------------------------------------*/
// this file is from tcptrace
#ifndef _TCPDUMP
#define _TCPDUMP

#include <stdio.h>
/* 
 * (from bpf.h)
 * Data-link level type codes.
 */

/* Note - Tue Feb 13, 2001
   We're having trouble with the standard DLT_type because some OS versions,
   insist on renumbering these to different values.  To avoid the problem,
   we're hijacking the types a little and adding the PCAP_ prefix.  The
   constants all correspond to the "true" pcap numbers, so this should
   fix the problem */

/* currently supported */
#define PCAP_DLT_NULL		0	/* no link-layer encapsulation */
#define PCAP_DLT_EN10MB		1	/* Ethernet (10Mb) */
#define PCAP_DLT_IEEE802	6	/* IEEE 802 Networks */
#define PCAP_DLT_SLIP		8	/* Serial Line IP */
#define PCAP_DLT_PPP            9	/* Point-to-Point Protocol */
#define PCAP_DLT_FDDI		10	/* FDDI */
#define PCAP_DLT_ATM_RFC1483	11	/* LLC/SNAP encapsulated atm */
#define PCAP_DLT_RAW		12	/* raw IP */
#define PCAP_DLT_C_HDLC         104	/* Cisco HDLC */
#define PCAP_DLT_IEEE802_11     105	/* IEEE 802.11 wireless */
#define PCAP_DLT_LINUX_SLL      113	/* Linux cooked socket */
#define PCAP_DLT_PRISM2         119	/* Prism2 raw capture header */
#define PCAP_DLT_IEEE802_11_RADIO 127	/* 802.11 plus WLAN header */
#define	PCAP_DLT_8021Q		/* 802.1q encapsulation */

/* NOT currently supported */
/* (mostly because I don't have an example file, send me one...) */
#define PCAP_DLT_EN3MB		2	/* Experimental Ethernet (3Mb) */
#define PCAP_DLT_AX25		3	/* Amateur Radio AX.25 */
#define PCAP_DLT_PRONET		4	/* Proteon ProNET Token Ring */
#define PCAP_DLT_CHAOS		5	/* Chaos */
#define PCAP_DLT_ARCNET		7	/* ARCNET */
#define PCAP_DLT_SLIP_BSDOS	13	/* BSD/OS Serial Line IP */
#define PCAP_DLT_PPP_BSDOS	14	/* BSD/OS Point-to-point Protocol */

/* tcpdump file header */
#define TCPDUMP_MAGIC 0xa1b2c3d4

#define US_PER_SEC 1000000	/* microseconds per second */

char *link_type(int type );
void init_filter(pcap_t *handle, char *argv[]);
int pread_tcpdump(pcap_t *handle, struct timeval *ptime, int *ptlen, struct ip **ppip, void **pplast);
#endif /* _TCPDUMP */
/*------------------------------------------------------------*/

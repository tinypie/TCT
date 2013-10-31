#ifndef _TCT_IPV6
#define _TCT_IPV6T

/* 
 * headers for network programming
 */
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>	/* for ipv4 and ipv6 address struct */
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>


/*
 * ipv6.h:
 *
 * Structures for IPv6 packets
 *
 */
#include <sys/types.h>
#include <netinet/icmp6.h>

/* just guessing... */
#if !defined(IPPROTO_NONE) && !defined(IPPROTO_FRAGMENT) && !defined(IPPROTO_DSTOPTS) && !defined(INET6_ADDRSTRLEN)
/* when IPv6 is more widely/standardly deployed, these constants won't need to be
   here.  In the mean time, here's the stuff we need... */
#define IPV6NOTFOUND

//minimum lenght of IPv6 packet=40 BYTES
#define MIN_IPV6_LENGHT 40

/* header types */
#define	IPPROTO_HOPOPTS		0	/* Hop by hop header for v6 */
#define	IPPROTO_IPV6		41	/* IPv6 encapsulated in IP */
#define	IPPROTO_ROUTING		43	/* Routing header for IPv6 */
#define	IPPROTO_FRAGMENT	44	/* Fragment header for IPv6 */
#define	IPPROTO_ICMPV6		58	/* ICMP for IPv6 */
#define	IPPROTO_NONE		59	/* No next header for IPv6 */
#define	IPPROTO_DSTOPTS		60	/* Destinations options */
/* other constants we need */
#define INET6_ADDRSTRLEN        46	/* IPv6 Address length in a string format */
#endif

/* this is SOMETIMES already defined */
#ifndef AF_INET6
#define AF_INET6                24	/* Internet Protocol, V6 */
#endif				/* AF_INET6 */


/*
 * IPv6 datagram header 
 */
struct ipv6 {
	u_int ip6_ver_tc_flabel;	/* first 4  bits = version #, 
					   next  4  bits = Trafic class,
					   next  24 bits = flow label */
	u_short ip6_lngth;	/* Payload length */
	u_char ip6_nheader;	/* Next Header */
	u_char ip6_hlimit;	/* Hop Limit */
	struct in6_addr ip6_saddr;	/* Source Address */
	struct in6_addr ip6_daddr;	/* Destination Address */
};

/* IPv6 extension header format */
struct ipv6_ext {
	u_char ip6ext_nheader;	/* Next Header */
	u_char ip6ext_len;	/* number of bytes in this header */
	u_char ip6ext_data[1];	/* optional data */
};

/* IPv6 fragmentation header */
struct ipv6_ext_frag {
	u_char ip6ext_fr_nheader;	/* Next Header */
	u_char ip6ext_fr_res;	/* (reserved) */
	u_short ip6ext_fr_offset;	/* fragment offset(13),res(2),M(1) */
	u_long ip6ext_fr_ID;	/* ID field */
};

//void ICMPv6_support(char *next, int internal_srcv6, int internal_dstv6);
char *findheader_ipv6(void *pplast, struct ip *pip, unsigned int *proto_type);
/* tcptrace's IPv6 access routines */
struct tcphdr *get_tcp(struct ip *pip, void **pplast);
struct udphdr *get_udp(struct ip *pip, void **pplast);

int gethdr_length(struct ip *pip, void *plast);
int get_payload_length(struct ip *pip, void *plast);

#endif /* _TCT_IPV6 */

#include "ipv6.h"
#include "error.h"
#include "macros.h"

char *findheader_ipv6(void *pplast, struct ip *pip, unsigned int *proto_type)
{
	struct ipv6_ext *pdef;
	struct ipv6 *ipv6;
	int next_header;
	char *next_header6;

	ipv6 = (struct ipv6 *) pip;

	next_header = ipv6->ip6_nheader;
	*proto_type = next_header;
	next_header6 = ((char *) pip) + 40;

	while ((void *) next_header6 < pplast) {
		switch (next_header) {
		case IPPROTO_TCP:
			//fprintf (fp_stdout, "next header: %d \n",next_header);
			return (next_header6);
			break;
		case IPPROTO_UDP:
			return (next_header6);
			break;
		case IPPROTO_ICMPV6:
			return (next_header6);
			break;

		case IPPROTO_FRAGMENT:
			{
				struct ipv6_ext_frag *pfrag =
				    (struct ipv6_ext_frag *) next_header6;

				if ((pfrag->ip6ext_fr_offset & 0xfc) != 0) {
#if DEBUG > 1
	err_msg("findheader_ipv6: Skipping IPv6 non-initial fragment\n");
#endif
					return (NULL);
				}

				next_header = (int) pfrag->ip6ext_fr_nheader;
				next_header6 =
				    (char *) (next_header6 +
					      pfrag->ip6ext_fr_res);
				break;
			}
		case IPPROTO_NONE:
		case IPPROTO_HOPOPTS:
		case IPPROTO_ROUTING:
		case IPPROTO_DSTOPTS:
		default:
			pdef = (struct ipv6_ext *) next_header6;
			next_header = pdef->ip6ext_nheader;
			next_header6 =
			    (char *) (next_header6 + pdef->ip6ext_len);
			return NULL;
			break;
		}
	}

	return NULL;

}

/*
 * get_tcp:  return a pointer to a tcp header.
 * Skips either ip or ipv6 headers
 */
static void *findheader(u_int ipproto, struct ip *pip, void **pplast)
{
	void *theheader;
	unsigned int proto_type;

	if (PIP_ISV6(pip)) {
		theheader = findheader_ipv6(*pplast, pip, &proto_type);
		if (proto_type != ipproto)
			return NULL;
		else
			return theheader;
	} else
		/* IPv4 is easy */
	if (PIP_ISV4(pip)) {
		/* make sure it's what we want */
		if (pip->ip_p != ipproto) {
			return NULL;
		}

		/* check the fragment field, if it's not the first fragment,
		   it's useless (offset part of field must be 0 */
		if ((ntohs(pip->ip_off) & 0x1fff) != 0) {
#if DEBUG > 1
	err_msg("gettcp: Skipping IPv4 non-initial fragment\n");
#endif
			return NULL;
		}

		/* OK, it starts here */
		theheader = ((char *) pip + 4 * pip->ip_hl);

		/* adjust plast in accordance with ip_len (really short packets get garbage) */
		if (((unsigned long) pip + ntohs(pip->ip_len) - 1) <
		    (unsigned long) (*pplast)) {
			*pplast =
			    (void *) ((unsigned long) pip + ntohs(pip->ip_len));
		}

		return (theheader);
	} else
		return NULL;
}


/*
 * gettcp:  return a pointer to a tcp header.
 * Skips either ip or ipv6 headers
 */
struct tcphdr *get_tcp(struct ip *pip, void **pplast)
{
	struct tcphdr *ptcp;
	ptcp = (struct tcphdr *) findheader(IPPROTO_TCP, pip, pplast);
	return (ptcp);
}

/*
 * getudp:  return a pointer to a udp header.
 * Skips either ip or ipv6 headers
 */
struct udphdr *get_udp(struct ip *pip, void **pplast)
{
	struct udphdr *pudp;
	pudp = (struct udphdr *) findheader(IPPROTO_UDP, pip, pplast);
	return (pudp);
}

/* 
 * gethdrlength: returns the length of the header in the case of ipv4
 *               returns the length of all the headers in the case of ipv6
 */
int gethdr_length(struct ip *pip, void *plast)
{
	int length, nextheader;
	char *pheader;
	struct ipv6 *pipv6;

	if (PIP_ISV6(pip)) {
		length = 40;

		pheader = (char *) pip;
		nextheader = *(pheader + 6);
		pheader += 40;

		pipv6 = (struct ipv6 *) pip;
		while (1) {
			if (nextheader == IPPROTO_NONE)
				return length;
			if (nextheader == IPPROTO_TCP)
				return length;
			if (nextheader == IPPROTO_UDP)
				return length;
			if (nextheader == IPPROTO_FRAGMENT) {
				nextheader = *pheader;
				pheader += 8;
				length += 8;
			}
			if ((nextheader == IPPROTO_HOPOPTS)
			    || (nextheader == IPPROTO_ROUTING)
			    || (nextheader == IPPROTO_DSTOPTS)) {
				nextheader = *pheader;
				pheader += *(pheader + 1);
				length += *(pheader + 1);
			}
			if (pheader > (char *) plast)
				return -1;
		}
	} else {
		return pip->ip_hl * 4;
	}
}

/*
 * getpayloadlength: returns the length of the packet without the header.
 */
int get_payload_length(struct ip *pip, void *plast)
{
	struct ipv6 *pipv6;

	if (PIP_ISV6(pip)) {
		pipv6 = (struct ipv6 *) pip;	/* how about all headers */
		return ntohs(pipv6->ip6_lngth);
	}

	return ntohs(pip->ip_len) - (pip->ip_hl * 4);
}


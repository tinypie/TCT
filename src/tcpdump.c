// this file and this header is from tcptrace, I really thanks to the authers 
/*------------------------------------------------------------*/
#include "tct.h"
#include "tcpdump.h"

#define EH_SIZE sizeof(struct ether_header)

/* 
 * globle local variable
 */
struct ether_header eth_header;
static char *ip_buf;
static void *callback_plast;
struct pcap_pkthdr pcap_current_hdr;

/*
 * Read from file to buffer (stolen form tcpdump)
 */
char *read_infile(char *fname)
{
	int fd, cc;
	char *cp;
	struct stat buf;

	fd = open(fname, O_RDONLY);
	if (fd < 0) {
		printf("can't open %s: %s", fname, pcap_strerror(errno));
		exit(1);
	}

	if (fstat(fd, &buf) < 0) {
		printf("can't stat %s: %s", fname, pcap_strerror(errno));
		exit(1);
	}

	cp = malloc((u_int) buf.st_size + 1);
	if (cp == NULL) {
		printf("malloc(%d) for %s: %s", (u_int) buf.st_size + 1, fname, pcap_strerror(errno));
		exit(1);
	}
	cc = read(fd, cp, (u_int) buf.st_size);
	if (cc < 0) {
		printf("read %s: %s", fname, pcap_strerror(errno));
		exit(1);
	}
	if (cc != buf.st_size) {
		printf("short read %s (%d != %d)", fname, cc, (int) buf.st_size);
		exit(1);
	}
	cp[(int) buf.st_size] = '\0';

	return (cp);
}

/*
 * Copy a 2D array (like argv) into a flat string. (Stolen from tcpdum)
 *
 * Return: Pointer to the flat string
 */
char *copy_argv(char **argv)
{
	char **p;
	u_int len = 0;
	char *buf;
	char *src, *dst;
	void ftlerr(char *, ...);

	p = argv;
	if (*p == 0)
		return 0;

	while (*p)
		len += strlen(*p++) + 1;

	buf = (char *) malloc(len);

	if (buf == NULL) {
		printf("copy_argv: malloc() failed: %s\n", strerror(errno));
		exit(1);
	}
	p = argv;
	dst = buf;

	while ((src = *p++) != NULL) {
		while ((*dst++ = *src++) != '\0')
			;
		dst[-1] = ' ';
	}

	dst[-1] = '\0';

	return buf;
}

void init_filter(pcap_t *handle, char *argv[])
{
	char errbuf[PCAP_ERRBUF_SIZE];	/* error string */
	struct bpf_program fp;		/* the compiled filter */
	bpf_u_int32 localnet, netmask;	/* our netip and netmask */

	char *filter_string = NULL;
	char *filter = NULL;

	/* put it in a blocking mode */
	/*
	 * in "non-blocking" an attemp to read from the capture descriptor with pcap_dispatch()
	 * will, if no packets are currently available to be read, return 0 immediately rather than
	 * blocking waiting for packets to arrive. So we set it to blocking mode to wait if there are 
	 * no packets arraiving currently.
	 */
	/* because save files couldn't be put into non block mode, it has no effect on savefiles */
	if (tct_opts.work_mode == MODE_REALTIME) {		
		if (pcap_setnonblock(handle, 0, errbuf) < 0) {
			err_quit("pcap_setnonblock failed %s\n", pcap_geterr(handle));
		}
	}

	/* set the filter */
	if (tct_opts.filter_file) {
		filter= read_infile(tct_opts.filter_file);
	} else {
		filter= copy_argv(&argv[optind]);
	}
	
	/* filter of IP packet only, now */
	if (filter != NULL) {
		filter_string = (char *) malloc(strlen(filter)+10);
		sprintf(filter_string, "ip and (%s)", filter);
		/* to avoid memory leak */
		free(filter);
	} else {
		filter_string = (char *) malloc(10);
		sprintf(filter_string, "ip");
	}
#if DEBUG > 3
	printf("filter command %s\n", filter_string);
#endif
	if (pcap_lookupnet(tct_opts.device, &localnet, &netmask, errbuf) == -1) {
		err_msg("pcaf coultn't get netmask for device:%s. because of %s\n", tct_opts.device, errbuf);
		netmask = 0;
		localnet = 0;
	}
	
	if (pcap_compile(handle, &fp, filter_string, 1, netmask) == -1) {
		err_msg("pcap compile failed %s", pcap_geterr(handle));
		pcap_close(handle);
		exit(-1);
	}
	
	if (pcap_setfilter(handle, &fp) == -1) {
		err_quit("pcap_setfilter failed %s", pcap_geterr(handle));
	}

	if (filter_string != NULL)
		free(filter_string);
}

/*
 * to find the link type and is use memory to allocat memory for ip_buf
 */
char *link_type(int type )
{
	char *pstr = "unknow";
	switch (type) {
	case 100:	/* fall througth */
	case PCAP_DLT_EN10MB:
		pstr = "Ethernet";
		break;
	case PCAP_DLT_IEEE802:
		/* just pretend it's normal ethernet */
		pstr = "Ethernet";
		break;
	case PCAP_DLT_SLIP:
		pstr = "Slip";
		break;
	case PCAP_DLT_PPP:
		pstr = "PPP or HDLC PPP";
		break;
	case PCAP_DLT_FDDI:
		pstr = "FDDI";
		break;
	case PCAP_DLT_NULL:
		pstr = "NULL";
		break;
	case PCAP_DLT_ATM_RFC1483:
		pstr = "ATM, LLC/SNAP encapsulated";
		break;
	case PCAP_DLT_RAW:
		pstr = "RAW_IP";
		break;
	case PCAP_DLT_LINUX_SLL:
		pstr = "Linux Cooked Socket";
		break;
	case PCAP_DLT_IEEE802_11:
		pstr = "IEEE802_11";
		break;
	case PCAP_DLT_IEEE802_11_RADIO:
		pstr = "IEEE802_11_RADIO";
		break;
	case PCAP_DLT_PRISM2:
		pstr = "PRISM2";
		break;
	case PCAP_DLT_C_HDLC:
		pstr = "Cisco HDLC";
		break;
	default:
		err_msg("tcptrace did not understand link format (%d)!\n", type);
		err_quit("\t If you can give us a capture file with this link format\n\
			\t or even better, a patch to decipher this format, we shall add it in, \n\
			\t in a future release.\n");
	}

#ifdef USE_MEMCPY
	ip_buf = (char *)malloc(IP_MAXPACKET);
#endif

	return strdup(pstr);
}

// find_ip_*( ) function I stolen from tcptrace program 
//
/* locate ip within FDDI according to RFC 1188 */
static int find_ip_fddi(unsigned char *buf, int iplen)
{
	unsigned char *ptr, *ptr2;
	int i;
	u_char pattern[] = { 0xAA, 0x03, 0x00, 0x00, 0x00, 0x08, 0x00 };
#define FDDIPATTERNLEN 7

	ptr = ptr2 = buf;

	for (i = 0; i < FDDIPATTERNLEN; i++) {
		ptr2 = memchr(ptr, pattern[i], (iplen - (int) (ptr - buf)));
		if (!ptr2)
			return (-1);
		if (i && (ptr2 != ptr)) {
			ptr2 = ptr2 - i - 1;
			i = -1;
		}
		ptr = ptr2 + 1;
	}
	return (ptr2 - buf + 1);

}

/* This function determine the offset for the IP packet in an Ethernet frame */
/* We handle two cases : straight Ethernet encapsulation or PPPoE encapsulation */
/* Written by Yann Samama (ysamama@nortelnetworks.com) on july 18th, 2003 */
int find_ip_eth(unsigned char *buf)
{
	unsigned short ppp_proto_type;	/* the protocol type field of the PPP header */
	unsigned short eth_proto_type;	/* the protocol type field of the Ethernet header */
	unsigned short vlan_proto_type;	/* the protocol type field of the VLAN header */
	int offset = -1;	/* the calculated offset that this function will return */
#ifndef USE_MEMCPY
	uint16_t *ptype;	/* pointer at the location of the field in the buffer */
#endif

#ifdef USE_MEMCPY
	memcpy(&eth_proto_type, buf + 12, 2);
	eth_proto_type = ntohs(eth_proto_type);
#else
	ptype = (uint16_t *) (buf + 12);
	eth_proto_type = ntohs(*ptype);
#endif

	switch (eth_proto_type) {
	case ETHERTYPE_IPV6:	/* it's pure IPv6 over ethernet */
		offset = 14;
		break;
	case ETHERTYPE_IP:	/* it's pure IPv4 over ethernet */
		offset = 14;
		break;
	case ETHERTYPE_PPPOE_SESSION:	/* it's a PPPoE session */
#ifdef USE_MEMCPY
		memcpy(&ppp_proto_type, buf + 20, 2);
		ppp_proto_type = ntohs(ppp_proto_type);
#else
		ptype = (uint16_t *) (buf + 20);
		ppp_proto_type = ntohs(*ptype);
#endif
		if (ppp_proto_type == 0x0021)	/* it's IP over PPPoE */
			offset = PPPOE_SIZE;
		break;
	case ETHERTYPE_8021Q:
		offset = 18;
#ifdef USE_MEMCPY
		memcpy(&vlan_proto_type, buf + 16, 2);
		vlan_proto_type = ntohs(vlan_proto_type);
#else
		ptype = (uint16_t *) (buf + 16);
		vlan_proto_type = ntohs(*ptype);
#endif
		if (vlan_proto_type == ETHERTYPE_MPLS) {	/* it's MPLS over VLAN */
			offset += 4;	/* Skip 4 bytes of MPLS label */
		}
		break;
	case ETHERTYPE_MPLS:	/* it's IP over MPLS over Eth - skip 4 bytes of MPLS label */
		offset = 18;
		break;

	default:		/* well, this is not an IP packet */
		offset = -1;
		break;
	}
	return offset;
}

/* This function determine the offset for the IP packet in a PPP or HDLC PPP frame */
/* Written by Yann Samama (ysamama@nortelnetworks.com) on june 19th, 2003 */
static int find_ip_ppp(unsigned char *buf)
{
	unsigned char ppp_byte0;	/* the first byte of the PPP frame */
	unsigned short ppp_proto_type;	/* the protocol type field of the PPP header */
	int offset = -1;	/* the calculated offset that this function will return */
#ifndef USE_MEMCPY
	uint16_t *ptype;	/* pointer at the location of the field in the buffer */
#endif

#ifdef USE_MEMCPY
	memcpy(&ppp_byte0, buf, 1);
#else
	ppp_byte0 = buf[0];
#endif
	switch (ppp_byte0) {
	case 0xff:		/* It is HDLC PPP encapsulation (2 bytes for HDLC and 2 bytes for PPP) */
#ifdef USE_MEMCPY
		memcpy(&ppp_proto_type, buf + 2, 2);
		ppp_proto_type = ntohs(ppp_proto_type);
#else
		ptype = (uint16_t *) (buf + 2);
		ppp_proto_type = ntohs(*ptype);
#endif
		if (ppp_proto_type == 0x21)	/* That means HDLC PPP is encapsulating IP */
			offset = 4;
		else		/* That means PPP is *NOT* encapsulating IP */
			offset = -1;
		break;

	case 0x0f:		/* It is raw CISCO HDLC encapsulation of IP */
		offset = 4;
		break;

	case 0x21:		/* It is raw PPP encapsulation of IP with compressed (1 byte) protocol field */
		offset = 1;
		break;

	case 0x00:		/* It is raw PPP encapsulation */
#ifdef USE_MEMCPY
		memcpy(&ppp_proto_type, buf, 2);
		ppp_proto_type = ntohs(ppp_proto_type);
#else
		ptype = (uint16_t *) (buf);
		ppp_proto_type = ntohs(*ptype);
#endif
		if (ppp_proto_type == 0x21)	/* It is raw PPP encapsulation of IP with uncompressed (2 bytes) protocol field */
			offset = 2;
		else		/* That means PPP is *NOT* encapsulating IP */
			offset = -1;
		break;

	default:		/* There is certainly not an IP packet there ... */
		offset = -1;
		break;
	}
	return offset;
}

static int callback(char *user, struct pcap_pkthdr *phdr, unsigned char *buf)
{
	int type, iplen;
	static int offset = -1;
	struct ether_header *ptr_eth_header;

	pcap_t *pcap = (pcap_t *)user;

	iplen = phdr->caplen;
	if (iplen > IP_MAXPACKET)	/* 65535 */
		iplen = IP_MAXPACKET;
	
	type = pcap_datalink(pcap);

	/* remember the stuff we always save */
	pcap_current_hdr = *phdr;

	/* kind of ugly, but about the only way to make them fit together :-(  */
	switch (type) {
	case 100:
		/* for some reason, the windows version of tcpdump is using */
		/* this.  It looks just like ethernet to me */
	case PCAP_DLT_EN10MB:
		offset = find_ip_eth(buf);	/* Here we check if we are dealing with Straight Ethernet encapsulation or PPPoE */
		iplen -= offset;
#ifdef USE_MEMCPY
		memcpy(&eth_header, buf, EH_SIZE);	/* save ether header */
#else
		ptr_eth_header = (struct ether_header *)buf;
		eth_header.ether_type = ptr_eth_header->ether_type;	/*save ether type */
#endif

		switch (offset) {
		case -1:	/* Not an IP packet */
			return (-1);
		case EH_SIZE:	/* straight Ethernet encapsulation */
#ifdef USE_MEMCPY
			memcpy((char *) ip_buf, buf + offset, iplen);
#else
			ip_buf = (char *) (buf + offset);
#endif
			callback_plast = ip_buf + iplen - 1;
			break;
		case PPPOE_SIZE:	/* PPPoE encapsulation */
			//case MPLS8021Q_SIZE:          /* VLAN-MPLS encapsulation - same len*/
			/* we use a fake ether type here */
			eth_header.ether_type = htons(ETHERTYPE_IP);
#ifdef USE_MEMCPY
			memcpy((char *) ip_buf, buf + offset, iplen);
#else
			ip_buf = (char *) (buf + offset);
#endif
			callback_plast = ip_buf + iplen - 1;
			break;
		case IEEE8021Q_SIZE:	/* VLAN encapsulation */
			//case MPLS_SIZE:                       /* MPLS encapsulation - same len*/
			/* we use a fake ether type here */
			eth_header.ether_type = htons(ETHERTYPE_IP);
#ifdef USE_MEMCPY
			memcpy((char *) ip_buf, buf + offset, iplen);
#else
			ip_buf = (char *) (buf + offset);
#endif
			callback_plast = ip_buf + iplen - 1;
			break;
		default:	/* should not be used, but we never know ... */
			return (-1);
		}
		break;
	case PCAP_DLT_IEEE802:
		/* just pretend it's "normal" ethernet */
		offset = 14;	/* 22 bytes of IEEE cruft */
#ifdef USE_MEMCPY
		memcpy(&eth_header, buf, EH_SIZE);	/* save ether header */
#else
		ptr_eth_header = (struct ether_header *)buf;
		eth_header.ether_type = ptr_eth_header->ether_type;	/*save ether type */
#endif

		iplen -= offset;
#ifdef USE_MEMCPY
		memcpy(ip_buf, buf + offset, iplen);
#else
		ip_buf = (char *) (buf + offset);
#endif
		callback_plast = (char *) ip_buf + iplen - 1;
		break;
	case PCAP_DLT_SLIP:
#ifdef USE_MEMCPY
		memcpy(ip_buf, buf + 16, iplen);
#else
		ip_buf = (char *) (buf + 16);
#endif
		iplen -= 16;
		callback_plast = (char *) ip_buf + iplen - 1;
		break;
	case PCAP_DLT_PPP:
		/* deals with raw PPP and also with HDLC PPP frames */
		offset = find_ip_ppp(buf);
		if (offset < 0)	/* Not an IP packet */
			return (-1);
		iplen -= offset;
#ifdef USE_MEMCPY
		memcpy((char *) ip_buf, buf + offset, iplen);
#else
		ip_buf = (char *) (buf + offset);
#endif
		callback_plast = ip_buf + iplen - 1;
		break;
	case PCAP_DLT_FDDI:
		if (offset < 0)
			offset = find_ip_fddi(buf, iplen);
		if (offset < 0)
			return (-1);
		iplen -= offset;
#ifdef USE_MEMCPY
		memcpy((char *) ip_buf, buf + offset, iplen);
#else
		ip_buf = (char *) (buf + offset);
#endif
		callback_plast = ip_buf + iplen - 1;
		break;
	case PCAP_DLT_NULL:
		/* no phys header attached */
		offset = 4;
		iplen -= offset;
#ifdef USE_MEMCPY
		memcpy((char *) ip_buf, buf + offset, iplen);
#else
		ip_buf = (char *) (buf + offset);
#endif
		callback_plast = ip_buf + iplen - 1;
		/* we use a fake ether type here */
		eth_header.ether_type = htons(ETHERTYPE_IP);
		break;
	case PCAP_DLT_ATM_RFC1483:
		/* ATM RFC1483 - LLC/SNAP ecapsulated atm */
		iplen -= 8;
#ifdef USE_MEMCPY
		memcpy((char *) ip_buf, buf + 8, iplen);
#else
		ip_buf = (char *) (buf + 8);
#endif
		callback_plast = ip_buf + iplen - 1;
		break;
	case PCAP_DLT_RAW:
		/* raw IP */
		offset = 0;
		iplen -= offset;
#ifdef USE_MEMCPY
		memcpy((char *) ip_buf, buf + offset, iplen);
#else
		ip_buf = (char *) (buf + offset);
#endif
		callback_plast = ip_buf + iplen - 1;
		break;
	case PCAP_DLT_LINUX_SLL:
		/* linux cooked socket */
		offset = 16;
		iplen -= offset;
#ifdef USE_MEMCPY
		memcpy((char *) ip_buf, buf + offset, iplen);
#else
		ip_buf = (char *) (buf + offset);
#endif
		callback_plast = ip_buf + iplen - 1;
		break;
		// Patch sent by Brandon Eisenamann to passby 802.11, LLC/SNAP
		// and Prism2 headers to get to the IP packet.
	case PCAP_DLT_IEEE802_11:
		offset = 24 + 8;	// 802.11 header + LLC/SNAP header
		iplen -= offset;
#ifdef USE_MEMCPY
		memcpy((char *) ip_buf, buf + offset, iplen);
#else
		ip_buf = (char *) (buf + offset);
#endif
		callback_plast = ip_buf + iplen - 1;
		break;
	case PCAP_DLT_IEEE802_11_RADIO:
		offset = 64 + 24;	//WLAN header + 802.11 header
		iplen -= offset;
#ifdef USE_MEMCPY
		memcpy(&eth_header, buf, EH_SIZE);	// save ethernet header
		memcpy((char *) ip_buf, buf + offset, iplen);
#else
		ptr_eth_header = (struct ether_header *)buf;
		eth_header.ether_type = ptr_eth_header->ether_type;
		ip_buf = (char *) (buf + offset);
#endif
		callback_plast = ip_buf + iplen - 1;
		break;
	case PCAP_DLT_PRISM2:
		offset = 144 + 24 + 8;	// PRISM2+IEEE 802.11+ LLC/SNAP headers
		iplen -= offset;
#ifdef USE_MEMCPY
		memcpy((char *) ip_buf, buf + offset, iplen);
#else
		ip_buf = (char *) (buf + offset);
#endif
		callback_plast = ip_buf + iplen - 1;
		break;
	case PCAP_DLT_C_HDLC:
		offset = 4;
		iplen -= offset;
#ifdef USE_MEMCPY
		memcpy((char *) ip_buf, buf + offset, iplen);
#else
		ip_buf = (char *) (buf + offset);
#endif
		callback_plast = (char *) ip_buf + iplen - 1;
		break;
	default:
		err_quit("Don't understand link-level format (%d)\n", type);
	}


	/* if need to dump traffic from link level */
	if (tct_opts.write_mode == 1) {
		if (tct_gb.dumpd == NULL) {
			err_quit("dump handle not open \n");
		}
		pcap_dump((u_char *)tct_gb.dumpd, phdr, buf);
	}
	return 0;
}
/*
 * mainly from tcptrace 
 * Called pcap_dipatch and got the pointer to struct ip and the last bytes in 
 * the capture buff.
 * @ptime --> store the timestample of the packet
 * @pclen --> capture length. 
 * @ppip --> pointer to struct ip
 * @pplast --> pointer to the last byte 
 */
int pread_tcpdump(
	pcap_t 		*handle, 	/* is the handle of the pcap */
	struct timeval	*ptime,		/* the timestamp of of the packet */
	int		*pclen,
	struct ip	**ppip,
	void		**pplast)
{
	int ret;
	char *err;
	while (1) {
		ret = pcap_dispatch(handle, 1, (pcap_handler)callback, (u_char *)handle);

		if (ret != 1) {		/* prob eof */
			if (ret == -1) {
				err = pcap_geterr(handle);
				if (err && *err)
					err_msg("pcap error:%s\n", pcap_geterr(handle));

				/* else, it's just EOF */
				return -1;
			}

			/* in live capture is just a packet filter by kernel */
			if (tct_opts.work_mode == MODE_REALTIME)
				continue;

			/* from a file ==> EOF */
			return 0;
		}

		/* at least one tcpdump implementation (AIX) seems to be */
		/* storing NANOseconds in the usecs field of the timestamp. */
		/* This confuses EVERYTHING.  Try to compensate. */
		{
			static int bogus_nanoseconds = 0;
			if ((pcap_current_hdr.ts.tv_usec >= US_PER_SEC)
			    || (bogus_nanoseconds)) {
				if (!bogus_nanoseconds) {
					fprintf(stderr,
						"tcpdump: attempting to adapt to bogus nanosecond timestamps\n");
					bogus_nanoseconds = 1;
				}
				pcap_current_hdr.ts.tv_usec /= 1000;
			}
		}

		/* fill in all of the return values */

		*ppip = (struct ip *) ip_buf;
		*pplast = callback_plast;	/* last byte in IP packet */
		/* (copying time structure in 2 steps to avoid RedHat brain damage) */
		ptime->tv_usec = pcap_current_hdr.ts.tv_usec;
		ptime->tv_sec = pcap_current_hdr.ts.tv_sec;
	//	*plen = pcap_current_hdr.len;
		*pclen = pcap_current_hdr.caplen;

		/* if it's not IP, then skip it check in TCP/IP mode  l2 */
		if ((ntohs(eth_header.ether_type) != ETHERTYPE_IP) &&
		    (ntohs(eth_header.ether_type) != ETHERTYPE_IPV6)) {
#if DEBUG > 2
	err_msg("pread_tcpdump: not an IP packet\n");
#endif
			continue;
		}
		return (1);
	}
}
/*------------------------------------------------------------*/

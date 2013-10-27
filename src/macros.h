#ifndef _TCT_MACRO
#define _TCT_MACRO

/*
 * macro functions to process packet 
 */

/* Macros to simplify access to IPv4/IPv6 header fields */
#define PIP_VERS(pip) (((struct ip *)(pip))->ip_v)
#define PIP_ISV6(pip) (PIP_VERS(pip) == 6)
#define PIP_ISV4(pip) (PIP_VERS(pip) == 4)

#define PIP_V6(pip) ((struct ipv6 *)(pip))
#define PIP_V4(pip) ((struct ip *)(pip))
#define PIP_EITHERFIELD(pip,fld4,fld6) \
   (PIP_ISV4(pip)?(PIP_V4(pip)->fld4):(PIP_V6(pip)->fld6))
#define PIP_LEN(pip) (PIP_EITHERFIELD(pip,ip_len,ip6_lngth))


#define ZERO_TIME(ptr)	(((ptr)->tv_sec == 0) && ((ptr)->tv_usec == 0))

/* Bit operations: r = register, b = bit mask, v = value (0|1) */
#define SET_BIT(r,b,v)			((v == 1) ? (r |= b) : (r &= ~b))
#define TEST_BIT(r,b,v)			((v == 1) ? ((r & b) == b) : ((r & b) == 0))

#define TIME2DOUBLE(t) ((double)(t).tv_sec * 1000000 + (double)(t).tv_usec)

#endif /* _TCT_MACRO */

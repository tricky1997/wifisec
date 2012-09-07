#include "common.h"
#include "prototypes.h"



#ifndef HAVE_GETADDRINFO

#ifndef EAI_MEMORY
#define EAI_MEMORY 1
#endif
#ifndef EAI_NONAME
#define EAI_NONAME 2
#endif
#ifndef EAI_SERVICE
#define EAI_SERVICE 8
#endif


#define getaddrinfo     local_getaddrinfo
#define freeaddrinfo    local_freeaddrinfo

static int getaddrinfo(const char *, const char *,
		       const struct addrinfo *, struct addrinfo **);
static int alloc_addresses(struct hostent *, const struct addrinfo *,
			   u_short port, struct addrinfo **,
			   struct addrinfo **);
static void freeaddrinfo(struct addrinfo *);

#endif 



int name2addr(SOCKADDR_UNION * addr, char *name, char *default_host)
{
	SOCKADDR_LIST addr_list;
	int retval;

	addr_list.num = 0;
	addr_list.addr = NULL;
	retval = name2addrlist(&addr_list, name, default_host);
	if (retval > 0)
		memcpy(addr, &addr_list.addr[0], sizeof *addr);
	if (addr_list.addr)
		str_free(addr_list.addr);
	return retval;
}

int name2addrlist(SOCKADDR_LIST * addr_list, char *name, char *default_host)
{
	char *tmp, *hostname, *portname;
	int retval;

	addr_list->cur = 0;	

	
#ifdef HAVE_STRUCT_SOCKADDR_UN
	if (*name == '/') {
		if (offsetof(struct sockaddr_un, sun_path) + strlen(name) + 1
		    > sizeof(struct sockaddr_un)) {
			s_log(LOG_ERR, "Unix socket path is too long");
			return 0;	
		}
		addr_list->addr = str_realloc(addr_list->addr,
					      (addr_list->num +
					       1) * sizeof(SOCKADDR_UNION));
		addr_list->addr[addr_list->num].un.sun_family = AF_UNIX;
		strcpy(addr_list->addr[addr_list->num].un.sun_path, name);
		return ++(addr_list->num);	
	}
#endif

	
	tmp = str_dup(name);
	portname = strrchr(tmp, ':');
	if (portname) {
		hostname = tmp;
		*portname++ = '\0';
	} else {		
		hostname = default_host;
		portname = tmp;
	}

	
	retval = hostport2addrlist(addr_list, hostname, portname);
	str_free(tmp);
	return retval;
}

int hostport2addrlist(SOCKADDR_LIST * addr_list, char *hostname, char *portname)
{
	struct addrinfo hints, *res = NULL, *cur;
	int err;

	memset(&hints, 0, sizeof hints);
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	do {
		err = getaddrinfo(hostname, portname, &hints, &res);
		if (err && res)
			freeaddrinfo(res);
		if (err == EAI_AGAIN) {
			s_log(LOG_DEBUG,
			      "getaddrinfo: EAI_AGAIN received: retrying");
			sleep(1);
		}
	} while (err == EAI_AGAIN);
	switch (err) {
	case 0:
		break;		
	case EAI_SERVICE:
		s_log(LOG_ERR, "Unknown TCP service '%s'", portname);
		return 0;	
	default:
		s_log(LOG_ERR, "Error resolving '%s': %s",
		      hostname, s_gai_strerror(err));
		return 0;	
	}

	
	for (cur = res; cur; cur = cur->ai_next) {
		if (cur->ai_addrlen > (int)sizeof(SOCKADDR_UNION)) {
			s_log(LOG_ERR,
			      "INTERNAL ERROR: ai_addrlen value too big");
			freeaddrinfo(res);
			return 0;	
		}
		addr_list->addr = str_realloc(addr_list->addr,
					      (addr_list->num +
					       1) * sizeof(SOCKADDR_UNION));
		memcpy(&addr_list->addr[addr_list->num], cur->ai_addr,
		       cur->ai_addrlen);
		++(addr_list->num);
	}
	freeaddrinfo(res);
	return addr_list->num;	
}

char *s_ntop(SOCKADDR_UNION * addr, socklen_t addrlen)
{
	int err;
	char *host, *port, *retval;

	if (addrlen == sizeof(u_short))	
		return str_dup("unnamed socket");
	host = str_alloc(256);
	port = str_alloc(256);	
	err = getnameinfo(&addr->sa, addrlen,
			  host, 256, port, 256,
			  NI_NUMERICHOST | NI_NUMERICSERV);
	if (err) {
		s_log(LOG_ERR, "getnameinfo: %s", s_gai_strerror(err));
		retval = str_dup("unresolvable address");
	} else
		retval = str_printf("%s:%s", host, port);
	str_free(host);
	str_free(port);
	return retval;
}

socklen_t addr_len(const SOCKADDR_UNION * addr)
{
	if (addr->sa.sa_family == AF_INET)
		return sizeof(struct sockaddr_in);
	if (addr->sa.sa_family == AF_INET6)
		return sizeof(struct sockaddr_in6);
	if (addr->sa.sa_family == AF_UNIX)
		return sizeof(struct sockaddr_un);
	s_log(LOG_ERR, "INTERNAL ERROR: Unknown sa_family: %d",
	      addr->sa.sa_family);
	return sizeof(SOCKADDR_UNION);
}




const char *s_gai_strerror(int err)
{
	switch (err) {
#ifdef EAI_BADFLAGS
	case EAI_BADFLAGS:
		return "Invalid value for ai_flags (EAI_BADFLAGS)";
#endif
	case EAI_NONAME:
		return "Neither nodename nor servname known (EAI_NONAME)";
#ifdef EAI_AGAIN
	case EAI_AGAIN:
		return "Temporary failure in name resolution (EAI_AGAIN)";
#endif
#ifdef EAI_FAIL
	case EAI_FAIL:
		return "Non-recoverable failure in name resolution (EAI_FAIL)";
#endif
#ifdef EAI_NODATA
#if EAI_NODATA!=EAI_NONAME
	case EAI_NODATA:
		return "No address associated with nodename (EAI_NODATA)";
#endif 
#endif 
#ifdef EAI_FAMILY
	case EAI_FAMILY:
		return "ai_family not supported (EAI_FAMILY)";
#endif
#ifdef EAI_SOCKTYPE
	case EAI_SOCKTYPE:
		return "ai_socktype not supported (EAI_SOCKTYPE)";
#endif
#ifdef EAI_SERVICE
	case EAI_SERVICE:
		return
		    "servname is not supported for ai_socktype (EAI_SERVICE)";
#endif
#ifdef EAI_ADDRFAMILY
	case EAI_ADDRFAMILY:
		return
		    "Address family for nodename not supported (EAI_ADDRFAMILY)";
#endif 
	case EAI_MEMORY:
		return "Memory allocation failure (EAI_MEMORY)";
#ifdef EAI_SYSTEM
	case EAI_SYSTEM:
		return "System error returned in errno (EAI_SYSTEM)";
#endif 
	default:
		return "Unknown error";
	}
}



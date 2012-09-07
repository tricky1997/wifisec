#include "s_server.h"

#ifndef NO_STANDARD_RESOLVER
const int dnsUseGethostbyname = 3;
#else
#error use no resolver at all?
#endif

#ifndef NO_STANDARD_RESOLVER
int dnsGethostbynameTtl = 1200;
#endif

int dnsNegativeTtl = 120;

const int dnsQueryIPv6 = 0;

typedef struct _DnsQuery {
	unsigned id;
	AtomPtr name;
	ObjectPtr object;
	AtomPtr inet4, inet6;
	time_t ttl4, ttl6;
	time_t time;
	int timeout;
	TimeEventHandlerPtr timeout_handler;
	struct _DnsQuery *next;
} DnsQueryRec, *DnsQueryPtr;

union {
	struct sockaddr sa;
	struct sockaddr_in sin;
} nameserverAddress_storage;

static int really_do_gethostbyname(AtomPtr name, ObjectPtr object);
static int really_do_dns(AtomPtr name, ObjectPtr object);

void preinitDns()
{
	assert(sizeof(struct in_addr) == 4);

	CONFIG_VARIABLE(dnsGethostbynameTtl, CONFIG_TIME,
			"TTL for gethostbyname addresses.");
}

int
do_gethostbyname(char *origname,
		 int count,
		 int (*handler) (int, GethostbynameRequestPtr), void *data)
{
	ObjectPtr object;
	int n = strlen(origname);
	AtomPtr name;
	GethostbynameRequestRec request;
	int done, rc;

	memset(&request, 0, sizeof(request));
	request.name = NULL;
	request.addr = NULL;
	request.error_message = NULL;
	request.count = count;
	request.handler = handler;
	request.data = data;

	if (n <= 0 || n > 131) {
		if (n <= 0) {
			request.error_message = internAtom("empty name");
			do_log(L_ERROR, "Empty DNS name.\n");
			done = handler(-EINVAL, &request);
		} else {
			request.error_message = internAtom("name too long");
			do_log(L_ERROR, "DNS name too long.\n");
			done = handler(-ENAMETOOLONG, &request);
		}
		assert(done);
		releaseAtom(request.error_message);
		return 1;
	}

	if (origname[n - 1] == '.')
		n--;

	name = internAtomLowerN(origname, n);

	if (name == NULL) {
		request.error_message = internAtom("couldn't allocate name");
		do_log(L_ERROR, "Couldn't allocate DNS name.\n");
		done = handler(-ENOMEM, &request);
		assert(done);
		releaseAtom(request.error_message);
		return 1;
	}

	request.name = name;
	request.addr = NULL;
	request.error_message = NULL;
	request.count = count;
	request.object = NULL;
	request.handler = handler;
	request.data = data;

	object = findObject(OBJECT_DNS, name->string, name->length);
	if (object == NULL || objectMustRevalidate(object, NULL)) {
		if (object) {
			privatiseObject(object, 0);
			releaseObject(object);
		}
		object =
		    makeObject(OBJECT_DNS, name->string, name->length, 1, 0,
			       NULL, NULL);
		if (object == NULL) {
			request.error_message =
			    internAtom("Couldn't allocate object");
			do_log(L_ERROR, "Couldn't allocate DNS object.\n");
			done = handler(-ENOMEM, &request);
			assert(done);
			releaseAtom(name);
			releaseAtom(request.error_message);
			return 1;
		}
	}

	if ((object->flags & (OBJECT_INITIAL | OBJECT_INPROGRESS)) ==
	    OBJECT_INITIAL) {
		if (dnsUseGethostbyname >= 3)
			rc = really_do_gethostbyname(name, object);
		else
			rc = really_do_dns(name, object);
		if (rc < 0) {
			assert(!
			       (object->flags &
				(OBJECT_INITIAL | OBJECT_INPROGRESS)));
			goto fail;
		}
	}

	if (dnsUseGethostbyname >= 3)
		assert(!(object->flags & OBJECT_INITIAL));

	if (object->headers && object->headers->length > 0) {
		if (object->headers->string[0] == DNS_A)
			assert(((object->headers->length - 1) %
				sizeof(HostAddressRec)) == 0);
		else
			assert(object->headers->string[0] == DNS_CNAME);
		request.addr = retainAtom(object->headers);
	} else if (object->message) {
		request.error_message = retainAtom(object->message);
	}

	releaseObject(object);

	if (request.addr && request.addr->length > 0)
		done = handler(1, &request);
	else
		done = handler(-EDNS_HOST_NOT_FOUND, &request);
	assert(done);

	releaseAtom(request.addr);
	request.addr = NULL;
	releaseAtom(request.name);
	request.name = NULL;
	releaseAtom(request.error_message);
	request.error_message = NULL;
	return 1;

      fail:
	releaseNotifyObject(object);
	done = handler(-errno, &request);
	assert(done);
	releaseAtom(name);
	return 1;
}

static int really_do_gethostbyname(AtomPtr name, ObjectPtr object)
{
	struct hostent *host;
	char *s;
	AtomPtr a;
	int i, j;
	int error;

	host = gethostbyname(name->string);
	if (host == NULL) {
		switch (h_errno) {
		case HOST_NOT_FOUND:
			error = EDNS_HOST_NOT_FOUND;
			break;
		case NO_ADDRESS:
			error = EDNS_NO_ADDRESS;
			break;
		case NO_RECOVERY:
			error = EDNS_NO_RECOVERY;
			break;
		case TRY_AGAIN:
			error = EDNS_TRY_AGAIN;
			break;
		default:
			error = EUNKNOWN;
			break;
		}
		if (error == EDNS_HOST_NOT_FOUND) {
			object->headers = NULL;
			object->age = current_time.tv_sec;
			object->expires = current_time.tv_sec + dnsNegativeTtl;
			object->flags &= ~(OBJECT_INITIAL | OBJECT_INPROGRESS);
			object->flags &= ~OBJECT_INPROGRESS;
			notifyObject(object);
			return 0;
		} else {
			do_log_error(L_ERROR, error, "Gethostbyname failed ");
			abortObject(object, 404,
				    internAtomError(error,
						    "Gethostbyname failed"));
			object->flags &= ~OBJECT_INPROGRESS;
			notifyObject(object);
			return 0;
		}
	}
	if (host->h_addrtype != AF_INET) {
		do_log(L_ERROR, "Address is not AF_INET.\n");
		object->flags &= ~OBJECT_INPROGRESS;
		abortObject(object, 404, internAtom("Address is not AF_INET"));
		notifyObject(object);
		return -1;
	}
	if (host->h_length != sizeof(struct in_addr)) {
		do_log(L_ERROR, "Address size inconsistent.\n");
		object->flags &= ~OBJECT_INPROGRESS;
		abortObject(object, 404,
			    internAtom("Address size inconsistent"));
		notifyObject(object);
		return 0;
	}
	i = 0;
	while (host->h_addr_list[i] != NULL)
		i++;
	s = malloc(1 + i * sizeof(HostAddressRec));
	if (s == NULL) {
		a = NULL;
	} else {
		memset(s, 0, 1 + i * sizeof(HostAddressRec));
		s[0] = DNS_A;
		for (j = 0; j < i; j++) {
			s[j * sizeof(HostAddressRec) + 1] = 4;
			memcpy(&s[j * sizeof(HostAddressRec) + 2],
			       host->h_addr_list[j], sizeof(struct in_addr));
		}
		a = internAtomN(s, i * sizeof(HostAddressRec) + 1);
		free(s);
	}
	if (!a) {
		object->flags &= ~OBJECT_INPROGRESS;
		abortObject(object, 501,
			    internAtom("Couldn't allocate address"));
		notifyObject(object);
		return 0;
	}
	object->headers = a;
	object->age = current_time.tv_sec;
	object->expires = current_time.tv_sec + dnsGethostbynameTtl;
	object->flags &= ~(OBJECT_INITIAL | OBJECT_INPROGRESS);
	notifyObject(object);
	return 0;

}

static int really_do_dns(AtomPtr name, ObjectPtr object)
{
	(void)name;
	(void)object;
	abort();
}


#define getpeername no_getpeername
#include <sys/types.h>
#include <sys/socket.h>		
#include <netinet/in.h>
#include <arpa/inet.h>		
#include <stdlib.h>		
#include <sys/socket.h>		
#undef getpeername

int getpeername(int s, struct sockaddr_in *name, int *len)
{
	char *value;

	(void)s;		
	(void)len;		
	name->sin_family = AF_INET;
	if ((value = getenv("REMOTE_HOST")))
		name->sin_addr.s_addr = inet_addr(value);
	else
		name->sin_addr.s_addr = htonl(INADDR_ANY);
	if ((value = getenv("REMOTE_PORT")))
		name->sin_port = htons(atoi(value));
	else
		name->sin_port = htons(0);	
	return 0;
}



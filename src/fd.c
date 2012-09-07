
#include "common.h"
#include "prototypes.h"

#if defined HAVE_PIPE2 && defined HAVE_ACCEPT4
#define USE_NEW_LINUX_API 1
#endif


#if !defined O_NONBLOCK && defined O_NDELAY
#define O_NONBLOCK O_NDELAY
#endif



static int setup_fd(int, int, char *);



int s_socket(int domain, int type, int protocol, int nonblock, char *msg)
{
#ifdef USE_NEW_LINUX_API
	if (nonblock)
		type |= SOCK_NONBLOCK;
	type |= SOCK_CLOEXEC;
#endif
	return setup_fd(socket(domain, type, protocol), nonblock, msg);
}

int s_accept(int sockfd, struct sockaddr *addr, socklen_t * addrlen,
	     int nonblock, char *msg)
{
	int fd;

#ifdef USE_NEW_LINUX_API
	if (nonblock)
		fd = accept4(sockfd, addr, addrlen,
			     SOCK_NONBLOCK | SOCK_CLOEXEC);
	else
		fd = accept4(sockfd, addr, addrlen, SOCK_CLOEXEC);
#else
	fd = accept(sockfd, addr, addrlen);
#endif
	return setup_fd(fd, nonblock, msg);
}

int s_socketpair(int domain, int type, int protocol, int sv[2],
		 int nonblock, char *msg)
{
#ifdef USE_NEW_LINUX_API
	if (nonblock)
		type |= SOCK_NONBLOCK;
	type |= SOCK_CLOEXEC;
#endif
	if (socketpair(domain, type, protocol, sv) < 0) {
		ioerror(msg);
		return -1;
	}
	if (setup_fd(sv[0], nonblock, msg) < 0) {
		closesocket(sv[1]);
		return -1;
	}
	if (setup_fd(sv[1], nonblock, msg) < 0) {
		closesocket(sv[0]);
		return -1;
	}
	return 0;
}

int s_pipe(int pipefd[2], int nonblock, char *msg)
{
	int retval;

#ifdef USE_NEW_LINUX_API
	if (nonblock)
		retval = pipe2(pipefd, O_NONBLOCK | O_CLOEXEC);
	else
		retval = pipe2(pipefd, O_CLOEXEC);
#else
	retval = pipe(pipefd);
#endif
	if (retval < 0) {
		ioerror(msg);
		return -1;
	}
	if (setup_fd(pipefd[0], nonblock, msg) < 0) {
		close(pipefd[1]);
		return -1;
	}
	if (setup_fd(pipefd[1], nonblock, msg) < 0) {
		close(pipefd[0]);
		return -1;
	}
	return 0;
}

static int setup_fd(int fd, int nonblock, char *msg)
{
#if !defined USE_NEW_LINUX_API && defined FD_CLOEXEC
	int err;
#endif

	if (fd < 0) {
		sockerror(msg);
		return -1;
	}
#ifdef USE_NEW_LINUX_API
	(void)nonblock;		
#else 
	set_nonblock(fd, nonblock);
#ifdef FD_CLOEXEC
	do {
		err = fcntl(fd, F_SETFD, FD_CLOEXEC);
	} while (err < 0 && get_last_socket_error() == S_EINTR);
	if (err < 0)
		sockerror("fcntl SETFD");	
#endif 
#endif 

#ifdef DEBUG_FD_ALLOC
	s_log(LOG_DEBUG, "%s: FD=%d allocated (%sblocking mode)",
	      msg, fd, nonblock ? "non-" : "");
#endif 

	return fd;
}

void set_nonblock(int fd, unsigned long nonblock)
{
#if defined F_GETFL && defined F_SETFL && defined O_NONBLOCK && !defined __INNOTEK_LIBC__
	int err, flags;

	do {
		flags = fcntl(fd, F_GETFL, 0);
	} while (flags < 0 && get_last_socket_error() == S_EINTR);
	if (flags < 0) {
		sockerror("fcntl GETFL");	
		return;
	}
	if (nonblock)
		flags |= O_NONBLOCK;
	else
		flags &= ~O_NONBLOCK;
	do {
		err = fcntl(fd, F_SETFL, flags);
	} while (err < 0 && get_last_socket_error() == S_EINTR);
	if (err < 0)
		sockerror("fcntl SETFL");	
#else 
	if (ioctlsocket(fd, FIONBIO, &nonblock) < 0)
		sockerror("ioctlsocket");	
#endif
}



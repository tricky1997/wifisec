#include "common.h"
#include "prototypes.h"





s_poll_set *s_poll_alloc()
{
	
	return str_alloc(sizeof(s_poll_set));
}

void s_poll_free(s_poll_set * fds)
{
	if (fds) {
		if (fds->ufds)
			str_free(fds->ufds);
		str_free(fds);
	}
}

void s_poll_init(s_poll_set * fds)
{
	fds->nfds = 0;
	fds->allocated = 4;	
	fds->ufds =
	    str_realloc(fds->ufds, fds->allocated * sizeof(struct pollfd));
}


void s_poll_add(s_poll_set * fds, int fd, int rd, int wr)
{
	unsigned int i;

	for (i = 0; i < fds->nfds && fds->ufds[i].fd != fd; i++) ;
	if (i == fds->nfds) {
		if (i == fds->allocated) {
			fds->allocated = i + 1;
			fds->ufds =
			    str_realloc(fds->ufds,
					fds->allocated * sizeof(struct pollfd));
		}
		fds->ufds[i].fd = fd;
		fds->ufds[i].events = 0;
		fds->nfds++;
	}
	if (rd)
		fds->ufds[i].events |= POLLIN;
	if (wr)
		fds->ufds[i].events |= POLLOUT;
}

int s_poll_canread(s_poll_set * fds, int fd)
{
	unsigned int i;

	for (i = 0; i < fds->nfds; i++)
		if (fds->ufds[i].fd == fd)
			return fds->ufds[i].revents & (POLLIN | POLLHUP);	
	return 0;
}

int s_poll_canwrite(s_poll_set * fds, int fd)
{
	unsigned int i;

	for (i = 0; i < fds->nfds; i++)
		if (fds->ufds[i].fd == fd)
			return fds->ufds[i].revents & POLLOUT;	
	return 0;
}

int s_poll_error(s_poll_set * fds, FD * s)
{
	unsigned int i;

	if (!s->is_socket)
		return 0;
	for (i = 0; i < fds->nfds; i++)
		if (fds->ufds[i].fd == s->fd)
			return fds->ufds[i].revents & (POLLERR | POLLNVAL) ?
			    get_socket_error(s->fd) : 0;
	return 0;
}

int s_poll_wait(s_poll_set * fds, int sec, int msec)
{
	int retval;

	do {			
		retval =
		    poll(fds->ufds, fds->nfds,
			 sec < 0 ? -1 : 1000 * sec + msec);
	} while (retval < 0 && get_last_socket_error() == S_EINTR);
	return retval;
}



int set_socket_options(int s, int type)
{
	SOCK_OPT *ptr;
	extern SOCK_OPT sock_opts[];
	static char *type_str[3] = { "accept", "local", "remote" };
	int opt_size;
	int retval = 0;		

	for (ptr = sock_opts; ptr->opt_str; ptr++) {
		if (!ptr->opt_val[type])
			continue;	
		switch (ptr->opt_type) {
		case TYPE_LINGER:
			opt_size = sizeof(struct linger);
			break;
		case TYPE_TIMEVAL:
			opt_size = sizeof(struct timeval);
			break;
		case TYPE_STRING:
			opt_size = strlen(ptr->opt_val[type]->c_val) + 1;
			break;
		default:
			opt_size = sizeof(int);
		}
		if (setsockopt(s, ptr->opt_level, ptr->opt_name,
			       (void *)ptr->opt_val[type], opt_size)) {
			if (get_last_socket_error() == S_EOPNOTSUPP) {
				
				s_log(LOG_DEBUG,
				      "Option %s not supported on %s socket",
				      ptr->opt_str, type_str[type]);
			} else {
				sockerror(ptr->opt_str);
				retval = -1;	
			}
		}
#ifdef DEBUG_FD_ALLOC
		else {
			s_log(LOG_DEBUG, "Option %s set on %s socket",
			      ptr->opt_str, type_str[type]);
		}
#endif 
	}
	return retval;		
}

int get_socket_error(const int fd)
{
	int err;
	socklen_t optlen = sizeof err;

	if (getsockopt(fd, SOL_SOCKET, SO_ERROR, (void *)&err, &optlen))
		err = get_last_socket_error();	
	return err;
}



int connect_blocking(CLI * c, SOCKADDR_UNION * addr, socklen_t addrlen)
{
	int error;
	char *dst;

	dst = s_ntop(addr, addrlen);
	s_log(LOG_INFO, "connect_blocking: connecting %s", dst);

	if (!connect(c->fd, &addr->sa, addrlen)) {
		s_log(LOG_NOTICE, "connect_blocking: connected %s", dst);
		str_free(dst);
		return 0;	
	}
	error = get_last_socket_error();
	if (error != S_EINPROGRESS && error != S_EWOULDBLOCK) {
		s_log(LOG_ERR, "connect_blocking: connect %s: %s (%d)",
		      dst, s_strerror(error), error);
		str_free(dst);
		return -1;
	}

	s_log(LOG_DEBUG, "connect_blocking: s_poll_wait %s: waiting %d seconds",
	      dst, c->opt->timeout_connect);
	s_poll_init(c->fds);
	s_poll_add(c->fds, c->fd, 1, 1);
	switch (s_poll_wait(c->fds, c->opt->timeout_connect, 0)) {
	case -1:
		error = get_last_socket_error();
		s_log(LOG_ERR, "connect_blocking: s_poll_wait %s: %s (%d)",
		      dst, s_strerror(error), error);
		str_free(dst);
		return -1;
	case 0:
		s_log(LOG_ERR, "connect_blocking: s_poll_wait %s:"
		      " TIMEOUTconnect exceeded", dst);
		str_free(dst);
		return -1;
	default:
		error = get_socket_error(c->fd);
		if (error) {
			s_log(LOG_ERR, "connect_blocking: connect %s: %s (%d)",
			      dst, s_strerror(error), error);
			str_free(dst);
			return -1;
		}
		if (s_poll_canwrite(c->fds, c->fd)) {
			s_log(LOG_NOTICE, "connect_blocking: connected %s",
			      dst);
			str_free(dst);
			return 0;	
		}
		s_log(LOG_ERR,
		      "connect_blocking: s_poll_wait %s: internal error", dst);
		str_free(dst);
		return -1;
	}
	return -1;		
}

void write_blocking(CLI * c, int fd, void *ptr, int len)
{
	
	int num;

	while (len > 0) {
		s_poll_init(c->fds);
		s_poll_add(c->fds, fd, 0, 1);	
		switch (s_poll_wait(c->fds, c->opt->timeout_busy, 0)) {
		case -1:
			sockerror("write_blocking: s_poll_wait");
			longjmp(c->err, 1);	
		case 0:
			s_log(LOG_INFO, "write_blocking: s_poll_wait:"
			      " TIMEOUTbusy exceeded: sending reset");
			longjmp(c->err, 1);	
		case 1:
			break;	
		default:
			s_log(LOG_ERR,
			      "write_blocking: s_poll_wait: unknown result");
			longjmp(c->err, 1);	
		}
		num = writesocket(fd, ptr, len);
		switch (num) {
		case -1:	
			sockerror("writesocket (write_blocking)");
			longjmp(c->err, 1);
		}
		ptr = (u8 *) ptr + num;
		len -= num;
	}
}

void read_blocking(CLI * c, int fd, void *ptr, int len)
{
	
	int num;

	while (len > 0) {
		s_poll_init(c->fds);
		s_poll_add(c->fds, fd, 1, 0);	
		switch (s_poll_wait(c->fds, c->opt->timeout_busy, 0)) {
		case -1:
			sockerror("read_blocking: s_poll_wait");
			longjmp(c->err, 1);	
		case 0:
			s_log(LOG_INFO, "read_blocking: s_poll_wait:"
			      " TIMEOUTbusy exceeded: sending reset");
			longjmp(c->err, 1);	
		case 1:
			break;	
		default:
			s_log(LOG_ERR,
			      "read_blocking: s_poll_wait: unknown result");
			longjmp(c->err, 1);	
		}
		num = readsocket(fd, ptr, len);
		switch (num) {
		case -1:	
			sockerror("readsocket (read_blocking)");
			longjmp(c->err, 1);
		case 0:	
			s_log(LOG_ERR,
			      "Unexpected socket close (read_blocking)");
			longjmp(c->err, 1);
		}
		ptr = (u8 *) ptr + num;
		len -= num;
	}
}

void fd_putline(CLI * c, int fd, const char *line)
{
	char *tmpline;
	const char crlf[] = "\r\n";
	int len;

	tmpline = str_printf("%s%s", line, crlf);
	len = strlen(tmpline);
	write_blocking(c, fd, tmpline, len);
	tmpline[len - 2] = '\0';	
	safestring(tmpline);
	s_log(LOG_DEBUG, " -> %s", tmpline);
	str_free(tmpline);
}

char *fd_getline(CLI * c, int fd)
{
	char *line = NULL, *tmpline;
	int ptr = 0;

	for (;;) {
		s_poll_init(c->fds);
		s_poll_add(c->fds, fd, 1, 0);	
		switch (s_poll_wait(c->fds, c->opt->timeout_busy, 0)) {
		case -1:
			sockerror("fd_getline: s_poll_wait");
			str_free(line);
			longjmp(c->err, 1);	
		case 0:
			s_log(LOG_INFO, "fd_getline: s_poll_wait:"
			      " TIMEOUTbusy exceeded: sending reset");
			str_free(line);
			longjmp(c->err, 1);	
		case 1:
			break;	
		default:
			s_log(LOG_ERR,
			      "fd_getline: s_poll_wait: Unknown result");
			str_free(line);
			longjmp(c->err, 1);	
		}
		line = str_realloc(line, ptr + 1);
		switch (readsocket(fd, line + ptr, 1)) {
		case -1:	
			sockerror("fd_getline: readsocket");
			str_free(line);
			longjmp(c->err, 1);
		case 0:	
			s_log(LOG_ERR, "fd_getline: Unexpected socket close");
			str_free(line);
			longjmp(c->err, 1);
		}
		if (line[ptr] == '\r')
			continue;
		if (line[ptr] == '\n')
			break;
		if (line[ptr] == '\0')
			break;
		if (++ptr > 65536) {	
			s_log(LOG_ERR, "fd_getline: Line too long");
			str_free(line);
			longjmp(c->err, 1);
		}
	}
	line[ptr] = '\0';
	tmpline = str_dup(line);
	safestring(tmpline);
	s_log(LOG_DEBUG, " <- %s", tmpline);
	str_free(tmpline);
	return line;
}

void fd_printf(CLI * c, int fd, const char *format, ...)
{
	va_list ap;
	char *line;

	va_start(ap, format);
	line = str_vprintf(format, ap);
	va_end(ap);
	if (!line) {
		s_log(LOG_ERR, "fd_printf: str_vprintf failed");
		longjmp(c->err, 1);
	}
	fd_putline(c, fd, line);
	str_free(line);
}



int make_sockets(int fd[2])
{				
	if (s_socketpair
	    (AF_UNIX, SOCK_STREAM, 0, fd, 1, "make_sockets: socketpair"))
		return 1;
	return 0;
}



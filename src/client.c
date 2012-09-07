#include "common.h"
#include "prototypes.h"

#ifndef SHUT_RD
#define SHUT_RD 0
#endif
#ifndef SHUT_WR
#define SHUT_WR 1
#endif
#ifndef SHUT_RDWR
#define SHUT_RDWR 2
#endif

static void client_try(CLI *);
static void client_run(CLI *);
static void init_local(CLI *);
static void init_remote(CLI *);
static void init_ssl(CLI *);
static void transfer(CLI *);
static int parse_socket_error(CLI *, const char *);

static void print_cipher(CLI *);
static void auth_user(CLI *, char *);
static int connect_remote(CLI *);
static SOCKADDR_LIST *dynamic_remote_addr(CLI *);
static void local_bind(CLI * c);
static void print_bound_address(CLI *);
static void reset(int, char *);


CLI *alloc_client_session(SERVICE_OPTIONS * opt, int rfd, int wfd)
{
	CLI *c;

	c = str_alloc(sizeof(CLI));
	str_detach(c);
	c->opt = opt;
	c->local_rfd.fd = rfd;
	c->local_wfd.fd = wfd;
	return c;
}

void *client_thread(void *arg)
{
	CLI *c = arg;

#ifdef DEBUG_STACK_SIZE
	stack_info(1);		
#endif
	client_main(c);
#ifdef DEBUG_STACK_SIZE
	stack_info(0);		
#endif
	str_stats();
	str_cleanup();
	
	return NULL;
}

void client_main(CLI * c)
{
	s_log(LOG_DEBUG, "Service [%s] started", c->opt->servname);
	client_run(c);
	str_free(c);
}

static void client_run(CLI * c)
{
	int error;

	c->remote_fd.fd = -1;
	c->fd = -1;
	c->ssl = NULL;
	c->sock_bytes = c->ssl_bytes = 0;
	c->fds = s_poll_alloc();
	c->connect_addr.num = 0;
	c->connect_addr.addr = NULL;

	error = setjmp(c->err);
	if (!error)
		client_try(c);

	s_log(LOG_NOTICE,
	      "Connection %s: %d byte(s) sent to SSL, %d byte(s) sent to socket",
	      error == 1 ? "reset" : "closed", c->ssl_bytes, c->sock_bytes);

	
	if (c->fd >= 0)
		closesocket(c->fd);
	c->fd = -1;

	
	if (c->ssl) {		
		SSL_set_shutdown(c->ssl,
				 SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN);
		SSL_free(c->ssl);
		c->ssl = NULL;
		ERR_remove_state(0);
	}

	
	if (c->remote_fd.fd >= 0) {	
		if (error == 1 && c->remote_fd.is_socket)	
			reset(c->remote_fd.fd, "linger (remote)");
		closesocket(c->remote_fd.fd);
		s_log(LOG_DEBUG, "Remote socket (FD=%d) closed",
		      c->remote_fd.fd);
		c->remote_fd.fd = -1;
	}

	
	if (c->local_rfd.fd >= 0) {	
		if (c->local_rfd.fd == c->local_wfd.fd) {
			if (error == 1 && c->local_rfd.is_socket)
				reset(c->local_rfd.fd, "linger (local)");
			closesocket(c->local_rfd.fd);
			s_log(LOG_DEBUG, "Local socket (FD=%d) closed",
			      c->local_rfd.fd);
		} else {	
			if (error == 1 && c->local_rfd.is_socket)
				reset(c->local_rfd.fd, "linger (local_rfd)");
			if (error == 1 && c->local_wfd.is_socket)
				reset(c->local_wfd.fd, "linger (local_wfd)");
		}
		c->local_rfd.fd = c->local_wfd.fd = -1;
	}

	s_log(LOG_DEBUG, "Service [%s] finished", c->opt->servname);

	
	if (c->connect_addr.addr)
		str_free(c->connect_addr.addr);
	s_poll_free(c->fds);
	c->fds = NULL;
}

static void client_try(CLI * c)
{
	init_local(c);
	if (!c->opt->option.client) {
		init_ssl(c);
		init_remote(c);
	} else {
		init_remote(c);
		init_ssl(c);
	}
	transfer(c);
}

static void init_local(CLI * c)
{
	SOCKADDR_UNION addr;
	socklen_t addr_len;
	char *accepted_address;

	
	addr_len = sizeof(SOCKADDR_UNION);
	c->local_rfd.is_socket =
	    !getpeername(c->local_rfd.fd, &addr.sa, &addr_len);
	if (c->local_rfd.is_socket) {
		memcpy(&c->peer_addr.sa, &addr.sa, addr_len);
		c->peer_addr_len = addr_len;
		if (set_socket_options(c->local_rfd.fd, 1))
			s_log(LOG_WARNING,
			      "Failed to set local socket options");
	} else {
		if (get_last_socket_error() != S_ENOTSOCK) {
			sockerror("getpeerbyname (local_rfd)");
			longjmp(c->err, 1);
		}
	}

	
	if (c->local_rfd.fd == c->local_wfd.fd) {
		c->local_wfd.is_socket = c->local_rfd.is_socket;
	} else {
		addr_len = sizeof(SOCKADDR_UNION);
		c->local_wfd.is_socket =
		    !getpeername(c->local_wfd.fd, &addr.sa, &addr_len);
		if (c->local_wfd.is_socket) {
			if (!c->local_rfd.is_socket) {	
				memcpy(&c->peer_addr.sa, &addr.sa, addr_len);
				c->peer_addr_len = addr_len;
			}
			if (set_socket_options(c->local_wfd.fd, 1))
				s_log(LOG_WARNING,
				      "Failed to set local socket options");
		} else {
			if (get_last_socket_error() != S_ENOTSOCK) {
				sockerror("getpeerbyname (local_wfd)");
				longjmp(c->err, 1);
			}
		}
	}

	
	if (!c->local_rfd.is_socket && !c->local_rfd.is_socket) {
		s_log(LOG_NOTICE, "Service [%s] accepted connection",
		      c->opt->servname);
		return;
	}

	
	accepted_address = s_ntop(&c->peer_addr, c->peer_addr_len);
	auth_user(c, accepted_address);
	s_log(LOG_NOTICE, "Service [%s] accepted connection from %s",
	      c->opt->servname, accepted_address);
	str_free(accepted_address);
}

static void init_remote(CLI * c)
{
	
	if (c->opt->option.local)	
		c->bind_addr = &c->opt->source_addr;
	else
		c->bind_addr = NULL;	

	
	if (c->opt->option.remote) {	
		c->remote_fd.fd = connect_remote(c);
	} else {
		s_log(LOG_ERR, "INTERNAL ERROR: No target for remote socket");
		longjmp(c->err, 1);
	}

	c->remote_fd.is_socket = 1;	
	s_log(LOG_DEBUG, "Remote socket (FD=%d) initialized", c->remote_fd.fd);
	if (set_socket_options(c->remote_fd.fd, 2))
		s_log(LOG_WARNING, "Failed to set remote socket options");
}

static void init_ssl(CLI * c)
{
	int i, err;
	SSL_SESSION *old_session;

	c->ssl = SSL_new(c->opt->ctx);
	if (!c->ssl) {
		sslerror("SSL_new");
		longjmp(c->err, 1);
	}
	SSL_set_ex_data(c->ssl, cli_index, c);	
	if (c->opt->option.client) {
		if (c->opt->session) {
			SSL_set_session(c->ssl, c->opt->session);
		}
		SSL_set_fd(c->ssl, c->remote_fd.fd);
		SSL_set_connect_state(c->ssl);
	} else {
		if (c->local_rfd.fd == c->local_wfd.fd)
			SSL_set_fd(c->ssl, c->local_rfd.fd);
		else {
			
			SSL_set_rfd(c->ssl, c->local_rfd.fd);
			SSL_set_wfd(c->ssl, c->local_wfd.fd);
		}
		SSL_set_accept_state(c->ssl);
	}

	
	if (c->opt->option.client) {
		c->sock_rfd = &(c->local_rfd);
		c->sock_wfd = &(c->local_wfd);
		c->ssl_rfd = c->ssl_wfd = &(c->remote_fd);
	} else {
		c->sock_rfd = c->sock_wfd = &(c->remote_fd);
		c->ssl_rfd = &(c->local_rfd);
		c->ssl_wfd = &(c->local_wfd);
	}

	while (1) {
		if (c->opt->option.client)
			i = SSL_connect(c->ssl);
		else
			i = SSL_accept(c->ssl);

		err = SSL_get_error(c->ssl, i);
		if (err == SSL_ERROR_NONE)
			break;	
		if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
			s_poll_init(c->fds);
			s_poll_add(c->fds, c->ssl_rfd->fd,
				   err == SSL_ERROR_WANT_READ,
				   err == SSL_ERROR_WANT_WRITE);
			switch (s_poll_wait(c->fds, c->opt->timeout_busy, 0)) {
			case -1:
				sockerror("init_ssl: s_poll_wait");
				longjmp(c->err, 1);
			case 0:
				s_log(LOG_INFO, "init_ssl: s_poll_wait:"
				      " TIMEOUTbusy exceeded: sending reset");
				longjmp(c->err, 1);
			case 1:
				break;	
			default:
				s_log(LOG_ERR,
				      "init_ssl: s_poll_wait: unknown result");
				longjmp(c->err, 1);
			}
			continue;	
		}
		if (err == SSL_ERROR_SYSCALL) {
			switch (get_last_socket_error()) {
			case S_EINTR:
			case S_EWOULDBLOCK:
#if S_EAGAIN!=S_EWOULDBLOCK
			case S_EAGAIN:
#endif
				continue;
			}
		}
		if (c->opt->option.client)
			sslerror("SSL_connect");
		else
			sslerror("SSL_accept");
		longjmp(c->err, 1);
	}
	if (SSL_session_reused(c->ssl)) {
		s_log(LOG_INFO, "SSL %s: previous session reused",
		      c->opt->option.client ? "connected" : "accepted");
	} else {		
		if (c->opt->option.client) {
			s_log(LOG_INFO,
			      "SSL connected: new session negotiated");
			old_session = c->opt->session;
			c->opt->session = SSL_get1_session(c->ssl);	
			if (old_session)
				SSL_SESSION_free(old_session);	
		} else
			s_log(LOG_INFO, "SSL accepted: new session negotiated");
		print_cipher(c);
	}
}


static void transfer(CLI * c)
{
	int watchdog = 0;	
	int num, err;
	
	int sock_open_rd = 1, sock_open_wr = 1;
	
	int shutdown_wants_read = 0, shutdown_wants_write = 0;
	int read_wants_read, read_wants_write = 0;
	int write_wants_read = 0, write_wants_write;
	
	int sock_can_rd, sock_can_wr, ssl_can_rd, ssl_can_wr;

	c->sock_ptr = c->ssl_ptr = 0;

	do {			
	
		read_wants_read =
		    !(SSL_get_shutdown(c->ssl) & SSL_RECEIVED_SHUTDOWN)
		    && c->ssl_ptr < BUFFSIZE && !read_wants_write;
		write_wants_write =
		    !(SSL_get_shutdown(c->ssl) & SSL_SENT_SHUTDOWN)
		    && c->sock_ptr && !write_wants_read;

	
		s_poll_init(c->fds);	
		
		
		if (sock_open_rd)
			s_poll_add(c->fds, c->sock_rfd->fd,
				   c->sock_ptr < BUFFSIZE, 0);
		if (sock_open_wr)
			s_poll_add(c->fds, c->sock_wfd->fd, 0, c->ssl_ptr);
		
		if (read_wants_read || write_wants_read || shutdown_wants_read)
			s_poll_add(c->fds, c->ssl_rfd->fd, 1, 0);
		if (read_wants_write || write_wants_write
		    || shutdown_wants_write)
			s_poll_add(c->fds, c->ssl_wfd->fd, 0, 1);

	
		err = s_poll_wait(c->fds, (sock_open_rd &&	
					   !(SSL_get_shutdown(c->ssl) &
					     SSL_RECEIVED_SHUTDOWN))
				  || c->ssl_ptr	
				  ||
				  c->sock_ptr
				   ?
				  c->opt->timeout_idle : c->opt->timeout_close,
				  0);
		switch (err) {
		case -1:
			sockerror("transfer: s_poll_wait");
			longjmp(c->err, 1);
		case 0:	
			if ((sock_open_rd &&
			     !(SSL_get_shutdown(c->ssl) &
			       SSL_RECEIVED_SHUTDOWN)) || c->ssl_ptr
			    || c->sock_ptr) {
				s_log(LOG_INFO,
				      "transfer: s_poll_wait:"
				      " TIMEOUTidle exceeded: sending reset");
				longjmp(c->err, 1);
			} else {	
				s_log(LOG_ERR, "transfer: s_poll_wait:"
				      " TIMEOUTclose exceeded: closing");
				return;	
			}
		}

	
		err = s_poll_error(c->fds, c->sock_rfd);
		if (err) {
			s_log(LOG_NOTICE,
			      "Error detected on socket (read) file descriptor: %s (%d)",
			      s_strerror(err), err);
			longjmp(c->err, 1);
		}
		if (c->sock_wfd->fd != c->sock_rfd->fd) {	
			err = s_poll_error(c->fds, c->sock_wfd);
			if (err) {
				s_log(LOG_NOTICE,
				      "Error detected on socket write file descriptor: %s (%d)",
				      s_strerror(err), err);
				longjmp(c->err, 1);
			}
		}
		err = s_poll_error(c->fds, c->ssl_rfd);
		if (err) {
			s_log(LOG_NOTICE,
			      "Error detected on SSL (read) file descriptor: %s (%d)",
			      s_strerror(err), err);
			longjmp(c->err, 1);
		}
		if (c->ssl_wfd->fd != c->ssl_rfd->fd) {	
			err = s_poll_error(c->fds, c->ssl_wfd);
			if (err) {
				s_log(LOG_NOTICE,
				      "Error detected on SSL write file descriptor: %s (%d)",
				      s_strerror(err), err);
				longjmp(c->err, 1);
			}
		}

	
		sock_can_rd = s_poll_canread(c->fds, c->sock_rfd->fd);
		sock_can_wr = s_poll_canwrite(c->fds, c->sock_wfd->fd);
		ssl_can_rd = s_poll_canread(c->fds, c->ssl_rfd->fd);
		ssl_can_wr = s_poll_canwrite(c->fds, c->ssl_wfd->fd);

	
		if (!(sock_can_rd || sock_can_wr || ssl_can_rd || ssl_can_wr)) {
			s_log(LOG_ERR, "INTERNAL ERROR: "
			      "s_poll_wait returned %d, but no descriptor is ready",
			      err);
			longjmp(c->err, 1);
		}

	
		if (shutdown_wants_read || shutdown_wants_write) {
			num = SSL_shutdown(c->ssl);	
			if (num < 0)	
				err = SSL_get_error(c->ssl, num);
			else	
				err = SSL_ERROR_NONE;
			switch (err) {
			case SSL_ERROR_NONE:	
				s_log(LOG_INFO,
				      "SSL_shutdown successfully sent close_notify alert");
				shutdown_wants_read = shutdown_wants_write = 0;
				break;
			case SSL_ERROR_SYSCALL:	
				if (parse_socket_error(c, "SSL_shutdown"))
					break;	
				SSL_set_shutdown(c->ssl,
						 SSL_SENT_SHUTDOWN |
						 SSL_RECEIVED_SHUTDOWN);
				shutdown_wants_read = shutdown_wants_write = 0;
				break;
			case SSL_ERROR_WANT_WRITE:
				s_log(LOG_DEBUG,
				      "SSL_shutdown returned WANT_WRITE: retrying");
				shutdown_wants_read = 0;
				shutdown_wants_write = 1;
				break;
			case SSL_ERROR_WANT_READ:
				s_log(LOG_DEBUG,
				      "SSL_shutdown returned WANT_READ: retrying");
				shutdown_wants_read = 1;
				shutdown_wants_write = 0;
				break;
			case SSL_ERROR_SSL:	
				sslerror("SSL_shutdown");
				longjmp(c->err, 1);
			default:
				s_log(LOG_ERR,
				      "SSL_shutdown/SSL_get_error returned %d",
				      err);
				longjmp(c->err, 1);
			}
		}

	
		if (sock_open_rd && sock_can_rd) {
			num = readsocket(c->sock_rfd->fd,
					 c->sock_buff + c->sock_ptr,
					 BUFFSIZE - c->sock_ptr);
			switch (num) {
			case -1:
				if (parse_socket_error(c, "readsocket"))
					break;	
			case 0:	
				s_log(LOG_DEBUG, "Socket closed on read");
				sock_open_rd = 0;
				break;
			default:
				c->sock_ptr += num;
				watchdog = 0;	
			}
		}

	
		if (sock_open_wr && sock_can_wr) {
			num =
			    writesocket(c->sock_wfd->fd, c->ssl_buff,
					c->ssl_ptr);
			switch (num) {
			case -1:	
				if (parse_socket_error(c, "writesocket"))
					break;	
			case 0:
				s_log(LOG_DEBUG, "Socket closed on write");
				sock_open_rd = sock_open_wr = 0;
				break;
			default:
				memmove(c->ssl_buff, c->ssl_buff + num,
					c->ssl_ptr - num);
				c->ssl_ptr -= num;
				c->sock_bytes += num;
				watchdog = 0;	
			}
		}

	
		
		read_wants_read =
		    !(SSL_get_shutdown(c->ssl) & SSL_RECEIVED_SHUTDOWN)
		    && c->ssl_ptr < BUFFSIZE && !read_wants_write;
		write_wants_write =
		    !(SSL_get_shutdown(c->ssl) & SSL_SENT_SHUTDOWN)
		    && c->sock_ptr && !write_wants_read;

	
		if ((read_wants_read && (ssl_can_rd || SSL_pending(c->ssl))) ||
		    (read_wants_write && ssl_can_wr)) {
			read_wants_write = 0;
			num =
			    SSL_read(c->ssl, c->ssl_buff + c->ssl_ptr,
				     BUFFSIZE - c->ssl_ptr);
			switch (err = SSL_get_error(c->ssl, num)) {
			case SSL_ERROR_NONE:
				if (num == 0)
					s_log(LOG_DEBUG, "SSL_read returned 0");
				c->ssl_ptr += num;
				watchdog = 0;	
				break;
			case SSL_ERROR_WANT_WRITE:
				s_log(LOG_DEBUG,
				      "SSL_read returned WANT_WRITE: retrying");
				read_wants_write = 1;
				break;
			case SSL_ERROR_WANT_READ:	
				break;
			case SSL_ERROR_WANT_X509_LOOKUP:
				s_log(LOG_DEBUG,
				      "SSL_read returned WANT_X509_LOOKUP: retrying");
				break;
			case SSL_ERROR_SYSCALL:
				if (num && parse_socket_error(c, "SSL_read"))
					break;	
				if (c->sock_ptr) {
					s_log(LOG_ERR,
					      "SSL socket closed on SSL_read with %d unsent byte(s)",
					      c->sock_ptr);
					longjmp(c->err, 1);	
				}
				s_log(LOG_DEBUG,
				      "SSL socket closed on SSL_read");
				SSL_set_shutdown(c->ssl,
						 SSL_SENT_SHUTDOWN |
						 SSL_RECEIVED_SHUTDOWN);
				break;
			case SSL_ERROR_ZERO_RETURN:	
				s_log(LOG_DEBUG, "SSL closed on SSL_read");
				if (SSL_version(c->ssl) == SSL2_VERSION)
					SSL_set_shutdown(c->ssl,
							 SSL_SENT_SHUTDOWN |
							 SSL_RECEIVED_SHUTDOWN);
				break;
			case SSL_ERROR_SSL:
				sslerror("SSL_read");
				longjmp(c->err, 1);
			default:
				s_log(LOG_ERR,
				      "SSL_read/SSL_get_error returned %d",
				      err);
				longjmp(c->err, 1);
			}
		}

	
		if ((write_wants_read && ssl_can_rd) ||
		    (write_wants_write && ssl_can_wr)) {
			write_wants_read = 0;
			num = SSL_write(c->ssl, c->sock_buff, c->sock_ptr);
			switch (err = SSL_get_error(c->ssl, num)) {
			case SSL_ERROR_NONE:
				if (num == 0)
					s_log(LOG_DEBUG,
					      "SSL_write returned 0");
				memmove(c->sock_buff, c->sock_buff + num,
					c->sock_ptr - num);
				c->sock_ptr -= num;
				c->ssl_bytes += num;
				watchdog = 0;	
				break;
			case SSL_ERROR_WANT_WRITE:	
				break;
			case SSL_ERROR_WANT_READ:
				s_log(LOG_DEBUG,
				      "SSL_write returned WANT_READ: retrying");
				write_wants_read = 1;
				break;
			case SSL_ERROR_WANT_X509_LOOKUP:
				s_log(LOG_DEBUG,
				      "SSL_write returned WANT_X509_LOOKUP: retrying");
				break;
			case SSL_ERROR_SYSCALL:	
				if (num && parse_socket_error(c, "SSL_write"))
					break;	
				if (c->sock_ptr) {
					s_log(LOG_ERR,
					      "SSL socket closed on SSL_write with %d unsent byte(s)",
					      c->sock_ptr);
					longjmp(c->err, 1);	
				}
				s_log(LOG_DEBUG,
				      "SSL socket closed on SSL_write");
				SSL_set_shutdown(c->ssl,
						 SSL_SENT_SHUTDOWN |
						 SSL_RECEIVED_SHUTDOWN);
				break;
			case SSL_ERROR_ZERO_RETURN:	
				s_log(LOG_DEBUG, "SSL closed on SSL_write");
				if (SSL_version(c->ssl) == SSL2_VERSION)
					SSL_set_shutdown(c->ssl,
							 SSL_SENT_SHUTDOWN |
							 SSL_RECEIVED_SHUTDOWN);
				break;
			case SSL_ERROR_SSL:
				sslerror("SSL_write");
				longjmp(c->err, 1);
			default:
				s_log(LOG_ERR,
				      "SSL_write/SSL_get_error returned %d",
				      err);
				longjmp(c->err, 1);
			}
		}

	
		if (sock_open_wr
		    && SSL_get_shutdown(c->ssl) & SSL_RECEIVED_SHUTDOWN
		    && !c->ssl_ptr) {
			sock_open_wr = 0;	
			if (!c->sock_wfd->is_socket) {
				s_log(LOG_DEBUG,
				      "Closing the socket file descriptor");
				sock_open_rd = 0;	
			} else if (!shutdown(c->sock_wfd->fd, SHUT_WR)) {	
				s_log(LOG_DEBUG, "Sent socket write shutdown");
			} else {
				s_log(LOG_DEBUG,
				      "Failed to send socket write shutdown");
				sock_open_rd = 0;	
			}
		}
		if (!(SSL_get_shutdown(c->ssl) & SSL_SENT_SHUTDOWN)
		    && !sock_open_rd && !c->sock_ptr) {
			if (SSL_version(c->ssl) != SSL2_VERSION) {	
				s_log(LOG_DEBUG, "Sending close_notify alert");
				shutdown_wants_write = 1;
			} else {	
				s_log(LOG_DEBUG, "Closing SSLv2 socket");
				if (c->ssl_rfd->is_socket)
					shutdown(c->ssl_rfd->fd, SHUT_RD);	
				if (c->ssl_wfd->is_socket)
					shutdown(c->ssl_wfd->fd, SHUT_WR);	
				
				SSL_set_shutdown(c->ssl,
						 SSL_SENT_SHUTDOWN |
						 SSL_RECEIVED_SHUTDOWN);
			}
		}

	
		if (++watchdog > 100) {	
			s_log(LOG_ERR,
			      "transfer() loop executes not transferring any data");
			wifisec_info(LOG_ERR);
			s_log(LOG_ERR, "protocol=%s, SSL_pending=%d",
			      SSL_get_version(c->ssl), SSL_pending(c->ssl));
			s_log(LOG_ERR, "sock_open_rd=%s, sock_open_wr=%s",
			      sock_open_rd ? "Y" : "n",
			      sock_open_wr ? "Y" : "n");
			s_log(LOG_ERR,
			      "SSL_RECEIVED_SHUTDOWN=%s, SSL_SENT_SHUTDOWN=%s",
			      SSL_get_shutdown(c->ssl) & SSL_RECEIVED_SHUTDOWN ?
			      "Y" : "n",
			      SSL_get_shutdown(c->ssl) & SSL_SENT_SHUTDOWN ? "Y"
			      : "n");
			s_log(LOG_ERR, "sock_can_rd=%s, sock_can_wr=%s",
			      sock_can_rd ? "Y" : "n", sock_can_wr ? "Y" : "n");
			s_log(LOG_ERR, "ssl_can_rd=%s, ssl_can_wr=%s",
			      ssl_can_rd ? "Y" : "n", ssl_can_wr ? "Y" : "n");
			s_log(LOG_ERR,
			      "read_wants_read=%s, read_wants_write=%s",
			      read_wants_read ? "Y" : "n",
			      read_wants_write ? "Y" : "n");
			s_log(LOG_ERR,
			      "write_wants_read=%s, write_wants_write=%s",
			      write_wants_read ? "Y" : "n",
			      write_wants_write ? "Y" : "n");
			s_log(LOG_ERR,
			      "shutdown_wants_read=%s, shutdown_wants_write=%s",
			      shutdown_wants_read ? "Y" : "n",
			      shutdown_wants_write ? "Y" : "n");
			s_log(LOG_ERR,
			      "socket input buffer: %d byte(s), "
			      "ssl input buffer: %d byte(s)", c->sock_ptr,
			      c->ssl_ptr);
			longjmp(c->err, 1);
		}

	} while (sock_open_wr || !(SSL_get_shutdown(c->ssl) & SSL_SENT_SHUTDOWN)
		 || shutdown_wants_read || shutdown_wants_write);
}

    
static int parse_socket_error(CLI * c, const char *text)
{
	switch (get_last_socket_error()) {
		
	case 0:		
	case EPIPE:		
	case S_ECONNABORTED:
		s_log(LOG_INFO, "%s: Socket is closed", text);
		return 0;
	case S_EINTR:
		s_log(LOG_DEBUG, "%s: Interrupted by a signal: retrying", text);
		return 1;
	case S_EWOULDBLOCK:
		s_log(LOG_NOTICE, "%s: Would block: retrying", text);
		sleep(1);	
		return 1;
#if S_EAGAIN!=S_EWOULDBLOCK
	case S_EAGAIN:
		s_log(LOG_DEBUG,
		      "%s: Temporary lack of resources: retrying", text);
		return 1;
#endif
	default:
		sockerror(text);
		longjmp(c->err, 1);
	}
}

static void print_cipher(CLI * c)
{				
	SSL_CIPHER *cipher;
	const COMP_METHOD *compression, *expansion;


	if (global_options.debug_level < LOG_INFO)	
		return;
	cipher = (SSL_CIPHER *) SSL_get_current_cipher(c->ssl);
	s_log(LOG_INFO, "Negotiated %s ciphersuite: %s (%d-bit encryption)",
	      SSL_CIPHER_get_version(cipher), SSL_CIPHER_get_name(cipher),
	      SSL_CIPHER_get_bits(cipher, NULL));

#if OPENSSL_VERSION_NUMBER>=0x0090800fL
	compression = SSL_get_current_compression(c->ssl);
	expansion = SSL_get_current_expansion(c->ssl);
	s_log(LOG_INFO, "Compression: %s, expansion: %s",
	      compression ? SSL_COMP_get_name(compression) : "null",
	      expansion ? SSL_COMP_get_name(expansion) : "null");
#endif
}

static void auth_user(CLI * c, char *accepted_address)
{
	struct servent *s_ent;	
	SOCKADDR_UNION ident;	
	char *line, *type, *system, *user;

	if (!c->opt->username)
		return;		
	if (c->peer_addr.sa.sa_family == AF_UNIX) {
		s_log(LOG_INFO, "IDENT not supported on Unix sockets");
		return;
	}
	c->fd = s_socket(c->peer_addr.sa.sa_family, SOCK_STREAM,
			 0, 1, "socket (auth_user)");
	if (c->fd < 0)
		longjmp(c->err, 1);
	memcpy(&ident, &c->peer_addr, c->peer_addr_len);
	s_ent = getservbyname("auth", "tcp");
	if (s_ent) {
		ident.in.sin_port = s_ent->s_port;
	} else {
		s_log(LOG_WARNING, "Unknown service 'auth': using default 113");
		ident.in.sin_port = htons(113);
	}
	if (connect_blocking(c, &ident, addr_len(&ident)))
		longjmp(c->err, 1);
	s_log(LOG_DEBUG, "IDENT server connected");
	fd_printf(c, c->fd, "%u , %u",
		  ntohs(c->peer_addr.in.sin_port),
		  ntohs(c->opt->local_addr.in.sin_port));
	line = fd_getline(c, c->fd);
	closesocket(c->fd);
	c->fd = -1;		
	type = strchr(line, ':');
	if (!type) {
		s_log(LOG_ERR, "Malformed IDENT response");
		str_free(line);
		longjmp(c->err, 1);
	}
	*type++ = '\0';
	system = strchr(type, ':');
	if (!system) {
		s_log(LOG_ERR, "Malformed IDENT response");
		str_free(line);
		longjmp(c->err, 1);
	}
	*system++ = '\0';
	if (strcmp(type, " USERID ")) {
		s_log(LOG_ERR, "Incorrect INETD response type");
		str_free(line);
		longjmp(c->err, 1);
	}
	user = strchr(system, ':');
	if (!user) {
		s_log(LOG_ERR, "Malformed IDENT response");
		str_free(line);
		longjmp(c->err, 1);
	}
	*user++ = '\0';
	while (*user == ' ')	
		++user;
	if (strcmp(user, c->opt->username)) {
		safestring(user);
		s_log(LOG_WARNING,
		      "Connection from %s REFUSED by IDENT (user %s)",
		      accepted_address, user);
		str_free(line);
		longjmp(c->err, 1);
	}
	s_log(LOG_INFO, "IDENT authentication passed");
	str_free(line);
}


static int connect_remote(CLI * c)
{
	int fd, ind_try, ind_cur;
	SOCKADDR_LIST *remote_addr;	

	remote_addr = dynamic_remote_addr(c);
	
	for (ind_try = 0; ind_try < remote_addr->num; ind_try++) {
		if (c->opt->failover == FAILOVER_RR) {
			ind_cur = remote_addr->cur;
			
			remote_addr->cur = (ind_cur + 1) % remote_addr->num;
		} else {	
			ind_cur = ind_try;	
		}

		c->fd = s_socket(remote_addr->addr[ind_cur].sa.sa_family,
				 SOCK_STREAM, 0, 1, "remote socket");
		if (c->fd < 0)
			longjmp(c->err, 1);

		local_bind(c);	

		if (connect_blocking(c, &remote_addr->addr[ind_cur],
				     addr_len(&remote_addr->addr[ind_cur]))) {
			closesocket(c->fd);
			c->fd = -1;
			continue;	
		}
		print_bound_address(c);
		fd = c->fd;
		c->fd = -1;
		return fd;	
	}
	longjmp(c->err, 1);
	return -1;		
}

static SOCKADDR_LIST *dynamic_remote_addr(CLI * c)
{
	if (c->connect_addr.num)
		return &c->connect_addr;

	if (c->opt->option.delayed_lookup) {
		if (!name2addrlist(&c->connect_addr,
				   c->opt->connect_name, DEFAULT_LOOPBACK)) {
			s_log(LOG_ERR, "No host resolved");
			longjmp(c->err, 1);
		}
		return &c->connect_addr;
	}

	return &c->opt->connect_addr;	
}

static void local_bind(CLI * c)
{

	if (!c->bind_addr)
		return;
	if (ntohs(c->bind_addr->in.sin_port) >= 1024) {	
		
		if (!bind(c->fd, &c->bind_addr->sa, addr_len(c->bind_addr))) {
			s_log(LOG_INFO,
			      "local_bind succeeded on the original port");
			return;	
		}
		if (get_last_socket_error() != S_EADDRINUSE) {
			sockerror("local_bind (original port)");
			longjmp(c->err, 1);
		}
	}

	c->bind_addr->in.sin_port = htons(0);	
	if (!bind(c->fd, &c->bind_addr->sa, addr_len(c->bind_addr))) {
		s_log(LOG_INFO, "local_bind succeeded on an ephemeral port");
		return;		
	}
	sockerror("local_bind (ephemeral port)");
	longjmp(c->err, 1);
}

static void print_bound_address(CLI * c)
{
	char *txt;
	SOCKADDR_UNION addr;
	socklen_t addrlen = sizeof addr;

	if (global_options.debug_level < LOG_NOTICE)	
		return;
	memset(&addr, 0, addrlen);
	if (getsockname(c->fd, (struct sockaddr *)&addr, &addrlen)) {
		sockerror("getsockname");
		return;
	}
	txt = s_ntop(&addr, addrlen);
	s_log(LOG_NOTICE, "Service [%s] connected remote server from %s",
	      c->opt->servname, txt);
	str_free(txt);
}

static void reset(int fd, char *txt)
{				
	struct linger l;

	l.l_onoff = 1;
	l.l_linger = 0;
	if (setsockopt(fd, SOL_SOCKET, SO_LINGER, (void *)&l, sizeof l))
		log_error(LOG_DEBUG, get_last_socket_error(), txt);
}



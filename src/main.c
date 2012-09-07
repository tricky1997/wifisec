#include "common.h"
#include "prototypes.h"
#include "s_server.h"

static void start_sserver(void);
static void init_signals(void);
static int accept_connection(SERVICE_OPTIONS *);
static int change_root(void);
static int daemonize(int);
static int create_pid(void);
static void delete_pid(void);
static void signal_handler(int);
static int signal_pipe_init(void);
static int signal_pipe_dispatch(void);
static void client_status(void);	

static int signal_pipe[2] = { -1, -1 };

s_poll_set *fds;		


extern int proxyPort;



int main(int argc, char *argv[])
{				
	int retval;
	int fd;

	retval = 0;
	fd = open("/dev/null", O_RDWR);	
	if (fd < 0)
		fatal("Could not open /dev/null");
	main_initialize();

	if (main_configure(argc > 1 ? argv[1] : NULL, argc > 2 ? argv[2] : NULL)) {
		retval = 1;
		goto err;
	}

	if (service_options.next) {	
		if (daemonize(fd)) {
			retval = 1;
			goto err;
		}
		close(fd);
		if (create_pid()) {
			retval = 1;
			goto err;
		}
		init_signals();
		daemon_loop();
	}
err:
	unbind_ports();
	s_poll_free(fds);
	fds = NULL;
	str_stats();
	log_flush(LOG_MODE_ERROR);
	return retval;
}

void main_initialize()
{
	initAtoms();
	if (ssl_init())		
		fatal("SSL initialization failed");

	fds = s_poll_alloc();
	if (signal_pipe_init())
		fatal("Signal pipe initialization failed: "
		      "check your personal firewall");
	wifisec_info(LOG_NOTICE);
}


int main_configure(char *arg1, char *arg2)
{
	if (parse_commandline(arg1, arg2))
		return 1;

	if (service_options.next && !service_options.next->option.client) {
		start_sserver();
	}
	str_canary_init();
	syslog_open();
	if (bind_ports())
		return 1;
	if (change_root())
		return 1;
	if (drop_privileges(1))
		return 1;
	log_open();
	return 0;
}


void daemon_loop(void)
{
	SERVICE_OPTIONS *opt;
	int temporary_lack_of_resources;

	while (1) {
		temporary_lack_of_resources = 0;
		if (s_poll_wait(fds, -1, -1) >= 0) {
			if (s_poll_canread(fds, signal_pipe[0]))
				if (signal_pipe_dispatch())	
					break;	
			for (opt = service_options.next; opt; opt = opt->next)
				if (opt->option.accept
				    && s_poll_canread(fds, opt->fd))
					if (accept_connection(opt))
						temporary_lack_of_resources = 1;
		} else {
			log_error(LOG_NOTICE, get_last_socket_error(),
				  "daemon_loop: s_poll_wait");
			temporary_lack_of_resources = 1;
		}
		if (temporary_lack_of_resources) {
			s_log(LOG_NOTICE,
			      "Accepting new connections suspended for 1 second");
			sleep(1);	
		}
	}
}


static int accept_connection(SERVICE_OPTIONS * opt)
{
	SOCKADDR_UNION addr;
	char *from_address;
	int s;
	socklen_t addrlen;

	addrlen = sizeof addr;
	for (;;) {
		s = s_accept(opt->fd, &addr.sa, &addrlen, 1, "local socket");
		if (s >= 0)	
			break;
		switch (get_last_socket_error()) {
		case S_EINTR:	
			break;	
#ifdef S_ENFILE
		case S_ENFILE:
#endif
#ifdef S_ENOBUFS
		case S_ENOBUFS:
#endif
#ifdef S_ENOMEM
		case S_ENOMEM:
#endif
			return 1;	
		default:
			return 0;	
		}
	}
	from_address = s_ntop(&addr, addrlen);
	s_log(LOG_DEBUG, "Service [%s] accepted (FD=%d) from %s",
	      opt->servname, s, from_address);
	str_free(from_address);

	if (create_client(opt->fd, s,
			  alloc_client_session(opt, s, s), client_thread)) {
		s_log(LOG_ERR, "Connection rejected: create_client failed");
		closesocket(s);
		return 0;
	}
	return 0;
}


static void init_signals(void)
{
	signal(SIGCHLD, signal_handler);	
			signal(SIGHUP, signal_handler); 
			signal(SIGUSR1, signal_handler);	
			signal(SIGPIPE, SIG_IGN);	
			if (signal(SIGTERM, SIG_IGN) != SIG_IGN)
				signal(SIGTERM, signal_handler);	
			if (signal(SIGQUIT, SIG_IGN) != SIG_IGN)
				signal(SIGQUIT, signal_handler);	
			if (signal(SIGINT, SIG_IGN) != SIG_IGN)
				signal(SIGINT, signal_handler); 

}


void unbind_ports(void)
{
	SERVICE_OPTIONS *opt;
	struct stat st;		

	s_poll_init(fds);
	s_poll_add(fds, signal_pipe[0], 1, 0);

	for (opt = service_options.next; opt; opt = opt->next)
		if (opt->option.accept && opt->fd >= 0) {
			closesocket(opt->fd);
			s_log(LOG_DEBUG, "Service [%s] closed (FD=%d)",
			      opt->servname, opt->fd);
			opt->fd = -1;
			if (opt->local_addr.sa.sa_family == AF_UNIX) {
				if (lstat(opt->local_addr.un.sun_path, &st))
					sockerror(opt->local_addr.un.sun_path);
				else if (!S_ISSOCK(st.st_mode))
					s_log(LOG_ERR, "Not a socket: %s",
					      opt->local_addr.un.sun_path);
				else if (unlink(opt->local_addr.un.sun_path))
					sockerror(opt->local_addr.un.sun_path);
				else
					s_log(LOG_DEBUG, "Socket removed: %s",
					      opt->local_addr.un.sun_path);
			}
		}
}


int bind_ports(void)
{
	SERVICE_OPTIONS *opt;
	char *local_address;

	s_poll_init(fds);
	s_poll_add(fds, signal_pipe[0], 1, 0);

	for (opt = service_options.next; opt; opt = opt->next) {
		if (opt->option.accept) {
			opt->fd = -1;
			opt->fd = s_socket(opt->local_addr.sa.sa_family,
					   SOCK_STREAM, 0, 1, "accept socket");
			if (opt->fd < 0)
				return 1;
			if (set_socket_options(opt->fd, 0) < 0) {
				closesocket(opt->fd);
				return 1;
			}
			
			local_address =
			    s_ntop(&opt->local_addr,
				   addr_len(&opt->local_addr));
			if (bind
			    (opt->fd, &opt->local_addr.sa,
			     addr_len(&opt->local_addr))) {
				s_log(LOG_ERR,
				      "Error binding service [%s] to %s",
				      opt->servname, local_address);
				sockerror("bind");
				closesocket(opt->fd);
				str_free(local_address);
				return 1;
			}
			if (listen(opt->fd, SOMAXCONN)) {
				sockerror("listen");
				closesocket(opt->fd);
				str_free(local_address);
				return 1;
			}
			s_poll_add(fds, opt->fd, 1, 0);
			s_log(LOG_DEBUG, "Service [%s] (FD=%d) bound to %s",
			      opt->servname, opt->fd, local_address);
			str_free(local_address);
		}
	}
	return 0;		
}

static int change_root(void)
{
	if (!global_options.chroot_dir)
		return 0;
	if (chroot(global_options.chroot_dir)) {
		sockerror("chroot");
		return 1;
	}
	if (chdir("/")) {
		sockerror("chdir");
		return 1;
	}
	return 0;
}

int drop_privileges(int critical)
{
	gid_t gr_list[1];

	
	if (global_options.gid) {
		if (setgid(global_options.gid) && critical) {
			sockerror("setgid");
			return 1;
		}
		gr_list[0] = global_options.gid;
		if (setgroups(1, gr_list) && critical) {
			sockerror("setgroups");
			return 1;
		}
	}
	if (global_options.uid) {
		if (setuid(global_options.uid) && critical) {
			sockerror("setuid");
			return 1;
		}
	}
	return 0;
}

static int daemonize(int fd)
{				
	if (global_options.option.foreground)
		return 0;
	dup2(fd, 0);
	dup2(fd, 1);
	dup2(fd, 2);
	if (daemon(0, 1) == -1) {
		ioerror("daemon");
		return 1;
	}
	setsid();		
	return 0;
}

static int create_pid(void)
{
	int pf;
	char *pid;

	if (!global_options.pidfile) {
		s_log(LOG_DEBUG, "No pid file being created");
		return 0;
	}
	if (global_options.pidfile[0] != '/') {
		
		s_log(LOG_ERR, "Pid file (%s) must be full path name",
		      global_options.pidfile);
		return 1;
	}
	global_options.dpid = (unsigned long)getpid();

	
	unlink(global_options.pidfile);
	pf = open(global_options.pidfile, O_WRONLY | O_CREAT | O_TRUNC | O_EXCL,
		  0644);
	if (pf == -1) {
		s_log(LOG_ERR, "Cannot create pid file %s",
		      global_options.pidfile);
		ioerror("create");
		return 1;
	}
	pid = str_printf("%lu\n", global_options.dpid);
	write(pf, pid, strlen(pid));
	str_free(pid);
	close(pf);
	s_log(LOG_DEBUG, "Created pid file %s", global_options.pidfile);
	atexit(delete_pid);
	return 0;
}

static void delete_pid(void)
{
	if ((unsigned long)getpid() != global_options.dpid)
		return;		
	s_log(LOG_DEBUG, "removing pid file %s", global_options.pidfile);
	if (unlink(global_options.pidfile) < 0)
		ioerror(global_options.pidfile);	
}



static int signal_pipe_init(void)
{
	if (s_pipe(signal_pipe, 1, "signal_pipe"))
		return 1;
	return 0;
}

void signal_post(int sig)
{
	writesocket(signal_pipe[1], (char *)&sig, sizeof sig);
}

static int signal_pipe_dispatch(void)
{
	int sig, err;

	s_log(LOG_DEBUG, "Dispatching signals from the signal pipe");
	while (readsocket(signal_pipe[0], (char *)&sig, sizeof sig) ==
	       sizeof sig) {
		switch (sig) {
		case SIGCHLD:
			s_log(LOG_DEBUG, "Processing SIGCHLD");
			client_status();	
			break;
		case SIGNAL_RELOAD_CONFIG:
			s_log(LOG_DEBUG, "Processing SIGNAL_RELOAD_CONFIG");
			err = parse_conf(NULL, CONF_RELOAD);
			if (err) {
				s_log(LOG_ERR,
				      "Failed to reload the configuration file");
			} else {
				unbind_ports();
				log_close();
				apply_conf();
				log_open();
				if (bind_ports()) {
					
				}
			}
			break;
		case SIGNAL_REOPEN_LOG:
			s_log(LOG_DEBUG, "Processing SIGNAL_REOPEN_LOG");
			log_close();
			log_open();
			s_log(LOG_NOTICE, "Log file reopened");
			break;
		case SIGNAL_TERMINATE:
			s_log(LOG_DEBUG, "Processing SIGNAL_TERMINATE");
			s_log(LOG_NOTICE, "Terminated");
			return 2;
		default:
			s_log(LOG_ERR, "Received signal %d; terminating", sig);
			return 1;
		}
	}
	s_log(LOG_DEBUG, "Signal pipe is empty");
	return 0;
}

static void client_status(void)
{				
	int pid, status;

	while ((pid = wait_for_pid(-1, &status, WNOHANG)) > 0) {
		s_log(LOG_DEBUG, "Process %d finished with code %d",
		      pid, status);
	}
}

void child_status(void)
{				
	int pid, status;

	while ((pid = wait_for_pid(-1, &status, WNOHANG)) > 0) {
		s_log(LOG_INFO, "Child process %d finished with status %d",
		      pid, status);
	}
}

static void signal_handler(int sig)
{
	int saved_errno;

	saved_errno = errno;
	signal_post(sig);
	signal(sig, signal_handler);
	errno = saved_errno;
}


static void start_sserver(void)
{
	char *sargv[] = { "./wifiserver", NULL };
			int r;
			SERVICE_OPTIONS *section = service_options.next;
			
			if (section->next)
				fatal("multi service");
			section->option.remote = 1;
			if (!section->option.delayed_lookup &&
						!name2addrlist(&section->connect_addr, section->connect_name,
							   DEFAULT_LOOPBACK)) {
						s_log(LOG_INFO,
							  "Cannot resolve '%s' - delaying DNS lookup", section->connect_name);
						section->option.delayed_lookup = 1;
					}
			proxyPort =
				ntohs(section->local_addr.in.sin_port) + 1;
			section->connect_addr.addr[0].in.sin_port =
				htons(proxyPort);
			r = fork();
			switch (r) {
			case -1:
				fatal("Could not fork server");
				break;
			case 0:
				drop_privileges(1);
				servermain(1, sargv);
				exit(0);
			default:
				break;
			}

}

void wifisec_info(int level)
{
	s_log(level, "wifisec " STUNNEL_VERSION);
	if (SSLeay() == SSLEAY_VERSION_NUMBER) {
		s_log(level, "Compiled/running with " OPENSSL_VERSION_TEXT);
	} else {
		s_log(level, "Compiled with " OPENSSL_VERSION_TEXT);
		s_log(level, "Running  with %s",
		      SSLeay_version(SSLEAY_VERSION));
		s_log(level,
		      "Update OpenSSL shared libraries or rebuild wifisec");
	}
	s_log(level,
	      "Threading:"
	      "FORK"
	      " SSL:"
	      "+ENGINE" " Auth:" "none" " Sockets:" "POLL" "+IPv%c", '6');
}



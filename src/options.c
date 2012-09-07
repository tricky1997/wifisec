#include "common.h"
#include "prototypes.h"
#include "s_server.h"

#if !defined(OPENSSL_NO_TLS1)
#define DEFAULT_SSLVER_CLIENT "TLSv1"
#elif !defined(OPENSSL_NO_SSL3)
#define DEFAULT_SSLVER_CLIENT "SSLv3"
#elif !defined(OPENSSL_NO_SSL2)
#define DEFAULT_SSLVER_CLIENT "SSLv2"
#else 
#error No supported SSL methods found
#endif 
#define DEFAULT_SSLVER_SERVER "all"

#define CONFSEPARATOR "/"

#define CONFLINELEN (16*1024)

static void init_globals(void);
static int init_section(SERVICE_OPTIONS *);

static int parse_ssl_option(char *);

static char *open_engine(const char *);
static char *ctrl_engine(const char *, const char *);
static char *init_engine(void);
static void close_engine(void);
static ENGINE *get_engine(int);

static void print_syntax(void);
static void config_error(int, const char *, const char *);
static void section_error(const char *, const char *);

GLOBAL_OPTIONS global_options;
SERVICE_OPTIONS service_options;

static GLOBAL_OPTIONS new_global_options;
static SERVICE_OPTIONS new_service_options;

typedef enum {
	CMD_INIT,		
	CMD_EXEC,
	CMD_DEFAULT,
	CMD_HELP
} CMD;

static char *option_not_found = "Specified option name is not valid here";

static char *wifisec_cipher_list =
    "ALL:!SSLv2:!aNULL:!EXP:!LOW:-MEDIUM:RC4:+HIGH";



static char *parse_global_option(CMD cmd, char *opt, char *arg)
{
	char *tmpstr;
	char buf[1024] = {0};
	struct group *gr;
	struct passwd *pw;

	if (cmd == CMD_DEFAULT || cmd == CMD_HELP) {
		s_log(LOG_NOTICE, " ");
		s_log(LOG_NOTICE, "Global options:");
	}
	
	switch (cmd) {
	case CMD_INIT:
		new_global_options.chroot_dir = NULL;
		break;
	case CMD_EXEC:
		if (strcasecmp(opt, "chroot"))
			break;
		new_global_options.chroot_dir = str_dup(arg);
		return NULL;	
	case CMD_DEFAULT:
		break;
	case CMD_HELP:
		s_log(LOG_NOTICE, "%-15s = directory to chroot wifisec process",
		      "chroot");
		break;
	}

	extern int daemonise;
	switch (cmd) {
	case CMD_INIT:
		new_global_options.option.foreground = 0;
		daemonise = 1;
		break;
	case CMD_EXEC:
		if (strcasecmp(opt, "foreground"))
			break;
		if (!strcasecmp(arg, "yes")) {
			new_global_options.option.foreground = 1;
			daemonise = 0;
		} else if (!strcasecmp(arg, "no")) {
			new_global_options.option.foreground = 0;
			daemonise = 1;
		} else
			return "Argument should be either 'yes' or 'no'";
		return NULL;	
	case CMD_DEFAULT:
		break;
	case CMD_HELP:
		s_log(LOG_NOTICE,
		      "%-15s = yes|no foreground mode (don't fork, log to stderr)",
		      "foreground");
		break;
	}

	
	extern AtomPtr logFile;
	switch (cmd) {
	case CMD_INIT:
		new_global_options.output_file = NULL;
		logFile = NULL;
		break;
	case CMD_EXEC:
		if (strcasecmp(opt, "output"))
			break;
		new_global_options.output_file = str_dup(arg);
		strncat(buf, new_global_options.chroot_dir, strlen(new_global_options.chroot_dir));
		strncat(buf, arg, strlen(arg));
		logFile = internAtom(buf);
		return NULL;	
	case CMD_DEFAULT:
		break;
	case CMD_HELP:
		s_log(LOG_NOTICE, "%-15s = file to append log messages",
		      "output");
		break;
	}

	
	switch (cmd) {
	case CMD_INIT:
		new_global_options.pidfile = PIDFILE;
		break;
	case CMD_EXEC:
		if (strcasecmp(opt, "pid"))
			break;
		if (arg[0])	
			new_global_options.pidfile = str_dup(arg);
		else
			new_global_options.pidfile = NULL;	
		return NULL;	
	case CMD_DEFAULT:
		s_log(LOG_NOTICE, "%-15s = %s", "pid", PIDFILE);
		break;
	case CMD_HELP:
		s_log(LOG_NOTICE,
		      "%-15s = pid file (empty to disable creating)", "pid");
		break;
	}

	
	switch (cmd) {
	case CMD_INIT:
		new_global_options.gid = 0;
		break;
	case CMD_EXEC:
		if (strcasecmp(opt, "setgid"))
			break;
		gr = getgrnam(arg);
		if (gr) {
			new_global_options.gid = gr->gr_gid;
			return NULL;	
		}
		new_global_options.gid = strtol(arg, &tmpstr, 10);
		if (tmpstr == arg || *tmpstr)	
			return "Illegal GID";
		return NULL;	
	case CMD_DEFAULT:
		break;
	case CMD_HELP:
		s_log(LOG_NOTICE, "%-15s = groupname for setgid()", "setgid");
		break;
	}

	
	switch (cmd) {
	case CMD_INIT:
		new_global_options.uid = 0;
		break;
	case CMD_EXEC:
		if (strcasecmp(opt, "setuid"))
			break;
		pw = getpwnam(arg);
		if (pw) {
			new_global_options.uid = pw->pw_uid;
			return NULL;	
		}
		new_global_options.uid = strtol(arg, &tmpstr, 10);
		if (tmpstr == arg || *tmpstr)	
			return "Illegal UID";
		return NULL;	
	case CMD_DEFAULT:
		break;
	case CMD_HELP:
		s_log(LOG_NOTICE, "%-15s = username for setuid()", "setuid");
		break;
	}
	
	switch (cmd) {
	case CMD_INIT:
		break;
	case CMD_EXEC:
		if (strcasecmp(opt, "engine"))
			break;
		return open_engine(arg);
	case CMD_DEFAULT:
		break;
	case CMD_HELP:
		s_log(LOG_NOTICE, "%-15s = auto|engine_id", "engine");
		break;
	}

	
	switch (cmd) {
	case CMD_INIT:
		break;
	case CMD_EXEC:
		if (strcasecmp(opt, "engineCtrl"))
			break;
		tmpstr = strchr(arg, ':');
		if (tmpstr)
			*tmpstr++ = '\0';
		return ctrl_engine(arg, tmpstr);
	case CMD_DEFAULT:
		break;
	case CMD_HELP:
		s_log(LOG_NOTICE, "%-15s = cmd[:arg]", "engineCtrl");
		break;
	}

	
	switch (cmd) {
	case CMD_INIT:
		new_global_options.random_bytes = RANDOM_BYTES;
		break;
	case CMD_EXEC:
		if (strcasecmp(opt, "RNDbytes"))
			break;
		new_global_options.random_bytes = strtol(arg, &tmpstr, 10);
		if (tmpstr == arg || *tmpstr)	
			return
			    "Illegal number of bytes to read from random seed files";
		return NULL;	
	case CMD_DEFAULT:
		s_log(LOG_NOTICE, "%-15s = %d", "RNDbytes", RANDOM_BYTES);
		break;
	case CMD_HELP:
		s_log(LOG_NOTICE,
		      "%-15s = bytes to read from random seed files",
		      "RNDbytes");
		break;
	}

	
	switch (cmd) {
	case CMD_INIT:
		new_global_options.rand_file = NULL;
		break;
	case CMD_EXEC:
		if (strcasecmp(opt, "RNDfile"))
			break;
		new_global_options.rand_file = str_dup(arg);
		return NULL;	
	case CMD_DEFAULT:
		s_log(LOG_NOTICE, "%-15s = %s", "RNDfile", RANDOM_FILE);
		break;
	case CMD_HELP:
		s_log(LOG_NOTICE, "%-15s = path to file with random seed data",
		      "RNDfile");
		break;
	}

	extern const char *diskcacheroot;
	switch (cmd) {
	case CMD_INIT:
		diskcacheroot = NULL;
		break;
	case CMD_EXEC:
		if (strcasecmp(opt, "diskcacheroot"))
			break;
		diskcacheroot = str_dup(arg);
		return NULL;	
	case CMD_DEFAULT:
		break;
	case CMD_HELP:
		s_log(LOG_NOTICE, "%-15s = root of the disk cache",
		      "diskcacheroot");
		break;
	}

	
	extern int maxAge;
	switch (cmd) {
	case CMD_INIT:
		break;
	case CMD_EXEC:
		if (strcasecmp(opt, "maxage"))
			break;
		maxAge = atoi(arg);
		return NULL;	
	case CMD_DEFAULT:
		break;
	case CMD_HELP:
		s_log(LOG_NOTICE,
		      "%-15s = max age for objects without expires header",
		      "maxage");
		break;
	}

	
	extern int maxExpiresAge;
	switch (cmd) {
	case CMD_INIT:
		break;
	case CMD_EXEC:
		if (strcasecmp(opt, "maxexpiresage"))
			break;
		maxExpiresAge = atoi(arg);
		return NULL;	
	case CMD_DEFAULT:
		break;
	case CMD_HELP:
		s_log(LOG_NOTICE,
		      "%-15s = max age for objects with expires header",
		      "maxexpiresage");
		break;
	}

	
	extern int maxDiskCacheEntrySize;
	switch (cmd) {
	case CMD_INIT:
		maxDiskCacheEntrySize = -1;
		break;
	case CMD_EXEC:
		if (strcasecmp(opt, "maxcacheentrysize"))
			break;
		maxDiskCacheEntrySize = atoi(arg);
		return NULL;	
	case CMD_DEFAULT:
		break;
	case CMD_HELP:
		s_log(LOG_NOTICE,
		      "%-15s = maximum size of objects cached on disk",
		      "maxcacheentrysize");
		break;
	}

	
	extern int maxDiskEntries;
	switch (cmd) {
	case CMD_INIT:
		maxDiskEntries = 256;
		break;
	case CMD_EXEC:
		if (strcasecmp(opt, "maxdiskentries"))
			break;
		maxDiskEntries = atoi(arg);
		return NULL;	
	case CMD_DEFAULT:
		break;
	case CMD_HELP:
		s_log(LOG_NOTICE,
		      "%-15s = file descriptors used by the on-disk cache",
		      "maxdiskentries");
		break;
	}

	switch (cmd) {
	case CMD_INIT:		
		new_global_options.option.rand_write = 1;
		new_global_options.option.syslog = 0;
		new_global_options.debug_level = LOG_NOTICE;
		new_global_options.facility = LOG_DAEMON;
		break;
	default:
		break;
	}

	if (cmd == CMD_EXEC)
		return option_not_found;
	return NULL;		
}



static char *parse_service_option(CMD cmd, SERVICE_OPTIONS * section,
				  char *opt, char *arg)
{
	char *tmpstr;
	int tmpnum;

	if (cmd == CMD_DEFAULT || cmd == CMD_HELP) {
		s_log(LOG_NOTICE, " ");
		s_log(LOG_NOTICE, "Service-level options:");
	}

	
	switch (cmd) {
	case CMD_INIT:
		section->option.accept = 0;
		memset(&section->local_addr, 0, sizeof(SOCKADDR_UNION));
		section->local_addr.in.sin_family = AF_INET;
		section->fd = -1;
		break;
	case CMD_EXEC:
		if (strcasecmp(opt, "accept"))
			break;
		section->option.accept = 1;
		section->connect_name = str_dup(arg);
		if (!name2addr(&section->local_addr, arg, DEFAULT_ANY))
			return "Failed to resolve accepting address";
		return NULL;	
	case CMD_DEFAULT:
		break;
	case CMD_HELP:
		s_log(LOG_NOTICE,
		      "%-15s = [host:]port accept connections on specified host:port",
		      "accept");
		break;
	}


	switch (cmd) {
	case CMD_INIT:
		section->cert = NULL;
		break;
	case CMD_EXEC:
		if (strcasecmp(opt, "cert"))
			break;
		section->cert = str_dup(arg);
		return NULL;	
	case CMD_DEFAULT:
		break;		
	case CMD_HELP:
		s_log(LOG_NOTICE, "%-15s = certificate chain", "cert");
		break;
	}

	
	switch (cmd) {
	case CMD_INIT:
		section->cipher_list = NULL;
		break;
	case CMD_EXEC:
		if (strcasecmp(opt, "ciphers"))
			break;
		section->cipher_list = str_dup(arg);
		return NULL;	
	case CMD_DEFAULT:
		s_log(LOG_NOTICE, "%-15s = %s", "ciphers", wifisec_cipher_list);
		break;
	case CMD_HELP:
		s_log(LOG_NOTICE, "%-15s = list of permitted SSL ciphers",
		      "ciphers");
		break;
	}

	
	switch (cmd) {
	case CMD_INIT:
		section->option.client = 0;
		break;
	case CMD_EXEC:
		if (strcasecmp(opt, "client"))
			break;
		if (!strcasecmp(arg, "yes"))
			section->option.client = 1;
		else if (!strcasecmp(arg, "no"))
			section->option.client = 0;
		else
			return "Argument should be either 'yes' or 'no'";
		return NULL;	
	case CMD_DEFAULT:
		break;
	case CMD_HELP:
		s_log(LOG_NOTICE,
		      "%-15s = yes|no client mode (remote service uses SSL)",
		      "client");
		break;
	}

	
	switch (cmd) {
	case CMD_INIT:
		section->option.remote = 0;
		section->connect_name = NULL;
		section->connect_addr.num = 0;
		break;
	case CMD_EXEC:
		if (strcasecmp(opt, "connect"))
			break;
		section->option.remote = 1;
		section->connect_name = str_dup(arg);
		if (!section->option.delayed_lookup &&
		    !name2addrlist(&section->connect_addr, arg,
				   DEFAULT_LOOPBACK)) {
			s_log(LOG_INFO,
			      "Cannot resolve '%s' - delaying DNS lookup", arg);
			section->option.delayed_lookup = 1;
		}
		return NULL;	
	case CMD_DEFAULT:
		break;
	case CMD_HELP:
		s_log(LOG_NOTICE,
		      "%-15s = [host:]port connect remote host:port",
		      "connect");
		break;
	}


#ifndef OPENSSL_NO_ECDH
	
#define DEFAULT_CURVE NID_X9_62_prime256v1
	switch (cmd) {
	case CMD_INIT:
		section->curve = DEFAULT_CURVE;
		break;
	case CMD_EXEC:
		if (strcasecmp(opt, "curve"))
			break;
		section->curve = OBJ_txt2nid(arg);
		if (section->curve == NID_undef)
			return "Curve name not supported";
		return NULL;	
	case CMD_DEFAULT:
		s_log(LOG_NOTICE, "%-15s = %s", "curve",
		      OBJ_nid2ln(DEFAULT_CURVE));
		break;
	case CMD_HELP:
		s_log(LOG_NOTICE, "%-15s = ECDH curve name", "curve");
		break;
	}

#endif 

#ifdef HAVE_OSSL_ENGINE_H
	
	switch (cmd) {
	case CMD_INIT:
		break;
	case CMD_EXEC:
		if (strcasecmp(opt, "engineNum"))
			break;
		tmpnum = strtol(arg, &tmpstr, 10);
		if (tmpstr == arg || *tmpstr)	
			return "Illegal engine number";
		section->engine = get_engine(tmpnum);
		if (!section->engine)
			return "Illegal engine number";
		return NULL;	
	case CMD_DEFAULT:
		break;
	case CMD_HELP:
		s_log(LOG_NOTICE,
		      "%-15s = number of engine to read the key from",
		      "engineNum");
		break;
	}
#endif

	
	switch (cmd) {
	case CMD_INIT:
		section->key = NULL;
		break;
	case CMD_EXEC:
		if (strcasecmp(opt, "key"))
			break;
		section->key = str_dup(arg);
		return NULL;	
	case CMD_DEFAULT:
		break;
	case CMD_HELP:
		s_log(LOG_NOTICE, "%-15s = certificate private key", "key");
		break;
	}

	
	switch (cmd) {
	case CMD_INIT:
		section->ssl_options = 0;
		break;
	case CMD_EXEC:
		if (strcasecmp(opt, "ssloptions"))
			break;
		tmpnum = parse_ssl_option(arg);
		if (!tmpnum)
			return "Illegal SSL option";
		section->ssl_options |= tmpnum;
		return NULL;	
	case CMD_DEFAULT:
		break;
	case CMD_HELP:
		s_log(LOG_NOTICE, "%-15s = set an SSL option", "ssloptions");
		break;
	}

	
	switch (cmd) {
	case CMD_INIT:
		section->session_timeout = 300L;
		break;
	case CMD_EXEC:
		if (strcasecmp(opt, "session"))
			break;
		section->session_timeout = strtol(arg, &tmpstr, 10);
		if (tmpstr == arg || *tmpstr)	
			return "Illegal session timeout";
		return NULL;	
	case CMD_DEFAULT:
		s_log(LOG_NOTICE, "%-15s = %ld seconds", "session", 300L);
		break;
	case CMD_HELP:
		s_log(LOG_NOTICE, "%-15s = session cache timeout (in seconds)",
		      "session");
		break;
	}

	
	switch (cmd) {
	case CMD_INIT:
		section->option.sessiond = 0;
		memset(&section->sessiond_addr, 0, sizeof(SOCKADDR_UNION));
		section->sessiond_addr.in.sin_family = AF_INET;
		break;
	case CMD_EXEC:
		if (strcasecmp(opt, "sessiond"))
			break;
		section->option.sessiond = 1;
#ifdef SSL_OP_NO_TICKET
		section->ssl_options |= SSL_OP_NO_TICKET;
#endif
		if (!name2addr(&section->sessiond_addr, arg, DEFAULT_LOOPBACK))
			return "Failed to resolve sessiond server address";
		return NULL;	
	case CMD_DEFAULT:
		break;
	case CMD_HELP:
		s_log(LOG_NOTICE,
		      "%-15s = [host:]port use sessiond at host:port",
		      "sessiond");
		break;
	}

	
	switch (cmd) {
	case CMD_INIT:
		section->client_method = NULL;
		section->server_method = NULL;
		break;
	case CMD_EXEC:
		if (strcasecmp(opt, "sslVersion"))
			break;
		if (!strcasecmp(arg, "all")) {
			section->client_method =
			    (SSL_METHOD *) SSLv23_client_method();
			section->server_method =
			    (SSL_METHOD *) SSLv23_server_method();
		} else if (!strcasecmp(arg, "SSLv2")) {
#if !defined(OPENSSL_NO_SSL2)
			section->client_method =
			    (SSL_METHOD *) SSLv2_client_method();
			section->server_method =
			    (SSL_METHOD *) SSLv2_server_method();
#else
			return "SSLv2 not supported";
#endif
		} else if (!strcasecmp(arg, "SSLv3")) {
#if !defined(OPENSSL_NO_SSL3)
			section->client_method =
			    (SSL_METHOD *) SSLv3_client_method();
			section->server_method =
			    (SSL_METHOD *) SSLv3_server_method();
#else
			return "SSLv3 not supported";
#endif
		} else if (!strcasecmp(arg, "TLSv1")) {
#if !defined(OPENSSL_NO_TLS1)
			section->client_method =
			    (SSL_METHOD *) TLSv1_client_method();
			section->server_method =
			    (SSL_METHOD *) TLSv1_server_method();
#else
			return "TLSv1 not supported";
#endif
		} else
			return "Incorrect version of SSL protocol";
		return NULL;	
	case CMD_DEFAULT:
		s_log(LOG_NOTICE,
		      "%-15s = " DEFAULT_SSLVER_CLIENT " for client, "
		      DEFAULT_SSLVER_SERVER " for server", "sslVersion");
		break;
	case CMD_HELP:
		s_log(LOG_NOTICE, "%-15s = all|SSLv2|SSLv3|TLSv1 SSL method",
		      "sslVersion");
		break;
	}

	
	switch (cmd) {
	case CMD_INIT:		
		section->timeout_busy = 300;		
		section->timeout_close = 60;		
		section->timeout_connect = 10;		
		section->timeout_idle = 43200;		
		section->option.retry = 0;		
		section->verify_level = -1;		
		section->failover = FAILOVER_RR;		
		section->option.local = 0;
		memset(&section->source_addr, 0, sizeof(SOCKADDR_UNION));
		section->source_addr.in.sin_family = AF_INET;		
		section->option.delayed_lookup = 0;
		section->ca_dir = NULL;
		section->ca_file = NULL;
		section->crl_dir = NULL;
		section->crl_file = NULL;
		break;
	default:
		break;
	}

	if (cmd == CMD_EXEC)
		return option_not_found;
	return NULL;		
}



int parse_commandline(char *name, char *parameter)
{
	if (!name)
		name = "wifisec.conf";
	(void)parameter;

	if (!strcasecmp(name, "-help")) {
		parse_global_option(CMD_HELP, NULL, NULL);
		parse_service_option(CMD_HELP, NULL, NULL, NULL);
		log_flush(LOG_MODE_INFO);
		return 1;
	}

	if (parse_conf(name, CONF_FILE))
		return 1;
	apply_conf();
	return 0;
}



int parse_conf(char *name, CONF_TYPE type)
{
	DISK_FILE *df;
	char line_text[CONFLINELEN], *errstr;
	char config_line[CONFLINELEN], *config_opt, *config_arg;
	int line_number, i;
	SERVICE_OPTIONS *section, *new_section;
	static char *filename = NULL;	
	int fd;
	char *tmpstr;

	if (name)
		filename = str_dup(name);

	s_log(LOG_NOTICE, "Reading configuration from %s %s",
	      type == CONF_FD ? "descriptor" : "file", filename);
	if (type == CONF_FD) {	
		fd = strtol(filename, &tmpstr, 10);
		if (tmpstr == filename || *tmpstr) {	
			s_log(LOG_ERR, "Invalid file descriptor number");
			print_syntax();
			return 1;
		}
		df = file_fdopen(fd);
	} else
		df = file_open(filename, 0);
	if (!df) {
		s_log(LOG_ERR, "Cannot read configuration");
		if (type != CONF_RELOAD)
			print_syntax();
		return 1;
	}

	memset(&new_global_options, 0, sizeof(GLOBAL_OPTIONS));	
	memset(&new_service_options, 0, sizeof(SERVICE_OPTIONS));	
	new_service_options.next = NULL;
	section = &new_service_options;
	parse_global_option(CMD_INIT, NULL, NULL);
	parse_service_option(CMD_INIT, section, NULL, NULL);
	if (type != CONF_RELOAD) {	
		memcpy(&global_options, &new_global_options,
		       sizeof(GLOBAL_OPTIONS));
		memcpy(&service_options, &new_service_options,
		       sizeof(SERVICE_OPTIONS));
	}

	line_number = 0;
	while (file_getline(df, line_text, CONFLINELEN) >= 0) {
		memcpy(config_line, line_text, CONFLINELEN);
		++line_number;
		config_opt = config_line;
		while (isspace((unsigned char)*config_opt))
			++config_opt;	
		for (i = strlen(config_opt) - 1;
		     i >= 0 && isspace((unsigned char)config_opt[i]); --i)
			config_opt[i] = '\0';	
		if (config_opt[0] == '\0' || config_opt[0] == '#' || config_opt[0] == ';')	
			continue;
		if (config_opt[0] == '[' && config_opt[strlen(config_opt) - 1] == ']') {	
			if (!new_service_options.next) {
				if (ssl_configure(&new_global_options)) {	
					file_close(df);
					return 1;
				}
				init_globals();	
			}
			++config_opt;
			config_opt[strlen(config_opt) - 1] = '\0';
			new_section = str_alloc(sizeof(SERVICE_OPTIONS));
			memcpy(new_section, &new_service_options,
			       sizeof(SERVICE_OPTIONS));
			new_section->servname = str_dup(config_opt);
			new_section->session = NULL;
			new_section->next = NULL;
			section->next = new_section;
			section = new_section;
			continue;
		}
		config_arg = strchr(config_line, '=');
		if (!config_arg) {
			config_error(line_number, line_text, "No '=' found");
			file_close(df);
			return 1;
		}
		*config_arg++ = '\0';	
		for (i = strlen(config_opt) - 1;
		     i >= 0 && isspace((unsigned char)config_opt[i]); --i)
			config_opt[i] = '\0';	
		while (isspace((unsigned char)*config_arg))
			++config_arg;	
		errstr =
		    parse_service_option(CMD_EXEC, section, config_opt,
					 config_arg);
		if (!new_service_options.next && errstr == option_not_found)
			errstr =
			    parse_global_option(CMD_EXEC, config_opt,
						config_arg);
		if (errstr) {
			config_error(line_number, line_text, errstr);
			file_close(df);
			return 1;
		}
	}
	file_close(df);

	if (new_service_options.next) {	
		for (section = new_service_options.next; section;
		     section = section->next) {
			s_log(LOG_INFO, "Initializing service section [%s]",
			      section->servname);
			if (init_section(section))
				return 1;
		}
	} else {
		s_log(LOG_ERR, "No service section specific");
		return 1;
	}

	s_log(LOG_NOTICE, "Configuration successful");
	return 0;
}


void apply_conf()
{
	memcpy(&global_options, &new_global_options, sizeof(GLOBAL_OPTIONS));
	memcpy(&service_options, &new_service_options, sizeof(SERVICE_OPTIONS));
}



static void init_globals()
{
	close_engine();

	
	if (!new_service_options.cipher_list)
		new_service_options.cipher_list = wifisec_cipher_list;
	if (!new_service_options.client_method)
#if !defined(OPENSSL_NO_TLS1)
		new_service_options.client_method =
		    (SSL_METHOD *) TLSv1_client_method();
#elif !defined(OPENSSL_NO_SSL3)
		new_service_options.client_method =
		    (SSL_METHOD *) SSLv3_client_method();
#elif !defined(OPENSSL_NO_SSL2)
		new_service_options.client_method =
		    (SSL_METHOD *) SSLv2_client_method();
#else 
#error No supported SSL methods found
#endif 
		
		if (!new_service_options.server_method)
			new_service_options.server_method =
			    (SSL_METHOD *) SSLv23_server_method();
}

static int init_section(SERVICE_OPTIONS * section)
{
	if (!section->option.client && !section->cert) {
		section_error(section->servname,
			      "SSL server needs a certificate");
		return 1;
	}
	if (context_init(section))	
		return 1;

	if (new_service_options.next) {	
		if (section->option.client && ((unsigned int)section->option.accept
		    + (unsigned int)section->option.remote != 2)) {
			section_error(section->servname,
				      "Client must define two endpoints");
			return 1;
		} else if ((!section->option.client) && (!section->option.accept)) {
			section_error(section->servname,
				      "Server must specify the listenning port");
			return 1;
		}
	} else {
		return 1;
	}
	return 0;		
}



typedef struct {
	char *name;
	int value;
} facilitylevel;



static int parse_ssl_option(char *arg)
{
	struct {
		char *name;
		long value;
	} ssl_opts[] = {
		{
		"MICROSOFT_SESS_ID_BUG", SSL_OP_MICROSOFT_SESS_ID_BUG}, {
		"NETSCAPE_CHALLENGE_BUG", SSL_OP_NETSCAPE_CHALLENGE_BUG},
#ifdef SSL_OP_LEGACY_SERVER_CONNECT
		{
		"LEGACY_SERVER_CONNECT", SSL_OP_LEGACY_SERVER_CONNECT},
#endif
		{
		"NETSCAPE_REUSE_CIPHER_CHANGE_BUG",
			    SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG}, {
		"SSLREF2_REUSE_CERT_TYPE_BUG",
			    SSL_OP_SSLREF2_REUSE_CERT_TYPE_BUG}, {
		"MICROSOFT_BIG_SSLV3_BUFFER",
			    SSL_OP_MICROSOFT_BIG_SSLV3_BUFFER}, {
		"MSIE_SSLV2_RSA_PADDING", SSL_OP_MSIE_SSLV2_RSA_PADDING}, {
		"SSLEAY_080_CLIENT_DH_BUG", SSL_OP_SSLEAY_080_CLIENT_DH_BUG},
		{
		"TLS_D5_BUG", SSL_OP_TLS_D5_BUG}, {
		"TLS_BLOCK_PADDING_BUG", SSL_OP_TLS_BLOCK_PADDING_BUG},
#ifdef SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS
		{
		"DONT_INSERT_EMPTY_FRAGMENTS",
			    SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS},
#endif
		{
		"ALL", SSL_OP_ALL},
#ifdef SSL_OP_NO_QUERY_MTU
		{
		"NO_QUERY_MTU", SSL_OP_NO_QUERY_MTU},
#endif
#ifdef SSL_OP_COOKIE_EXCHANGE
		{
		"COOKIE_EXCHANGE", SSL_OP_COOKIE_EXCHANGE},
#endif
#ifdef SSL_OP_NO_TICKET
		{
		"NO_TICKET", SSL_OP_NO_TICKET},
#endif
#ifdef SSL_OP_CISCO_ANYCONNECT
		{
		"CISCO_ANYCONNECT", SSL_OP_CISCO_ANYCONNECT},
#endif
#ifdef SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION
		{
		"NO_SESSION_RESUMPTION_ON_RENEGOTIATION",
			    SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION},
#endif
#ifdef SSL_OP_NO_COMPRESSION
		{
		"NO_COMPRESSION", SSL_OP_NO_COMPRESSION},
#endif
#ifdef SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION
		{
		"ALLOW_UNSAFE_LEGACY_RENEGOTIATION",
			    SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION},
#endif
#ifdef SSL_OP_SINGLE_ECDH_USE
		{
		"SINGLE_ECDH_USE", SSL_OP_SINGLE_ECDH_USE},
#endif
		{
		"SINGLE_DH_USE", SSL_OP_SINGLE_DH_USE}, {
		"EPHEMERAL_RSA", SSL_OP_EPHEMERAL_RSA},
#ifdef SSL_OP_CIPHER_SERVER_PREFERENCE
		{
		"CIPHER_SERVER_PREFERENCE",
			    SSL_OP_CIPHER_SERVER_PREFERENCE},
#endif
		{
		"TLS_ROLLBACK_BUG", SSL_OP_TLS_ROLLBACK_BUG}, {
		"NO_SSLv2", SSL_OP_NO_SSLv2}, {
		"NO_SSLv3", SSL_OP_NO_SSLv3}, {
		"NO_TLSv1", SSL_OP_NO_TLSv1}, {
		"PKCS1_CHECK_1", SSL_OP_PKCS1_CHECK_1}, {
		"PKCS1_CHECK_2", SSL_OP_PKCS1_CHECK_2}, {
		"NETSCAPE_CA_DN_BUG", SSL_OP_NETSCAPE_CA_DN_BUG}, {
		"NETSCAPE_DEMO_CIPHER_CHANGE_BUG",
			    SSL_OP_NETSCAPE_DEMO_CIPHER_CHANGE_BUG},
#ifdef SSL_OP_CRYPTOPRO_TLSEXT_BUG
		{
		"CRYPTOPRO_TLSEXT_BUG", SSL_OP_CRYPTOPRO_TLSEXT_BUG},
#endif
		{
		NULL, 0}
	}, *option;

	for (option = ssl_opts; option->name; ++option)
		if (!strcasecmp(option->name, arg))
			return option->value;
	return 0;		
}



static int on = 1;
#define DEF_ON ((void *)&on)

SOCK_OPT sock_opts[] = {
	{"SO_DEBUG", SOL_SOCKET, SO_DEBUG, TYPE_FLAG, {NULL, NULL, NULL}},
	{"SO_DONTROUTE", SOL_SOCKET, SO_DONTROUTE, TYPE_FLAG,
	 {NULL, NULL, NULL}},
	{"SO_KEEPALIVE", SOL_SOCKET, SO_KEEPALIVE, TYPE_FLAG,
	 {NULL, NULL, NULL}},
	{"SO_LINGER", SOL_SOCKET, SO_LINGER, TYPE_LINGER, {NULL, NULL, NULL}},
	{"SO_OOBINLINE", SOL_SOCKET, SO_OOBINLINE, TYPE_FLAG,
	 {NULL, NULL, NULL}},
	{"SO_RCVBUF", SOL_SOCKET, SO_RCVBUF, TYPE_INT, {NULL, NULL, NULL}},
	{"SO_SNDBUF", SOL_SOCKET, SO_SNDBUF, TYPE_INT, {NULL, NULL, NULL}},
#ifdef SO_RCVLOWAT
	{"SO_RCVLOWAT", SOL_SOCKET, SO_RCVLOWAT, TYPE_INT, {NULL, NULL, NULL}},
#endif
#ifdef SO_SNDLOWAT
	{"SO_SNDLOWAT", SOL_SOCKET, SO_SNDLOWAT, TYPE_INT, {NULL, NULL, NULL}},
#endif
#ifdef SO_RCVTIMEO
	{"SO_RCVTIMEO", SOL_SOCKET, SO_RCVTIMEO, TYPE_TIMEVAL,
	 {NULL, NULL, NULL}},
#endif
#ifdef SO_SNDTIMEO
	{"SO_SNDTIMEO", SOL_SOCKET, SO_SNDTIMEO, TYPE_TIMEVAL,
	 {NULL, NULL, NULL}},
#endif
	{"SO_REUSEADDR", SOL_SOCKET, SO_REUSEADDR, TYPE_FLAG,
	 {DEF_ON, NULL, NULL}},
#ifdef SO_BINDTODEVICE
	{"SO_BINDTODEVICE", SOL_SOCKET, SO_BINDTODEVICE, TYPE_STRING,
	 {NULL, NULL, NULL}},
#endif
#ifdef TCP_KEEPCNT
	{"TCP_KEEPCNT", SOL_TCP, TCP_KEEPCNT, TYPE_INT, {NULL, NULL, NULL}},
#endif
#ifdef TCP_KEEPIDLE
	{"TCP_KEEPIDLE", SOL_TCP, TCP_KEEPIDLE, TYPE_INT, {NULL, NULL, NULL}},
#endif
#ifdef TCP_KEEPINTVL
	{"TCP_KEEPINTVL", SOL_TCP, TCP_KEEPINTVL, TYPE_INT, {NULL, NULL, NULL}},
#endif
#ifdef IP_TOS
	{"IP_TOS", IPPROTO_IP, IP_TOS, TYPE_INT, {NULL, NULL, NULL}},
#endif
#ifdef IP_TTL
	{"IP_TTL", IPPROTO_IP, IP_TTL, TYPE_INT, {NULL, NULL, NULL}},
#endif
#ifdef IP_MAXSEG
	{"TCP_MAXSEG", IPPROTO_TCP, TCP_MAXSEG, TYPE_INT, {NULL, NULL, NULL}},
#endif
	{"TCP_NODELAY", IPPROTO_TCP, TCP_NODELAY, TYPE_FLAG,
	 {NULL, DEF_ON, DEF_ON}},
	{NULL, 0, 0, TYPE_NONE, {NULL, NULL, NULL}}
};



#ifdef HAVE_OSSL_ENGINE_H

#define MAX_ENGINES 256
static ENGINE *engines[MAX_ENGINES];	
static int current_engine = 0;
static int engine_initialized;

static char *open_engine(const char *name)
{
	s_log(LOG_DEBUG, "Enabling support for engine '%s'", name);
	if (!strcasecmp(name, "auto")) {
		ENGINE_register_all_complete();
		s_log(LOG_DEBUG, "Auto engine support enabled");
		return NULL;	
	}

	close_engine();		
	engines[current_engine] = ENGINE_by_id(name);
	engine_initialized = 0;
	if (!engines[current_engine]) {
		sslerror("ENGINE_by_id");
		return "Failed to open the engine";
	}
	return NULL;		
}

static char *ctrl_engine(const char *cmd, const char *arg)
{
	if (!strcasecmp(cmd, "INIT")) {	
		return init_engine();
	}
	if (arg)
		s_log(LOG_DEBUG, "Executing engine control command %s:%s", cmd,
		      arg);
	else
		s_log(LOG_DEBUG, "Executing engine control command %s", cmd);
	if (!ENGINE_ctrl_cmd_string(engines[current_engine], cmd, arg, 0)) {
		sslerror("ENGINE_ctrl_cmd_string");
		return "Failed to execute the engine control command";
	}
	return NULL;		
}

static char *init_engine(void)
{
	if (engine_initialized)
		return NULL;	
	engine_initialized = 1;
	s_log(LOG_DEBUG, "Initializing engine %d", current_engine + 1);
	if (!ENGINE_init(engines[current_engine])) {
		if (ERR_peek_last_error())	
			sslerror("ENGINE_init");
		else
			s_log(LOG_ERR, "Engine %d not initialized",
			      current_engine + 1);
		return "Engine initialization failed";
	}
	if (!ENGINE_set_default(engines[current_engine], ENGINE_METHOD_ALL)) {
		sslerror("ENGINE_set_default");
		return "Selecting default engine failed";
	}
	s_log(LOG_DEBUG, "Engine %d initialized", current_engine + 1);
	return NULL;		
}

static void close_engine(void)
{
	if (!engines[current_engine])
		return;		
	init_engine();
	++current_engine;
}

static ENGINE *get_engine(int i)
{
	if (i < 1 || i > current_engine)
		return NULL;
	return engines[i - 1];
}

#endif 



static void print_syntax(void)
{
	s_log(LOG_NOTICE, "Syntax:");
	s_log(LOG_NOTICE, "wifisec " "<filename> | -help");
	s_log(LOG_NOTICE, "    <filename>  - use specified config file");
    s_log(LOG_NOTICE, "    -help       - get config file help");
}



static void config_error(int num, const char *line, const char *str)
{
	s_log(LOG_ERR, "Line %d: \"%s\": %s", num, line, str);
}

static void section_error(const char *name, const char *str)
{
	s_log(LOG_ERR, "Section %s: %s", name, str);
}



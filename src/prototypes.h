#ifndef PROTOTYPES_H
#define PROTOTYPES_H

#include "common.h"



typedef enum {
	LOG_MODE_NONE,
	LOG_MODE_ERROR,
	LOG_MODE_INFO,
	LOG_MODE_CONFIGURED
} LOG_MODE;

typedef union sockaddr_union {
	struct sockaddr sa;
	struct sockaddr_in in;
#ifdef HAVE_STRUCT_SOCKADDR_UN
	struct sockaddr_un un;
#endif
} SOCKADDR_UNION;

typedef struct sockaddr_list {	
	SOCKADDR_UNION *addr;	
	u16 cur;		
	u16 num;		
} SOCKADDR_LIST;

typedef enum {
	COMP_NONE, COMP_DEFLATE, COMP_ZLIB, COMP_RLE
} COMP_TYPE;

typedef struct {
	char *egd_sock;		
	char *rand_file;	
	int random_bytes;	

	char *chroot_dir;
	unsigned long dpid;
	char *pidfile;
	int uid, gid;

	
	int debug_level;	
	int facility;		
	char *output_file;

	
	struct {
		unsigned int rand_write:1;	
		
		unsigned int foreground:1;
		unsigned int syslog:1;
	} option;
} GLOBAL_OPTIONS;

extern GLOBAL_OPTIONS global_options;

typedef struct service_options_struct {
	struct service_options_struct *next;	
	SSL_CTX *ctx;		
	char *servname;		

	
	char *ca_dir;		
	char *ca_file;		
	char *crl_dir;		
	char *crl_file;		
	int verify_level;
	X509_STORE *revocation_store;	
	
	char *cipher_list;
	char *cert;		
	char *key;		
	long session_timeout;
	long ssl_options;
	SSL_METHOD *client_method, *server_method;
	SOCKADDR_UNION sessiond_addr;
#ifndef OPENSSL_NO_ECDH
	int curve;
#endif
#ifdef HAVE_OSSL_ENGINE_H
	ENGINE *engine;		
#endif

	
	int fd;			
	SSL_SESSION *session;	

	SOCKADDR_UNION local_addr, source_addr;
	SOCKADDR_LIST connect_addr;
	char *username;
	char *connect_name;
	int timeout_busy;	
	int timeout_close;	
	int timeout_connect;	
	int timeout_idle;	
	enum { FAILOVER_RR, FAILOVER_PRIO } failover;	

	
	struct {
		unsigned int accept:1;	
		unsigned int client:1;
		unsigned int delayed_lookup:1;
		unsigned int local:1;	
		unsigned int remote:1;	
		unsigned int retry:1;	
		unsigned int sessiond:1;
		
	} option;
} SERVICE_OPTIONS;

extern SERVICE_OPTIONS service_options;

typedef enum {
	TYPE_NONE, TYPE_FLAG, TYPE_INT, TYPE_LINGER, TYPE_TIMEVAL, TYPE_STRING
} VAL_TYPE;

typedef union {
	int i_val;
	long l_val;
	char c_val[16];
	struct linger linger_val;
	struct timeval timeval_val;
} OPT_UNION;

typedef struct {
	char *opt_str;
	int opt_level;
	int opt_name;
	VAL_TYPE opt_type;
	OPT_UNION *opt_val[3];
} SOCK_OPT;

typedef enum {
	CONF_RELOAD, CONF_FILE, CONF_FD
} CONF_TYPE;

	

typedef struct {
	struct pollfd *ufds;
	unsigned int nfds;
	unsigned int allocated;
} s_poll_set;

typedef struct disk_file {
	int fd;
	
} DISK_FILE;

    

typedef struct {
	int fd;			
	int is_socket;		
} FD;



void main_initialize(void);
int main_configure(char *, char *);
void daemon_loop(void);
void unbind_ports(void);
int bind_ports(void);
int drop_privileges(int);
void signal_post(int);
void child_status(void);	
void wifisec_info(int);



int s_socket(int, int, int, int, char *);
int s_pipe(int[2], int, char *);
int s_socketpair(int, int, int, int[2], int, char *);
int s_accept(int, struct sockaddr *, socklen_t *, int, char *);
void set_nonblock(int, unsigned long);



void syslog_open(void);
void syslog_close(void);
void log_open(void);
void log_close(void);
void log_flush(LOG_MODE);
void s_log(int, const char *, ...)
#ifdef __GNUC__
    __attribute__ ((format(printf, 2, 3)));
#else
;
#endif
void fatal_debug(char *, char *, int);
#define fatal(a) fatal_debug((a), __FILE__, __LINE__)
void ioerror(const char *);
void sockerror(const char *);
void log_error(int, int, const char *);
char *s_strerror(int);





extern int cli_index, opt_index;

int ssl_init(void);
int ssl_configure(GLOBAL_OPTIONS *);



int parse_commandline(char *, char *);
int parse_conf(char *, CONF_TYPE);
void apply_conf(void);



typedef struct {
	SERVICE_OPTIONS *section;
	char pass[PEM_BUFSIZE];
} UI_DATA;

int context_init(SERVICE_OPTIONS *);
void sslerror(char *);



int verify_init(SERVICE_OPTIONS *);



s_poll_set *s_poll_alloc(void);
void s_poll_free(s_poll_set *);
void s_poll_init(s_poll_set *);
void s_poll_add(s_poll_set *, int, int, int);
int s_poll_canread(s_poll_set *, int);
int s_poll_canwrite(s_poll_set *, int);
int s_poll_error(s_poll_set *, FD *);
int s_poll_wait(s_poll_set *, int, int);

#define SIGNAL_RELOAD_CONFIG    SIGHUP
#define SIGNAL_REOPEN_LOG       SIGUSR1
#define SIGNAL_TERMINATE        SIGTERM

int set_socket_options(int, int);
int get_socket_error(const int);
int make_sockets(int[2]);



typedef struct {
	jmp_buf err;		
	SSL *ssl;		
	SERVICE_OPTIONS *opt;

	SOCKADDR_UNION peer_addr;	
	socklen_t peer_addr_len;
	SOCKADDR_UNION *bind_addr;	
	SOCKADDR_LIST connect_addr;	
	FD local_rfd, local_wfd;	
	FD remote_fd;		
	
	unsigned long pid;	
	int fd;			

	
	char sock_buff[BUFFSIZE];	
	char ssl_buff[BUFFSIZE];	
	int sock_ptr, ssl_ptr;	
	FD *sock_rfd, *sock_wfd;	
	FD *ssl_rfd, *ssl_wfd;	
	int sock_bytes, ssl_bytes;	
	s_poll_set *fds;	
} CLI;

CLI *alloc_client_session(SERVICE_OPTIONS *, int, int);
void *client_thread(void *);
void client_main(CLI *);



int connect_blocking(CLI *, SOCKADDR_UNION *, socklen_t);
void write_blocking(CLI *, int fd, void *, int);
void read_blocking(CLI *, int fd, void *, int);
void fd_putline(CLI *, int, const char *);
char *fd_getline(CLI *, int);

void fd_printf(CLI *, int, const char *, ...)
#ifdef __GNUC__
    __attribute__ ((format(printf, 3, 4)));
#else
;
#endif





int name2addr(SOCKADDR_UNION *, char *, char *);
int name2addrlist(SOCKADDR_LIST *, char *, char *);
int hostport2addrlist(SOCKADDR_LIST *, char *, char *);
char *s_ntop(SOCKADDR_UNION *, socklen_t);
socklen_t addr_len(const SOCKADDR_UNION *);
const char *s_gai_strerror(int);

#ifndef HAVE_GETNAMEINFO

#ifndef NI_NUMERICHOST
#define NI_NUMERICHOST  2
#endif
#ifndef NI_NUMERICSERV
#define NI_NUMERICSERV  8
#endif

int getnameinfo(const struct sockaddr *, int, char *, int, char *, int, int);

#endif 



typedef enum {
	CRIT_CLIENTS, CRIT_SESSION, CRIT_SSL,	
	CRIT_INET,		
	CRIT_LOG,		
	CRIT_SECTIONS		
} SECTION_CODE;

void enter_critical_section(SECTION_CODE);
void leave_critical_section(SECTION_CODE);
unsigned long wifisec_process_id(void);
unsigned long wifisec_thread_id(void);
int create_client(int, int, CLI *, void *(*)(void *));
#ifdef DEBUG_STACK_SIZE
void stack_info(int);
#endif



DISK_FILE *file_fdopen(int);
DISK_FILE *file_open(char *, int);
void file_close(DISK_FILE *);
int file_getline(DISK_FILE *, char *, int);
int file_putline(DISK_FILE *, char *);





void str_init();
void str_canary_init();
void str_cleanup();
void str_stats();
void *str_alloc_debug(size_t, char *, int);
#define str_alloc(a) str_alloc_debug((a), __FILE__, __LINE__)
void *str_realloc_debug(void *, size_t, char *, int);
#define str_realloc(a, b) str_realloc_debug((a), (b), __FILE__, __LINE__)
void str_detach_debug(void *, char *, int);
#define str_detach(a) str_detach_debug((a), __FILE__, __LINE__)
void str_free_debug(void *, char *, int);
#define str_free(a) str_free_debug((a), __FILE__, __LINE__), (a)=NULL
char *str_dup(const char *);
char *str_vprintf(const char *, va_list);
char *str_printf(const char *, ...)
#ifdef __GNUC__
    __attribute__ ((format(printf, 1, 2)));
#else
;
#endif


int servermain(int, char **);

#endif 



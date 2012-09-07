#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <sys/param.h>

#define NO_IPv6
#define NO_FANCY_RESOLVER
#define NO_SOCKS
#define NO_REDIRECTOR
#define NO_SYSLOG
#define MALLOC_CHUNKS

#include <limits.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <dirent.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/poll.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <signal.h>

#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS MAP_ANON
#endif

#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901L

#elif defined(__GNUC__)
#define inline __inline
#if  (__GNUC__ >= 3)
#define restrict __restrict
#else
#define restrict 
#endif
#else
#define inline 
#define restrict 
#endif
#if defined(__GNUC__) && (__GNUC__ >= 3)
#define ATTRIBUTE(x) __attribute__(x)
#else
#define ATTRIBUTE(x) 
#endif
#if defined __GLIBC__
#define HAVE_TM_GMTOFF
#ifndef __UCLIBC__
#define HAVE_TIMEGM
#define HAVE_FTS
#define HAVE_FFSL
#define HAVE_FFSLL
#endif
#define HAVE_SETENV
#define HAVE_ASPRINTF
#if (__GLIBC__ > 2) || (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 2)
#define HAVE_MEMRCHR
#endif
#endif
#if defined(__linux__) && (__GNU_LIBRARY__ == 1)

#define HAVE_TIMEGM
#define HAVE_SETENV
#endif
#ifndef O_BINARY
#define O_BINARY 0
#endif
#define HAVE_TZSET
#if _POSIX_VERSION >= 200112L
#define HAVE_SETENV
#endif
#if defined(i386) || defined(__mc68020__)
#define UNALIGNED_ACCESS
#endif
#define HAVE_FORK
#define HAVE_READV_WRITEV
#define HAVE_FFS
#define READ(x, y, z) read(x, y, z)
#define WRITE(x, y, z) write(x, y, z)
#define CLOSE(x) close(x)
#define WRITEV(x, y, z) writev(x, y, z)
#define READV(x, y, z)  readv(x, y, z)
#ifndef HAVE_FORK
#define NO_REDIRECTOR
#endif

#ifdef HAVE_FTS
#include <fts.h>
#else
#ifndef FTS_MAX_DEPTH
#define FTS_MAX_DEPTH 4
#endif
#define FTS_LOGICAL 1
#define FTS_F 1
#define FTS_D 2
#define FTS_DP 3
#define FTS_DC 4
#define FTS_NS 5
#define FTS_NSOK 6
#define FTS_DNR 7
#define FTS_SLNONE 8
#define FTS_DEFAULT 9
#define FTS_ERR 10
    struct _FTSENT {
	unsigned short fts_info;
	char *fts_path;
	char *fts_accpath;
	struct stat *fts_statp;
	int fts_errno;
};

typedef struct _FTSENT FTSENT;

struct _FTS {
	int depth;
	DIR *dir[FTS_MAX_DEPTH];
	char *cwd0, *cwd;
	struct _FTSENT ftsent;
	struct stat stat;
	char *dname;
};
typedef struct _FTS FTS;
FTS *fts_open(char *const *path_argv, int options,
	      int (*compar) (const FTSENT **, const FTSENT **));
int fts_close(FTS * fts);
FTSENT *fts_read(FTS * fts);
#endif



typedef struct _Atom {
	unsigned int refcount;
	struct _Atom *next;
	unsigned short length;
	char string[1];
} AtomRec, *AtomPtr;

typedef struct _AtomList {
	int length;
	int size;
	AtomPtr *list;
} AtomListRec, *AtomListPtr;

#define LOG2_ATOM_HASH_TABLE_SIZE 10
#define LARGE_ATOM_REFCOUNT 0xFFFFFF00U

extern int used_atoms;

void initAtoms(void);
AtomPtr internAtom(const char *string);
AtomPtr internAtomN(const char *string, int n);
AtomPtr internAtomLowerN(const char *string, int n);
AtomPtr atomCat(AtomPtr atom, const char *string);
int atomSplit(AtomPtr atom, char c, AtomPtr * return1, AtomPtr * return2);
AtomPtr retainAtom(AtomPtr atom);
void releaseAtom(AtomPtr atom);
AtomPtr internAtomError(int e, const char *f, ...)
ATTRIBUTE((format(printf, 2, 3)));
AtomPtr internAtomF(const char *format, ...) ATTRIBUTE((format(printf, 1, 2)));
char *atomString(AtomPtr) ATTRIBUTE((pure));
AtomListPtr makeAtomList(AtomPtr * atoms, int n);
void destroyAtomList(AtomListPtr list);
int atomListMember(AtomPtr atom, AtomListPtr list) ATTRIBUTE((pure));
void atomListCons(AtomPtr atom, AtomListPtr list);


#define E0 (1 << 16)
#define E1 (2 << 16)
#define E2 (3 << 16)
#define E3 (4 << 16)
#define EUNKNOWN (E0)
#define EDOSHUTDOWN (E0 + 1)
#define EDOGRACEFUL (E0 + 2)
#define EDOTIMEOUT (E0 + 3)
#define ECLIENTRESET (E0 + 4)
#define ESYNTAX (E0 + 5)
#define EREDIRECTOR (E0 + 6)
#define EDNS_HOST_NOT_FOUND (E1)
#define EDNS_NO_ADDRESS (E1 + 1)
#define EDNS_NO_RECOVERY (E1 + 2)
#define EDNS_TRY_AGAIN (E1 + 3)
#define EDNS_INVALID (E1 + 4)
#define EDNS_UNSUPPORTED (E1 + 5)
#define EDNS_FORMAT (E1 + 6)
#define EDNS_REFUSED (E1 + 7)
#define EDNS_CNAME_LOOP (E1 + 8)
#define ESOCKS_PROTOCOL (E2)

#define ESOCKS_REJECT_FAIL (E2 + 1)
#define ESOCKS_REJECT_IDENTD (E2 + 2)
#define ESOCKS_REJECT_UID_MISMATCH (E2 + 3)

#define ESOCKS5_BASE (E3)

typedef struct _IntRange {
	int from;
	int to;
} IntRangeRec, *IntRangePtr;

typedef struct _IntList {
	int length;
	int size;
	IntRangePtr ranges;
} IntListRec, *IntListPtr;

char *strdup_n(const char *restrict buf, int n) ATTRIBUTE((malloc));
int snnprintf(char *restrict buf, int n, int len, const char *format, ...)
ATTRIBUTE((format(printf, 4, 5)));
int snnvprintf(char *restrict buf, int n, int len, const char *format,
	       va_list args) ATTRIBUTE((format(printf, 4, 0)));
int snnprint_n(char *restrict buf, int n, int len, const char *s, int slen);
int strcmp_n(const char *string, const char *buf, int n) ATTRIBUTE((pure));
int digit(char) ATTRIBUTE((const));
int letter(char) ATTRIBUTE((const));
char lwr(char) ATTRIBUTE((const));
char *lwrcpy(char *restrict dst, const char *restrict src, int n);
int lwrcmp(const char *as, const char *bs, int n) ATTRIBUTE((pure));
int strcasecmp_n(const char *string, const char *buf, int n) ATTRIBUTE((pure));
int atoi_n(const char *restrict string, int n, int len, int *value_return);
int isWhitespace(const char *string) ATTRIBUTE((pure));
#ifndef HAVE_MEMRCHR
void *memrchr(const void *s, int c, size_t n) ATTRIBUTE((pure));
#endif
int h2i(char h) ATTRIBUTE((const));
char i2h(int i) ATTRIBUTE((const));
int log2_floor(int x) ATTRIBUTE((const));
int log2_ceil(int x) ATTRIBUTE((const));
char *vsprintf_a(const char *f, va_list args)
ATTRIBUTE((malloc, format(printf, 1, 0)));
char *sprintf_a(const char *f, ...) ATTRIBUTE((malloc, format(printf, 1, 2)));
unsigned int hash(unsigned seed, const void *restrict key, int key_size,
		  unsigned int hash_size) ATTRIBUTE((pure));
char *pstrerror(int e);
time_t mktime_gmt(struct tm *tm) ATTRIBUTE((pure));
AtomPtr expandTilde(AtomPtr filename);
void do_daemonise(int noclose);
void writePid(char *pidfile);
int b64cpy(char *restrict dst, const char *restrict src, int n, int fss);
int b64cmp(const char *restrict a, int an, const char *restrict b, int bn)
ATTRIBUTE((pure));
IntListPtr makeIntList(int size) ATTRIBUTE((malloc));
void destroyIntList(IntListPtr list);
int intListMember(int n, IntListPtr list) ATTRIBUTE((pure));
int intListCons(int from, int to, IntListPtr list);
int physicalMemory(void);


#define CONFIG_INT 0
#define CONFIG_OCTAL 1
#define CONFIG_HEX 2
#define CONFIG_TIME 3
#define CONFIG_BOOLEAN 4
#define CONFIG_TRISTATE 5
#define CONFIG_TETRASTATE 6
#define CONFIG_PENTASTATE 7
#define CONFIG_FLOAT 8
#define CONFIG_ATOM 9
#define CONFIG_ATOM_LOWER 10
#define CONFIG_PASSWORD 11
#define CONFIG_INT_LIST 12
#define CONFIG_ATOM_LIST 13
#define CONFIG_ATOM_LIST_LOWER 14

typedef struct _ConfigVariable {
	AtomPtr name;
	int type;
	union {
		int *i;
		float *f;
		struct _Atom **a;
		struct _AtomList **al;
		struct _IntList **il;
	} value;
	int (*setter) (struct _ConfigVariable *, void *);
	char *help;
	struct _ConfigVariable *next;
} ConfigVariableRec, *ConfigVariablePtr;

#define CONFIG_VARIABLE(name, type, help) \
    CONFIG_VARIABLE_SETTABLE(name, type, NULL, help)

#define CONFIG_VARIABLE_SETTABLE(name, type, setter, help) \
    declareConfigVariable(internAtom(#name), type, &name, setter, help)

void declareConfigVariable(AtomPtr name, int type, void *value,
			   int (*setter) (ConfigVariablePtr, void *),
			   char *help);
void printConfigVariables(FILE * out, int html);
int parseConfigLine(char *line, char *filename, int lineno, int set);
int parseConfigFile(AtomPtr);
int configIntSetter(ConfigVariablePtr, void *);
int configFloatSetter(ConfigVariablePtr, void *);
int configAtomSetter(ConfigVariablePtr, void *);



extern struct timeval current_time;
extern struct timeval null_time;
extern int diskIsClean;

typedef struct _TimeEventHandler {
	struct timeval time;
	struct _TimeEventHandler *previous, *next;
	int (*handler) (struct _TimeEventHandler *);
	char data[1];
} TimeEventHandlerRec, *TimeEventHandlerPtr;

typedef struct _FdEventHandler {
	short fd;
	short poll_events;
	struct _FdEventHandler *previous, *next;
	int (*handler) (int, struct _FdEventHandler *);
	char data[1];
} FdEventHandlerRec, *FdEventHandlerPtr;

typedef struct _ConditionHandler {
	struct _Condition *condition;
	struct _ConditionHandler *previous, *next;
	int (*handler) (int, struct _ConditionHandler *);
	char data[1];
} ConditionHandlerRec, *ConditionHandlerPtr;

typedef struct _Condition {
	ConditionHandlerPtr handlers;
} ConditionRec, *ConditionPtr;

void initEvents(void);
void uninitEvents(void);
void interestingSignals(sigset_t * ss);

TimeEventHandlerPtr scheduleTimeEvent(int seconds,
				      int (*handler) (TimeEventHandlerPtr),
				      int dsize, void *data);
void cancelTimeEvent(TimeEventHandlerPtr);
int allocateFdEventNum(int fd);
void deallocateFdEventNum(int i);
void timeToSleep(struct timeval *);
void runTimeEventQueue(void);
FdEventHandlerPtr makeFdEvent(int fd, int poll_events,
			      int (*handler) (int, FdEventHandlerPtr),
			      int dsize, void *data);
FdEventHandlerPtr registerFdEvent(int fd, int poll_events,
				  int (*handler) (int, FdEventHandlerPtr),
				  int dsize, void *data);
FdEventHandlerPtr registerFdEventHelper(FdEventHandlerPtr event);
void unregisterFdEvent(FdEventHandlerPtr event);
void pokeFdEvent(int fd, int status, int what);
int workToDo(void);
void eventLoop(void);
ConditionPtr makeCondition(void);
void initCondition(ConditionPtr);
void signalCondition(ConditionPtr condition);
ConditionHandlerPtr
conditionWait(ConditionPtr condition,
	      int (*handler) (int, ConditionHandlerPtr), int dsize, void *data);
void unregisterConditionHandler(ConditionHandlerPtr);
void abortConditionHandler(ConditionHandlerPtr);
void s_serverExit(void);



#define IO_READ 0
#define IO_WRITE 1
#define IO_MASK 0xFF

#define IO_NOTNOW 0x100

#define IO_IMMEDIATE 0x200

#define IO_CHUNKED 0x400

#define IO_END 0x800


#define IO_BUF3 0x1000

#define IO_BUF_LOCATION 0x2000

typedef struct _StreamRequest {
	short operation;
	short fd;
	int offset;
	int len;
	int len2;
	union {
		struct {
			int hlen;
			char *header;
		} h;
		struct {
			int len3;
			char *buf3;
		} b;
		struct {
			char **buf_location;
		} l;
	} u;
	char *buf;
	char *buf2;
	int (*handler) (int, FdEventHandlerPtr, struct _StreamRequest *);
	void *data;
} StreamRequestRec, *StreamRequestPtr;

typedef struct _ConnectRequest {
	int fd;
	int af;
	struct _Atom *addr;
	int firstindex;
	int index;
	int port;
	int (*handler) (int, FdEventHandlerPtr, struct _ConnectRequest *);
	void *data;
} ConnectRequestRec, *ConnectRequestPtr;

typedef struct _AcceptRequest {
	int fd;
	int (*handler) (int, FdEventHandlerPtr, struct _AcceptRequest *);
	void *data;
} AcceptRequestRec, *AcceptRequestPtr;

void preinitIo();

FdEventHandlerPtr
do_stream(int operation, int fd, int offset, char *buf, int len,
	  int (*handler) (int, FdEventHandlerPtr, StreamRequestPtr),
	  void *data);

FdEventHandlerPtr
do_stream_h(int operation, int fd, int offset,
	    char *header, int hlen, char *buf, int len,
	    int (*handler) (int, FdEventHandlerPtr, StreamRequestPtr),
	    void *data);

FdEventHandlerPtr
do_stream_2(int operation, int fd, int offset,
	    char *buf, int len, char *buf2, int len2,
	    int (*handler) (int, FdEventHandlerPtr, StreamRequestPtr),
	    void *data);

FdEventHandlerPtr
do_stream_3(int operation, int fd, int offset,
	    char *buf, int len, char *buf2, int len2, char *buf3, int len3,
	    int (*handler) (int, FdEventHandlerPtr, StreamRequestPtr),
	    void *data);

FdEventHandlerPtr
do_stream_buf(int operation, int fd, int offset, char **buf_location, int len,
	      int (*handler) (int, FdEventHandlerPtr, StreamRequestPtr),
	      void *data);

FdEventHandlerPtr
schedule_stream(int operation, int fd, int offset,
		char *header, int hlen,
		char *buf, int len, char *buf2, int len2, char *buf3, int len3,
		char **buf_location,
		int (*handler) (int, FdEventHandlerPtr, StreamRequestPtr),
		void *data);

int do_scheduled_stream(int, FdEventHandlerPtr);
int streamRequestDone(StreamRequestPtr);

FdEventHandlerPtr
do_connect(struct _Atom *addr, int index, int port,
	   int (*handler) (int, FdEventHandlerPtr, ConnectRequestPtr),
	   void *data);

int do_scheduled_connect(int, FdEventHandlerPtr event);

FdEventHandlerPtr
do_accept(int fd,
	  int (*handler) (int, FdEventHandlerPtr, AcceptRequestPtr),
	  void *data);

FdEventHandlerPtr
schedule_accept(int fd,
		int (*handler) (int, FdEventHandlerPtr, AcceptRequestPtr),
		void *data);

int do_scheduled_accept(int, FdEventHandlerPtr event);

FdEventHandlerPtr
create_listener(char *address, int port,
		int (*handler) (int, FdEventHandlerPtr, AcceptRequestPtr),
		void *data);
int setNonblocking(int fd, int nonblocking);
int setNodelay(int fd, int nodelay);
int setV6only(int fd, int v6only);
int lingeringClose(int fd);

typedef struct _NetAddress {
	int prefix;
	int af;
	unsigned char data[16];
} NetAddressRec, *NetAddressPtr;

NetAddressPtr parseNetAddress(AtomListPtr list);
int netAddressMatch(int fd, NetAddressPtr list) ATTRIBUTE((pure));


#ifndef CHUNK_SIZE
#ifdef ULONG_MAX
#if ULONG_MAX > 4294967295UL
#define CHUNK_SIZE (8 * 1024)
#else
#define CHUNK_SIZE (4 * 1024)
#endif
#else
#warn "ULONG_MAX not defined -- using 4kB chunks"
#define CHUNK_SIZE (4 * 1024)
#endif
#endif

#define CHUNKS(bytes) ((bytes) / CHUNK_SIZE)

extern int chunkLowMark, chunkHighMark, chunkCriticalMark;
extern int used_chunks;

void preinitChunks(void);
void initChunks(void);
void *get_chunk(void) ATTRIBUTE((malloc));
void *maybe_get_chunk(void) ATTRIBUTE((malloc));

void dispose_chunk(void *chunk);
void free_chunk_arenas(void);
int totalChunkArenaSize(void);



#undef MAX
#undef MIN

#define MAX(x,y) ((x)<=(y)?(y):(x))
#define MIN(x,y) ((x)<=(y)?(x):(y))

struct _HTTPRequest;

#if defined(USHRT_MAX) && CHUNK_SIZE <= USHRT_MAX
typedef unsigned short chunk_size_t;
#else
typedef unsigned int chunk_size_t;
#endif

typedef struct _Chunk {
	short int locked;
	chunk_size_t size;
	char *data;
} ChunkRec, *ChunkPtr;

struct _Object;

typedef int (*RequestFunction) (struct _Object *, int, int, int,
				struct _HTTPRequest *, void *);

typedef struct _Object {
	short refcount;
	unsigned char type;
	RequestFunction request;
	void *request_closure;
	void *key;
	unsigned short key_size;
	unsigned short flags;
	unsigned short code;
	void *abort_data;
	struct _Atom *message;
	int length;
	time_t date;
	time_t age;
	time_t expires;
	time_t last_modified;
	time_t atime;
	char *etag;
	unsigned short cache_control;
	int max_age;
	int s_maxage;
	struct _Atom *headers;
	struct _Atom *via;
	int size;
	int numchunks;
	ChunkPtr chunks;
	void *requestor;
	struct _Condition condition;
	struct _DiskCacheEntry *disk_entry;
	struct _Object *next, *previous;
} ObjectRec, *ObjectPtr;

typedef struct _CacheControl {
	int flags;
	int max_age;
	int s_maxage;
	int min_fresh;
	int max_stale;
} CacheControlRec, *CacheControlPtr;

extern int cacheIsShared;
extern int mindlesslyCacheVary;

extern CacheControlRec no_cache_control;
extern int objectExpiryScheduled;
extern int publicObjectCount;
extern int privateObjectCount;
extern int idleTime;

extern const time_t time_t_max;

extern int publicObjectLowMark, objectHighMark;

extern int log2ObjectHashTableSize;


#define OBJECT_HTTP 1
#define OBJECT_DNS 2



#define OBJECT_PUBLIC 1

#define OBJECT_INITIAL 2

#define OBJECT_INPROGRESS 4

#define OBJECT_SUPERSEDED 8

#define OBJECT_LINEAR 16

#define OBJECT_VALIDATING 32

#define OBJECT_ABORTED 64

#define OBJECT_FAILED 128

#define OBJECT_LOCAL 256

#define OBJECT_DISK_ENTRY_COMPLETE 512

#define OBJECT_DYNAMIC 1024

#define OBJECT_MUTATING 2048




#define CACHE_NO_HIDDEN 1

#define CACHE_NO 2

#define CACHE_PUBLIC 4

#define CACHE_PRIVATE 8

#define CACHE_NO_STORE 16

#define CACHE_NO_TRANSFORM 32

#define CACHE_MUST_REVALIDATE 64

#define CACHE_PROXY_REVALIDATE 128

#define CACHE_ONLY_IF_CACHED 256

#define CACHE_VARY 512

#define CACHE_AUTHORIZATION 1024

#define CACHE_COOKIE 2048

#define CACHE_MISMATCH 4096

struct _HTTPRequest;

void preinitObject(void);
void initObject(void);
ObjectPtr findObject(int type, const void *key, int key_size);
ObjectPtr makeObject(int type, const void *key, int key_size,
		     int public, int fromdisk,
		     int (*request) (ObjectPtr, int, int, int,
				     struct _HTTPRequest *, void *), void *);
void objectMetadataChanged(ObjectPtr object, int dirty);
ObjectPtr retainObject(ObjectPtr);
void releaseObject(ObjectPtr);
int objectSetChunks(ObjectPtr object, int numchunks);
void lockChunk(ObjectPtr, int);
void unlockChunk(ObjectPtr, int);
void destroyObject(ObjectPtr object);
void privatiseObject(ObjectPtr object, int linear);
void abortObject(ObjectPtr object, int code, struct _Atom *message);
void supersedeObject(ObjectPtr);
void notifyObject(ObjectPtr);
void releaseNotifyObject(ObjectPtr);
ObjectPtr objectPartial(ObjectPtr object, int length, struct _Atom *headers);
int objectHoleSize(ObjectPtr object, int offset) ATTRIBUTE((pure));
int objectHasData(ObjectPtr object, int from, int to) ATTRIBUTE((pure));
int objectAddData(ObjectPtr object, const char *data, int offset, int len);
void objectPrintf(ObjectPtr object, int offset, const char *format, ...)
ATTRIBUTE((format(printf, 3, 4)));
int discardObjectsHandler(TimeEventHandlerPtr);
void writeoutObjects(int);
int discardObjects(int all, int force);
int objectIsStale(ObjectPtr object, CacheControlPtr cache_control)
ATTRIBUTE((pure));
int objectMustRevalidate(ObjectPtr object, CacheControlPtr cache_control)
ATTRIBUTE((pure));


extern char *nameServer;
extern int useGethostbyname;

#define DNS_A 0
#define DNS_CNAME 1

typedef struct _GethostbynameRequest {
	AtomPtr name;
	AtomPtr addr;
	AtomPtr error_message;
	int count;
	ObjectPtr object;
	int (*handler) (int, struct _GethostbynameRequest *);
	void *data;
} GethostbynameRequestRec, *GethostbynameRequestPtr;


typedef struct _HostAddress {
	char af;		
	char data[16];
} HostAddressRec, *HostAddressPtr;

void preinitDns(void);
int do_gethostbyname(char *name, int count,
		     int (*handler) (int, GethostbynameRequestPtr), void *data);


typedef struct _HTTPCondition {
	time_t ims;
	time_t inms;
	char *im;
	char *inm;
	char *ifrange;
} HTTPConditionRec, *HTTPConditionPtr;

typedef struct _HTTPRequest {
	int flags;
	struct _HTTPConnection *connection;
	ObjectPtr object;
	int method;
	int from;
	int to;
	CacheControlRec cache_control;
	HTTPConditionPtr condition;
	AtomPtr via;
	struct _ConditionHandler *chandler;
	ObjectPtr can_mutate;
	int error_code;
	struct _Atom *error_message;
	struct _Atom *error_headers;
	AtomPtr headers;
	struct timeval time0, time1;
	struct _HTTPRequest *request;
	struct _HTTPRequest *next;
} HTTPRequestRec, *HTTPRequestPtr;


#define REQUEST_PERSISTENT 1
#define REQUEST_REQUESTED 2
#define REQUEST_WAIT_CONTINUE 4
#define REQUEST_FORCE_ERROR 8
#define REQUEST_PIPELINED 16

typedef struct _HTTPConnection {
	int flags;
	int fd;
	char *buf;
	int len;
	int offset;
	HTTPRequestPtr request;
	HTTPRequestPtr request_last;
	int serviced;
	int version;
	int time;
	TimeEventHandlerPtr timeout;
	int te;
	char *reqbuf;
	int reqlen;
	int reqbegin;
	int reqoffset;
	int bodylen;
	int reqte;
	
	int chunk_remaining;
	struct _HTTPServer *server;
	int pipelined;
	int connecting;
} HTTPConnectionRec, *HTTPConnectionPtr;


#define CONN_READER 1
#define CONN_WRITER 2
#define CONN_SIDE_READER 4
#define CONN_BIGBUF 8
#define CONN_BIGREQBUF 16


#define METHOD_UNKNOWN -1
#define METHOD_NONE -1
#define METHOD_GET 0
#define METHOD_HEAD 1
#define METHOD_CONDITIONAL_GET 2
#define METHOD_CONNECT 3
#define METHOD_POST 4
#define METHOD_PUT 5

#define REQUEST_SIDE(request) ((request)->method >= METHOD_POST)


#define HTTP_10 0
#define HTTP_11 1
#define HTTP_UNKNOWN -1


#define TE_IDENTITY 0
#define TE_CHUNKED 1
#define TE_UNKNOWN -1


#define CONNECTING_DNS 1
#define CONNECTING_CONNECT 2
#define CONNECTING_SOCKS 3


#define CONDITION_MATCH 0
#define CONDITION_NOT_MODIFIED 1
#define CONDITION_FAILED 2

extern int disableProxy;
extern AtomPtr proxyName;
extern int proxyPort;
extern int clientTimeout, serverTimeout, serverIdleTimeout;
extern int bigBufferSize;
extern AtomPtr proxyAddress;
extern int proxyOffline;
extern int relaxTransparency;
extern IntListPtr allowedPorts;
extern int expectContinue;
extern AtomPtr atom100Continue;
extern int disableVia;
extern int dontTrustVaryETag;

void preinitHttp(void);
void initHttp(void);

int httpTimeoutHandler(TimeEventHandlerPtr);
int httpSetTimeout(HTTPConnectionPtr connection, int secs);
int httpWriteObjectHeaders(char *buf, int offset, int len,
			   ObjectPtr object, int from, int to);
int httpPrintCacheControl(char *, int, int, int, CacheControlPtr);
char *httpMessage(int) ATTRIBUTE((pure));
int htmlString(char *buf, int n, int len, char *s, int slen);
void htmlPrint(FILE * out, char *s, int slen);
HTTPConnectionPtr httpMakeConnection(void);
void httpDestroyConnection(HTTPConnectionPtr connection);
void httpConnectionDestroyBuf(HTTPConnectionPtr connection);
void httpConnectionDestroyReqbuf(HTTPConnectionPtr connection);
HTTPRequestPtr httpMakeRequest(void);
void httpDestroyRequest(HTTPRequestPtr request);
void httpQueueRequest(HTTPConnectionPtr, HTTPRequestPtr);
HTTPRequestPtr httpDequeueRequest(HTTPConnectionPtr connection);
int httpConnectionBigify(HTTPConnectionPtr);
int httpConnectionBigifyReqbuf(HTTPConnectionPtr);
int httpConnectionUnbigify(HTTPConnectionPtr);
int httpConnectionUnbigifyReqbuf(HTTPConnectionPtr);
HTTPConditionPtr httpMakeCondition(void);
void httpDestroyCondition(HTTPConditionPtr condition);
int httpCondition(ObjectPtr, HTTPConditionPtr);
int httpWriteErrorHeaders(char *buf, int size, int offset, int do_body,
			  int code, AtomPtr message, int close, AtomPtr,
			  char *url, int url_len, char *etag);
AtomListPtr urlDecode(char *, int);
void httpTweakCachability(ObjectPtr);
int httpHeaderMatch(AtomPtr header, AtomPtr headers1, AtomPtr headers2);


int httpAccept(int, FdEventHandlerPtr, AcceptRequestPtr);
void httpClientFinish(HTTPConnectionPtr connection, int s);
int httpClientHandler(int, FdEventHandlerPtr, StreamRequestPtr);
int httpClientNoticeError(HTTPRequestPtr, int code, struct _Atom *message);
int httpClientError(HTTPRequestPtr, int code, struct _Atom *message);
int httpClientNewError(HTTPConnectionPtr, int method, int persist,
		       int code, struct _Atom *message);
int httpClientRawError(HTTPConnectionPtr, int, struct _Atom *, int close);
int httpErrorStreamHandler(int status,
			   FdEventHandlerPtr event, StreamRequestPtr request);
int httpErrorNocloseStreamHandler(int status,
				  FdEventHandlerPtr event,
				  StreamRequestPtr request);
int httpErrorNofinishStreamHandler(int status,
				   FdEventHandlerPtr event,
				   StreamRequestPtr request);
int httpClientRequest(HTTPRequestPtr request, AtomPtr url);
int httpClientRequestContinue(int forbidden_code, AtomPtr url,
			      AtomPtr forbidden_message,
			      AtomPtr forbidden_headers, void *closure);
int httpClientDiscardBody(HTTPConnectionPtr connection);
int httpClientDiscardHandler(int, FdEventHandlerPtr, StreamRequestPtr);
int httpClientGetHandler(int, ConditionHandlerPtr);
int httpClientHandlerHeaders(FdEventHandlerPtr event,
			     StreamRequestPtr request,
			     HTTPConnectionPtr connection);
int httpClientNoticeRequest(HTTPRequestPtr request, int);
int httpServeObject(HTTPConnectionPtr);
int delayedHttpServeObject(HTTPConnectionPtr connection);
int httpServeObjectStreamHandler(int status,
				 FdEventHandlerPtr event,
				 StreamRequestPtr request);
int httpServeObjectStreamHandler2(int status,
				  FdEventHandlerPtr event,
				  StreamRequestPtr request);
int httpServeObjectHandler(int, ConditionHandlerPtr);
int httpClientSideRequest(HTTPRequestPtr request);
int httpClientSideHandler(int status,
			  FdEventHandlerPtr event, StreamRequestPtr srequest);


typedef struct _SpecialRequest {
	ObjectPtr object;
	int fd;
	void *buf;
	int offset;
	pid_t pid;
} SpecialRequestRec, *SpecialRequestPtr;

extern int disableConfiguration;
extern int disableIndexing;

void preinitLocal(void);
void alternatingHttpStyle(FILE * out, char *id);
int httpLocalRequest(ObjectPtr object, int method, int from, int to,
		     HTTPRequestPtr, void *);
int httpSpecialRequest(ObjectPtr object, int method, int from, int to,
		       HTTPRequestPtr, void *);
int httpSpecialSideRequest(ObjectPtr object, int method, int from, int to,
			   HTTPRequestPtr requestor, void *closure);
int specialRequestHandler(int status,
			  FdEventHandlerPtr event, StreamRequestPtr request);
int httpSpecialDoSide(HTTPRequestPtr requestor);
int httpSpecialClientSideHandler(int status,
				 FdEventHandlerPtr event,
				 StreamRequestPtr srequest);
int httpSpecialDoSideFinish(AtomPtr data, HTTPRequestPtr requestor);



extern int maxDiskEntries;

extern AtomPtr diskCacheRoot;
extern AtomPtr additionalDiskCacheRoot;

typedef struct _DiskCacheEntry {
	char *filename;
	ObjectPtr object;
	int fd;
	off_t offset;
	off_t size;
	int body_offset;
	short local;
	short writeable;
	short metadataDirty;
	struct _DiskCacheEntry *next;
	struct _DiskCacheEntry *previous;
} *DiskCacheEntryPtr, DiskCacheEntryRec;

typedef struct _DiskObject {
	char *location;
	char *filename;
	int body_offset;
	int length;
	int size;
	time_t age;
	time_t access;
	time_t date;
	time_t last_modified;
	time_t expires;
	struct _DiskObject *next;
} DiskObjectRec, *DiskObjectPtr;

struct stat;

extern int maxDiskCacheEntrySize;

void preinitDiskcache(void);
void initDiskcache(void);
int destroyDiskEntry(ObjectPtr object, int);
int diskEntrySize(ObjectPtr object);
ObjectPtr objectGetFromDisk(ObjectPtr);
int objectFillFromDisk(ObjectPtr object, int offset, int chunks);
int writeoutMetadata(ObjectPtr object);
int writeoutToDisk(ObjectPtr object, int upto, int max);
void dirtyDiskEntry(ObjectPtr object);
int revalidateDiskEntry(ObjectPtr object);
DiskObjectPtr readDiskObject(char *filename, struct stat *sb);
void indexDiskObjects(FILE * out, const char *root, int r);
void expireDiskObjects(void);


extern int serverExpireTime, dontCacheRedirects;

typedef struct _HTTPServer {
	char *name;
	int port;
	int addrindex;
	int isProxy;
	int version;
	int persistent;
	int pipeline;
	int lies;
	int rtt;
	int rate;
	time_t time;
	int numslots;
	int maxslots;
	HTTPConnectionPtr *connection;
	FdEventHandlerPtr *idleHandler;
	HTTPRequestPtr request, request_last;
	struct _HTTPServer *next;
} HTTPServerRec, *HTTPServerPtr;

extern int parentPort;

void preinitServer(void);
void initServer(void);

void httpServerAbortHandler(ObjectPtr object);
int httpMakeServerRequest(char *name, int port, ObjectPtr object,
			  int method, int from, int to,
			  HTTPRequestPtr requestor);
int httpServerQueueRequest(HTTPServerPtr server, HTTPRequestPtr request);
int httpServerTrigger(HTTPServerPtr server);
int httpServerSideRequest(HTTPServerPtr server);
int httpServerDoSide(HTTPConnectionPtr connection);
int httpServerSideHandler(int status,
			  FdEventHandlerPtr event, StreamRequestPtr srequest);
int httpServerSideHandler2(int status,
			   FdEventHandlerPtr event, StreamRequestPtr srequest);
int httpServerConnectionDnsHandler(int status, GethostbynameRequestPtr request);
int httpServerConnectionHandler(int status,
				FdEventHandlerPtr event,
				ConnectRequestPtr request);
int httpServerConnectionHandlerCommon(int status, HTTPConnectionPtr connection);
void httpServerFinish(HTTPConnectionPtr connection, int s, int offset);

void httpServerReply(HTTPConnectionPtr connection, int immediate);
void httpServerAbort(HTTPConnectionPtr connection, int, int, struct _Atom *);
void httpServerAbortRequest(HTTPRequestPtr request, int, int, struct _Atom *);
void httpServerClientReset(HTTPRequestPtr request);
void httpServerUnpipeline(HTTPRequestPtr request);
int httpServerSendRequest(HTTPConnectionPtr connection);
int
httpServerHandler(int status,
		  FdEventHandlerPtr event, StreamRequestPtr request);
int
httpServerReplyHandler(int status,
		       FdEventHandlerPtr event, StreamRequestPtr request);
int
httpServerIndirectHandler(int status,
			  FdEventHandlerPtr event, StreamRequestPtr request);
int
httpServerDirectHandler(int status,
			FdEventHandlerPtr event, StreamRequestPtr request);
int
httpServerDirectHandler2(int status,
			 FdEventHandlerPtr event, StreamRequestPtr request);
int httpServerRequest(ObjectPtr object, int method, int from, int to,
		      HTTPRequestPtr, void *);
int httpServerHandlerHeaders(int eof,
			     FdEventHandlerPtr event,
			     StreamRequestPtr request,
			     HTTPConnectionPtr connection);
int httpServerReadData(HTTPConnectionPtr, int);
int connectionAddData(HTTPConnectionPtr connection, int skip);
int httpWriteRequest(HTTPConnectionPtr connection, HTTPRequestPtr request, int);

void listServers(FILE *);


typedef struct HTTPRange {
	int from;
	int to;
	int full_length;
} HTTPRangeRec, *HTTPRangePtr;

extern int censorReferer;
extern AtomPtr atomContentType, atomContentEncoding;

void preinitHttpParser(void);
void initHttpParser(void);
int httpParseClientFirstLine(const char *buf, int offset,
			     int *method_return,
			     AtomPtr * url_return, int *version_return);
int httpParseServerFirstLine(const char *buf,
			     int *status_return,
			     int *version_return, AtomPtr * message_return);

int findEndOfHeaders(const char *buf, int from, int to, int *body_return);

int httpParseHeaders(int, AtomPtr, const char *, int, HTTPRequestPtr,
		     AtomPtr *, int *, CacheControlPtr,
		     HTTPConditionPtr *, int *,
		     time_t *, time_t *, time_t *, time_t *, time_t *,
		     int *, int *, char **, AtomPtr *,
		     HTTPRangePtr, HTTPRangePtr, char **, AtomPtr *, AtomPtr *);
int httpFindHeader(AtomPtr header, const char *headers, int hlen,
		   int *value_begin_return, int *value_end_return);
int parseUrl(const char *url, int len,
	     int *x_return, int *y_return, int *port_return, int *z_return);
int urlIsLocal(const char *url, int len);
int urlIsSpecial(const char *url, int len);
int parseChunkSize(const char *buf, int i, int end, int *chunk_size_return);
int checkVia(AtomPtr, AtomPtr);



extern const time_t time_t_max;

int parse_time(const char *buf, int i, int len, time_t * time_return);
int format_time(char *buf, int i, int len, time_t t);


extern AtomPtr forbiddenUrl;
extern int forbiddenRedirectCode;

typedef struct _RedirectRequest {
	AtomPtr url;
	struct _RedirectRequest *next;
	int (*handler) (int, AtomPtr, AtomPtr, AtomPtr, void *);
	void *data;
} RedirectRequestRec, *RedirectRequestPtr;

void preinitForbidden(void);
void initForbidden(void);
int urlIsUncachable(char *url, int length);
int urlForbidden(AtomPtr url,
		 int (*handler) (int, AtomPtr, AtomPtr, AtomPtr, void *),
		 void *closure);
void redirectorKill(void);
int redirectorStreamHandler1(int status,
			     FdEventHandlerPtr event,
			     StreamRequestPtr srequest);
int redirectorStreamHandler2(int status,
			     FdEventHandlerPtr event,
			     StreamRequestPtr srequest);
void redirectorTrigger(void);
int
runRedirector(pid_t * pid_return, int *read_fd_return, int *write_fd_return);



#define L_ERROR 0x1
#define L_WARN 0x2
#define L_INFO 0x4
#define L_FORBIDDEN 0x8
#define L_UNCACHEABLE 0x10
#define L_SUPERSEDED 0x20
#define L_VARY 0x40

#define D_SERVER_CONN 0x100
#define D_SERVER_REQ 0x200
#define D_CLIENT_CONN 0x400
#define D_CLIENT_REQ 0x800
#define D_ATOM_REFCOUNT 0x1000
#define D_REFCOUNT 0x2000
#define D_LOCK 0x4000
#define D_OBJECT 0x8000
#define D_OBJECT_DATA 0x10000
#define D_SERVER_OFFSET 0x20000
#define D_CLIENT_DATA 0x40000
#define D_DNS 0x80000
#define D_CHILD 0x100000
#define D_IO 0x200000

#define LOGGING_DEFAULT (L_ERROR | L_WARN | L_INFO)
#define LOGGING_MAX 0xFF

void preinitLog(void);
void initLog(void);
void reopenLog(void);
void flushLog(void);
int loggingToStderr(void);

void really_do_log(int type, const char *f, ...)
ATTRIBUTE((format(printf, 2, 3)));
void really_do_log_v(int type, const char *f, va_list args)
ATTRIBUTE((format(printf, 2, 0)));
void really_do_log_n(int type, const char *s, int n);
void really_do_log_error(int type, int e, const char *f, ...)
ATTRIBUTE((format(printf, 3, 4)));
void really_do_log_error_v(int type, int e, const char *f, va_list args)
ATTRIBUTE((format(printf, 3, 0)));

extern AtomPtr logFile;

#ifdef __GNUC__
#define DO_BACKTRACE()                  \
  do {                                  \
    int n;                              \
    void *buffer[10];                   \
    n = backtrace(buffer, 5);           \
    fflush(stderr);                     \
    backtrace_symbols_fd(buffer, n, 2); \
 } while(0)
#else
#define DO_BACKTRACE()		
#endif


#if defined __STDC_VERSION__ && __STDC_VERSION__ >= 199901L

#define do_log(_type, ...)                                           \
    do {                                                             \
        if((_type) & (LOGGING_MAX)) really_do_log((_type), __VA_ARGS__); \
    } while(0)
#define do_log_error(_type, _e, ...)                                 \
    do {                                                             \
        if((_type) & (LOGGING_MAX))                                  \
            really_do_log_error((_type), (_e), __VA_ARGS__);         \
    } while(0)

#elif defined(__GNUC__)

#define do_log(_type, _args...)                                \
    do {                                                       \
        if((_type) & (LOGGING_MAX)) really_do_log((_type), _args); \
    } while(0)
#define do_log_error(_type, _e, _args...)                      \
    do {                                                       \
        if((_type) & (LOGGING_MAX))                            \
            really_do_log_error((_type), (_e), _args);         \
    } while(0)

#else



static inline void do_log(int type, const char *f, ...)
{
	va_list args;

	va_start(args, f);
	if ((type & (LOGGING_MAX)) != 0)
		really_do_log_v(type, f, args);
	va_end(args);
}

static inline void do_log_error(int type, int e, const char *f, ...)
{
	va_list args;

	va_start(args, f);
	if ((type & (LOGGING_MAX)) != 0)
		really_do_log_error_v(type, e, f, args);
	va_end(args);
}

#endif

#define do_log_n(_type, _s, _n) \
    do { \
        if((_type) & (LOGGING_MAX)) really_do_log_n((_type), (_s), (_n)); \
    } while(0)


typedef struct _CircularBuffer {
	int head;
	int tail;
	char *buf;
} CircularBufferRec, *CircularBufferPtr;

#define TUNNEL_READER1 1
#define TUNNEL_WRITER1 2
#define TUNNEL_EOF1 4
#define TUNNEL_EPIPE1 8
#define TUNNEL_READER2 16
#define TUNNEL_WRITER2 32
#define TUNNEL_EOF2 64
#define TUNNEL_EPIPE2 128

typedef struct _Tunnel {
	AtomPtr hostname;
	int port;
	int flags;
	int fd1;
	CircularBufferRec buf1;
	int fd2;
	CircularBufferRec buf2;
} TunnelRec, *TunnelPtr;

void do_tunnel(int fd, char *buf, int offset, int len, AtomPtr url);

extern int daemonise;


int timeval_minus_usec(const struct timeval *s1, const struct timeval *s2)
	ATTRIBUTE((pure));


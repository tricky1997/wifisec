#ifndef COMMON_H
#define COMMON_H

#ifndef VERSION_MAJOR

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif 


#define VERSION_MAJOR 0
#define VERSION_MINOR 1


#define STRINGIZE0(x) #x
#define STRINGIZE(x) STRINGIZE0(x)
#define STRZCONCAT30(a,b,c) a##b##c
#define STRZCONCAT3(a,b,c) STRZCONCAT30(a,b,c)

#define STUNNEL_VERSION0 STRZCONCAT3(VERSION_MAJOR, . , VERSION_MINOR)
#define STUNNEL_VERSION STRINGIZE(STUNNEL_VERSION0)


#define STUNNEL_VERSION_FIELDS VERSION_MAJOR,VERSION_MINOR,0,0
#define STUNNEL_PRODUCTNAME "wifisec " STUNNEL_VERSION " for " HOST
#endif 

#include "config.h"




#define DEFAULT_STACK_SIZE 65536



#define BUFFSIZE 18432



#define RANDOM_BYTES 64



#define S_EADDRINUSE    EADDRINUSE
#define S_EAGAIN        EAGAIN
#define S_ECONNRESET    ECONNRESET
#define S_EINPROGRESS   EINPROGRESS
#define S_EINTR         EINTR
#define S_EINVAL        EINVAL
#define S_EISCONN       EISCONN
#define S_EMFILE        EMFILE
#ifdef ENFILE
#define S_ENFILE        ENFILE
#endif
#ifdef ENOBUFS
#define S_ENOBUFS       ENOBUFS
#endif
#ifdef ENOMEM
#define S_ENOMEM        ENOMEM
#endif
#define S_ENOPROTOOPT   ENOPROTOOPT
#define S_ENOTSOCK      ENOTSOCK
#define S_EOPNOTSUPP    EOPNOTSUPP
#define S_EWOULDBLOCK   EWOULDBLOCK
#define S_ECONNABORTED  ECONNABORTED





#include <sys/types.h>		

#include <stdio.h>

#include <errno.h>
#include <syslog.h>
#include <stdlib.h>
#include <stdarg.h>		
#include <string.h>
#include <ctype.h>		
#include <time.h>
#include <sys/stat.h>		
#include <setjmp.h>
#include <fcntl.h>

#if SIZEOF_UNSIGNED_CHAR == 1
typedef unsigned char u8;
#endif

#if SIZEOF_UNSIGNED_SHORT == 2
typedef unsigned short u16;
#else
typedef unsigned int u16;
#endif

#if SIZEOF_UNSIGNED_INT == 4
typedef unsigned int u32;
#else
typedef unsigned long u32;
#endif

#define get_last_socket_error()     errno
#define set_last_socket_error(e)    (errno=(e))
#define get_last_error()            errno
#define set_last_error(e)           (errno=(e))
#define readsocket(s,b,n)           read((s),(b),(n))
#define writesocket(s,b,n)          write((s),(b),(n))
#define closesocket(s)              close(s)
#define ioctlsocket(a,b,c)          ioctl((a),(b),(c))

    
#include <signal.h>		
#include <sys/wait.h>		
#ifdef HAVE_SYS_RESOURCE_H
#include <sys/resource.h>	
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>		
#endif
#ifdef HAVE_STROPTS_H
#include <stropts.h>
#endif
#ifdef HAVE_MALLOC_H
#include <malloc.h>		
#endif
#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>		
#endif

#if defined(HAVE_POLL) && !defined(BROKEN_POLL)
#ifdef HAVE_POLL_H
#include <poll.h>
#define USE_POLL
#else 
#ifdef HAVE_SYS_POLL_H
#include <sys/poll.h>
#define USE_POLL
#endif 
#endif 
#endif 

#ifdef HAVE_SYS_FILIO_H
#include <sys/filio.h>		
#endif
#include <pwd.h>
#ifdef HAVE_GRP_H
#include <grp.h>
#endif
#ifdef __BEOS__
#include <posix/grp.h>
#endif

#ifdef HAVE_SYS_UIO_H
#include <sys/uio.h>		
#endif 

#include <netinet/in.h>		
#include <sys/socket.h>		
#include <arpa/inet.h>		
#include <sys/time.h>		
#include <sys/ioctl.h>		
#ifdef HAVE_SYS_UN_H
#include <sys/un.h>
#endif
#include <netinet/tcp.h>
#include <netdb.h>
#ifndef INADDR_ANY
#define INADDR_ANY       (u32)0x00000000
#endif
#ifndef INADDR_LOOPBACK
#define INADDR_LOOPBACK  (u32)0x7F000001
#endif

#if defined(HAVE_WAITPID)

#define wait_for_pid(a, b, c) waitpid((a), (b), (c))
#define HAVE_WAIT_FOR_PID 1
#elif defined(HAVE_WAIT4)

#define wait_for_pid(a, b, c) wait4((a), (b), (c), NULL)
#define HAVE_WAIT_FOR_PID 1
#endif


#ifndef SOL_TCP
#define SOL_TCP SOL_SOCKET
#endif 


#ifdef __linux__
#ifndef IP_FREEBIND

#define IP_FREEBIND 15
#endif 
#ifndef IP_TRANSPARENT

#define IP_TRANSPARENT 19
#endif 
#ifdef HAVE_LINUX_NETFILTER_IPV4_H
#include <limits.h>
#include <linux/types.h>
#include <linux/netfilter_ipv4.h>
#endif 
#endif 



#define OPENSSL_THREAD_DEFINES
#include <openssl/opensslconf.h>
#if defined(USE_PTHREAD) && !(defined(OPENSSL_THREADS) || \
    (OPENSSL_VERSION_NUMBER<0x0090700fL && defined(THREADS)))
#error OpenSSL library compiled without thread support
#endif 

#if defined (USE_WIN32) && defined(OPENSSL_FIPS)
#define USE_FIPS
#endif


#define ZLIB

#include <openssl/lhash.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/crypto.h>	
#include <openssl/rand.h>
#ifndef OPENSSL_NO_MD4
#include <openssl/md4.h>
#endif
#include <openssl/des.h>

#ifdef HAVE_OSSL_ENGINE_H
#ifndef OPENSSL_NO_ENGINE
#include <openssl/engine.h>
#else
#undef HAVE_OSSL_ENGINE_H
#endif
#endif 


#if OPENSSL_VERSION_NUMBER<0x00908080L
#ifdef HAVE_OSSL_OCSP_H
#undef HAVE_OSSL_OCSP_H
#endif 
#endif 

#ifdef HAVE_OSSL_OCSP_H
#include <openssl/ocsp.h>
#endif 

#ifdef USE_FIPS
#include <openssl/fips.h>
#include <openssl/fips_rand.h>
#endif 

#if OPENSSL_VERSION_NUMBER<0x0090800fL
#define OPENSSL_NO_ECDH
#endif 

#define OPENSSL_NO_TLSEXT


#define safestring(s) \
    do {unsigned char *p; for(p=(unsigned char *)(s); *p; p++) \
        if(!isprint((int)*p)) *p='.';} while(0)

#define safename(s) \
    do {unsigned char *p; for(p=(s); *p; p++) \
        if(!isalnum((int)*p)) *p='.';} while(0)


#define DEFAULT_LOOPBACK "127.0.0.1"
#define DEFAULT_ANY "0.0.0.0"
#if 0
#define DEFAULT_LOOPBACK "::1"
#define DEFAULT_ANY "::"
#endif

#ifndef offsetof
#define offsetof(T, F) ((unsigned int)((char *)&((T *)0L)->F - (char *)0L))
#endif

#endif 



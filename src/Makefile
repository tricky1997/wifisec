CC=gcc

#ssl
#if you install ssl in a specific place, please edit this
#ssl_PATH=/usr/local/ssl
#ssl_INCLUDE=-I$(ssl_PATH)/include
#ssl_LIB=-L$(ssl_PATH)/lib

#files
common_headers = common.h prototypes.h config.h
common_sources = str.c file.c client.c log.c options.c network.c \
       resolver.c ssl.c ctx.c verify.c sthreads.c fd.c env.c main.c
common_objs = $(common_sources:%.c=%.o)
server_sources = util.c event.c io.c chunk.c atom.c object.c s_log.c diskcache.c s_main.c \
       s_config.c local.c http.c s_client.c server.c tunnel.c \
       http_parse.c parse_time.c dns.c forbidden.c \
       md5import.c md5.c ftsimport.c fts_compat.c
server_objs = util.o event.o io.o chunk.o atom.o object.o s_log.o diskcache.o s_main.o \
       s_config.o local.o http.o s_client.o server.o tunnel.o \
       http_parse.o parse_time.o dns.o forbidden.o \
       md5import.o ftsimport.o

#bin
bin_PROGRAMS=wifisec

wifisec_ldflags = $(ssl_LIB) 
wifisec_ldlibs = -lssl -lcrypto -ldl 

CPPFLAGS=-g -Wall -Wextra $(ssl_INCLUDE)
LDFLAGS=$(wifisec_LDFLAGS)


#############################################################
.PHONY:all clean

all: $(bin_PROGRAMS) 

$(bin_PROGRAMS): $(common_objs) $(server_objs)
	-rm s_main.o
	$(CC) $(CPPFLAGS) -c s_main.c
	$(CC) $(CPPFLAGS) $(wifisec_ldflags) -o $@ $(common_objs) $(wifisec_ldlibs) $(server_objs)

polipo: $(server_objs)
	-rm s_main.o
	$(CC) $(CPPFLAGS) -DSOLO -c s_main.c
	$(CC) $(CPPFLAGS) $(wifisec_ldflags) -o $@ $(server_objs)

clean:
	-rm -f $(bin_PROGRAMS)
	-rm -f *.o *~

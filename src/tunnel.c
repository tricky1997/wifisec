#include "s_server.h"

void do_tunnel(int fd, char *buf, int offset, int len, AtomPtr url)
{
	int n;
	assert(buf);
	(void)offset;
	(void)len;
	n = httpWriteErrorHeaders(buf, CHUNK_SIZE, 0, 1,
				  501, internAtom("CONNECT not available "
						  "in this version."),
				  1, NULL, url->string, url->length, NULL);
	releaseAtom(url);
	if (n >= 0) {
		write(fd, buf, n);
	}
	dispose_chunk(buf);
	lingeringClose(fd);
	return;
}

#include "common.h"
#include "prototypes.h"

DISK_FILE *file_fdopen(int fd)
{
	DISK_FILE *df;

	df = str_alloc(sizeof(DISK_FILE));
	df->fd = fd;
	return df;
}

DISK_FILE *file_open(char *name, int wr)
{
	DISK_FILE *df;
	int fd, flags;

	
	if (wr)
		flags = O_CREAT | O_WRONLY | O_APPEND;
	else
		flags = O_RDONLY;
#ifdef O_NONBLOCK
	flags |= O_NONBLOCK;
#elif defined O_NDELAY
	flags |= O_NDELAY;
#endif
#ifdef O_CLOEXEC
	flags |= O_CLOEXEC;
#endif 
	fd = open(name, flags, 0640);
	if (fd < 0) {
		ioerror(name);
		return NULL;
	}

	
	df = str_alloc(sizeof df);
	df->fd = fd;
	return df;
}

void file_close(DISK_FILE * df)
{
	if (!df)		
		return;
	close(df->fd);
	str_free(df);
}

int file_getline(DISK_FILE * df, char *line, int len)
{
	
	
	int i;
	int num;

	if (!df)		
		return -1;

	for (i = 0; i < len - 1; i++) {
		num = read(df->fd, line + i, 1);
		if (num != 1) {	
			if (i)	
				break;
			else
				return -1;
		}
		if (line[i] == '\n')	
			break;
		if (line[i] == '\r')	
			--i;	
	}
	line[i] = '\0';
	return i;
}

int file_putline(DISK_FILE * df, char *line)
{
	int len;
	char *buff;
	int num;

	len = strlen(line);
	buff = str_alloc(len + 2);	
	strcpy(buff, line);
	buff[len++] = '\n';	
	
	num = write(df ? df->fd : 2, buff, len);
	str_free(buff);
	return num;
}




#ifndef _FTS_COMPAT_H
#define _FTS_COMPAT_H

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

#include "s_server.h"

#include <regex.h>

typedef struct _Domain {
	int length;
	char domain[1];
} DomainRec, *DomainPtr;

AtomPtr forbiddenFile = NULL;
AtomPtr forbiddenUrl = NULL;
int forbiddenRedirectCode = 302;

AtomPtr redirector = NULL;
int redirectorRedirectCode = 302;

DomainPtr *forbiddenDomains = NULL;
regex_t *forbiddenRegex = NULL;

AtomPtr uncachableFile = NULL;
DomainPtr *uncachableDomains = NULL;
regex_t *uncachableRegex = NULL;



static DomainPtr *domains;
static char *regexbuf;
static int rlen, rsize, dlen, dsize;

static int atomSetterForbidden(ConfigVariablePtr, void *);

void preinitForbidden(void)
{
	CONFIG_VARIABLE_SETTABLE(forbiddenUrl, CONFIG_ATOM, configAtomSetter,
				 "URL to which forbidden requests "
				 "should be redirected.");
	CONFIG_VARIABLE_SETTABLE(forbiddenRedirectCode, CONFIG_INT,
				 configIntSetter, "Redirect code, 301 or 302.");
	CONFIG_VARIABLE_SETTABLE(forbiddenFile, CONFIG_ATOM,
				 atomSetterForbidden,
				 "File specifying forbidden URLs.");
	CONFIG_VARIABLE_SETTABLE(uncachableFile, CONFIG_ATOM,
				 atomSetterForbidden,
				 "File specifying uncachable URLs.");
}

static int atomSetterForbidden(ConfigVariablePtr var, void *value)
{
	initForbidden();
	return configAtomSetter(var, value);
}

int readDomainFile(char *filename)
{
	FILE *in;
	char buf[512];
	char *rs;
	int i, j, is_regex, start;

	in = fopen(filename, "r");
	if (in == NULL) {
		if (errno != ENOENT)
			do_log_error(L_ERROR, errno, "Couldn't open file %s",
				     filename);
		return -1;
	}

	while (1) {
		rs = fgets(buf, 512, in);
		if (rs == NULL)
			break;
		for (i = 0; i < 512; i++) {
			if (buf[i] != ' ' && buf[i] != '\t')
				break;
		}
		start = i;
		for (i = start; i < 512; i++) {
			if (buf[i] == '#' || buf[i] == '\r' || buf[i] == '\n')
				break;
		}
		while (i > start) {
			if (buf[i - 1] != ' ' && buf[i - 1] != '\t')
				break;
			i--;
		}

		if (i <= start)
			continue;

		

		is_regex = 0;
		for (j = start; j < i; j++) {
			if (buf[j] == '\\' || buf[j] == '*' || buf[j] == '/') {
				is_regex = 1;
				break;
			}
		}

		if (is_regex) {
			while (rlen + i - start + 8 >= rsize) {
				char *new_regexbuf;
				new_regexbuf = realloc(regexbuf, rsize * 2 + 1);
				if (new_regexbuf == NULL) {
					do_log(L_ERROR,
					       "Couldn't reallocate regex.\n");
					fclose(in);
					return -1;
				}
				regexbuf = new_regexbuf;
				rsize = rsize * 2 + 1;
			}
			if (rlen != 0)
				rlen = snnprintf(regexbuf, rlen, rsize, "|");
			rlen = snnprintf(regexbuf, rlen, rsize, "(");
			rlen =
			    snnprint_n(regexbuf, rlen, rsize, buf + start,
				       i - start);
			rlen = snnprintf(regexbuf, rlen, rsize, ")");
		} else {
			DomainPtr new_domain;
			if (dlen >= dsize - 1) {
				DomainPtr *new_domains;
				new_domains = realloc(domains, (dsize * 2 + 1) *
						      sizeof(DomainPtr));
				if (new_domains == NULL) {
					do_log(L_ERROR,
					       "Couldn't reallocate domain list.\n");
					fclose(in);
					return -1;
				}
				domains = new_domains;
				dsize = dsize * 2 + 1;
			}
			new_domain = malloc(sizeof(DomainRec) - 1 + i - start);
			if (new_domain == NULL) {
				do_log(L_ERROR, "Couldn't allocate domain.\n");
				fclose(in);
				return -1;
			}
			new_domain->length = i - start;
			memcpy(new_domain->domain, buf + start, i - start);
			domains[dlen++] = new_domain;
		}
	}
	fclose(in);
	return 1;
}

void
parseDomainFile(AtomPtr file,
		DomainPtr ** domains_return, regex_t ** regex_return)
{
	struct stat ss;
	int rc;

	if (*domains_return) {
		DomainPtr *domain = *domains_return;
		while (*domain) {
			free(*domain);
			domain++;
		}
		free(*domains_return);
		*domains_return = NULL;
	}

	if (*regex_return) {
		regfree(*regex_return);
		*regex_return = NULL;
	}

	if (!file || file->length == 0)
		return;

	domains = malloc(64 * sizeof(DomainPtr));
	if (domains == NULL) {
		do_log(L_ERROR, "Couldn't allocate domain list.\n");
		return;
	}
	dlen = 0;
	dsize = 64;

	regexbuf = malloc(512);
	if (regexbuf == NULL) {
		do_log(L_ERROR, "Couldn't allocate regex.\n");
		free(domains);
		return;
	}
	rlen = 0;
	rsize = 512;

	rc = stat(file->string, &ss);
	if (rc < 0) {
		if (errno != ENOENT)
			do_log_error(L_WARN, errno, "Couldn't stat file %s",
				     file->string);
	} else {
		if (!S_ISDIR(ss.st_mode))
			readDomainFile(file->string);
		else {
			char *fts_argv[2];
			FTS *fts;
			FTSENT *fe;
			fts_argv[0] = file->string;
			fts_argv[1] = NULL;
			fts = fts_open(fts_argv, FTS_LOGICAL, NULL);
			if (fts) {
				while (1) {
					fe = fts_read(fts);
					if (!fe)
						break;
					if (fe->fts_info != FTS_D
					    && fe->fts_info != FTS_DP
					    && fe->fts_info != FTS_DC
					    && fe->fts_info != FTS_DNR)
						readDomainFile(fe->fts_accpath);
				}
				fts_close(fts);
			} else {
				do_log_error(L_ERROR, errno,
					     "Couldn't scan directory %s",
					     file->string);
			}
		}
	}

	if (dlen > 0) {
		domains[dlen] = NULL;
	} else {
		free(domains);
		domains = NULL;
	}

	regex_t *regex;

	if (rlen > 0) {
		regex = malloc(sizeof(regex_t));
		rc = regcomp(regex, regexbuf, REG_EXTENDED | REG_NOSUB);
		if (rc != 0) {
			do_log(L_ERROR, "Couldn't compile regex: %d.\n", rc);
			free(regex);
			regex = NULL;
		}
	} else {
		regex = NULL;
	}
	free(regexbuf);

	*domains_return = domains;
	*regex_return = regex;

	return;
}

void initForbidden(void)
{
	redirectorKill();

	if (forbiddenFile)
		forbiddenFile = expandTilde(forbiddenFile);

	if (forbiddenFile == NULL) {
		forbiddenFile =
		    expandTilde(internAtom("~/.s_server-forbidden"));
		if (forbiddenFile) {
			if (access(forbiddenFile->string, F_OK) < 0) {
				releaseAtom(forbiddenFile);
				forbiddenFile = NULL;
			}
		}
	}

	if (forbiddenFile == NULL) {
		if (access("/etc/s_server/forbidden", F_OK) >= 0)
			forbiddenFile = internAtom("/etc/s_server/forbidden");
	}

	parseDomainFile(forbiddenFile, &forbiddenDomains, &forbiddenRegex);

	if (uncachableFile)
		uncachableFile = expandTilde(uncachableFile);

	if (uncachableFile == NULL) {
		uncachableFile =
		    expandTilde(internAtom("~/.s_server-uncachable"));
		if (uncachableFile) {
			if (access(uncachableFile->string, F_OK) < 0) {
				releaseAtom(uncachableFile);
				uncachableFile = NULL;
			}
		}
	}

	if (uncachableFile == NULL) {
		if (access("/etc/s_server/uncachable", F_OK) >= 0)
			uncachableFile = internAtom("/etc/s_server/uncachable");
	}

	parseDomainFile(uncachableFile, &uncachableDomains, &uncachableRegex);

	return;
}

int urlIsMatched(char *url, int length, DomainPtr * domains, regex_t * regex)
{
	if (length < 8)
		return 0;

	if (memcmp(url, "http://", 7) != 0)
		return 0;

	if (domains) {
		int i;
		DomainPtr *domain;
		for (i = 8; i < length; i++) {
			if (url[i] == '/')
				break;
		}
		domain = domains;
		while (*domain) {
			if ((*domain)->length <= (i - 7) &&
			    (url[i - (*domain)->length - 1] == '.' ||
			     url[i - (*domain)->length - 1] == '/') &&
			    memcmp(url + i - (*domain)->length,
				   (*domain)->domain, (*domain)->length) == 0)
				return 1;
			domain++;
		}
	}

	if (regex) {
		
		char smallcopy[50];
		char *urlcopy;
		int rc;

		if (length < 50) {
			urlcopy = smallcopy;
		} else {
			urlcopy = malloc(length + 1);
			if (urlcopy == NULL)
				return 0;
		}
		memcpy(urlcopy, url, length);
		urlcopy[length] = '\0';

		rc = regexec(regex, urlcopy, 0, NULL, 0);

		if (urlcopy != smallcopy)
			free(urlcopy);

		return !rc;
	}
	return 0;
}

int urlIsUncachable(char *url, int length)
{
	return urlIsMatched(url, length, uncachableDomains, uncachableRegex);
}

int
urlForbidden(AtomPtr url,
	     int (*handler) (int, AtomPtr, AtomPtr, AtomPtr, void *),
	     void *closure)
{
	int forbidden = urlIsMatched(url->string, url->length,
				     forbiddenDomains, forbiddenRegex);
	int code = 0;
	AtomPtr message = NULL, headers = NULL;

	if (forbidden) {
		message = internAtomF("Forbidden URL %s", url->string);
		if (forbiddenUrl) {
			code = forbiddenRedirectCode;
			headers =
			    internAtomF("\r\nLocation: %s",
					forbiddenUrl->string);
		} else {
			code = 403;
		}
	}

	handler(code, url, message, headers, closure);
	return 1;
}

void redirectorKill(void)
{
	return;
}

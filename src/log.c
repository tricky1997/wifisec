#include "common.h"
#include "prototypes.h"

static void log_raw(const int, const char *, const char *, const char *);

static DISK_FILE *outfile = NULL;
static struct LIST {		
	struct LIST *next;
	int level;
	char *stamp, *id, *text;
} *head = NULL, *tail = NULL;
static LOG_MODE mode = LOG_MODE_NONE;

static int syslog_opened = 0;

void syslog_open(void)
{
	syslog_close();
	if (global_options.option.syslog)
		openlog("wifisec", LOG_CONS | LOG_NDELAY,
			global_options.facility);
	syslog_opened = 1;
}

void syslog_close(void)
{
	if (syslog_opened) {
		if (global_options.option.syslog)
			closelog();
		syslog_opened = 0;
	}
}

void log_open(void)
{
	if (global_options.output_file) {	
		outfile = file_open(global_options.output_file, 1);
		if (!outfile)
			s_log(LOG_ERR, "Unable to open output file: %s",
			      global_options.output_file);
	}
	log_flush(LOG_MODE_CONFIGURED);
}

void log_close(void)
{
	mode = LOG_MODE_NONE;
	if (outfile) {
		file_close(outfile);
		outfile = NULL;
	}
}

void log_flush(LOG_MODE new_mode)
{
	struct LIST *tmp;

	if (mode != LOG_MODE_CONFIGURED)
		mode = new_mode;

	while (head) {
		log_raw(head->level, head->stamp, head->id, head->text);
		str_free(head->stamp);
		str_free(head->id);
		str_free(head->text);
		tmp = head;
		head = head->next;
		str_free(tmp);
	}
	head = tail = NULL;
}

void s_log(int level, const char *format, ...)
{
	va_list ap;
	char *text, *stamp, *id;
	struct LIST *tmp;
	int libc_error, socket_error;
	time_t gmt;
	struct tm *timeptr;
#if defined(HAVE_LOCALTIME_R) && defined(_REENTRANT)
	struct tm timestruct;
#endif

	
	if (mode == LOG_MODE_CONFIGURED && level > global_options.debug_level)
		return;

	libc_error = get_last_error();
	socket_error = get_last_socket_error();

	time(&gmt);
#if defined(HAVE_LOCALTIME_R) && defined(_REENTRANT)
	timeptr = localtime_r(&gmt, &timestruct);
#else
	timeptr = localtime(&gmt);
#endif
	stamp = str_printf("%04d.%02d.%02d %02d:%02d:%02d",
			   timeptr->tm_year + 1900, timeptr->tm_mon + 1,
			   timeptr->tm_mday, timeptr->tm_hour, timeptr->tm_min,
			   timeptr->tm_sec);
	id = str_printf("LOG%d[%lu:%lu]", level, wifisec_process_id(),
			wifisec_thread_id());
	va_start(ap, format);
	text = str_vprintf(format, ap);
	va_end(ap);

	if (mode == LOG_MODE_NONE) {	
		tmp = str_alloc(sizeof(struct LIST));
		str_detach(tmp);
		tmp->next = NULL;
		tmp->level = level;
		tmp->stamp = stamp;
		str_detach(tmp->stamp);
		tmp->id = id;
		str_detach(tmp->id);
		tmp->text = text;
		str_detach(tmp->text);
		if (tail)
			tail->next = tmp;
		else
			head = tmp;
		tail = tmp;
	} else {		
		log_raw(level, stamp, id, text);
		str_free(stamp);
		str_free(id);
		str_free(text);
	}

	set_last_error(libc_error);
	set_last_socket_error(socket_error);
}

static void log_raw(const int level, const char *stamp,
		    const char *id, const char *text)
{
	char *line;

	
	if (mode == LOG_MODE_CONFIGURED) {	
		line = str_printf("%s %s: %s", stamp, id, text);
		if (level <= global_options.debug_level) {
			if (global_options.option.syslog)
				syslog(level, "%s: %s", id, text);
			if (outfile)
				file_putline(outfile, line);	
		}
	} else			
		line = str_dup(text);	

	
	if (mode == LOG_MODE_ERROR ||	
	    (mode == LOG_MODE_INFO && level < LOG_DEBUG) ||
	    (level <= global_options.debug_level &&
	     global_options.option.foreground))
		fprintf(stderr, "%s\n", line);	

	str_free(line);
}


void fatal_debug(char *error, char *file, int line)
{
	char text[80];
	snprintf(text, sizeof text,	
		 "INTERNAL ERROR: %s at %s, line %d\n", error, file, line);

	if (outfile) {
		
		write(outfile ? outfile->fd : 2, text, strlen(text));
	}

	if (mode != LOG_MODE_CONFIGURED || global_options.option.foreground)
		fputs(text, stderr);

	snprintf(text, sizeof text,	
		 "INTERNAL ERROR: %s at %s, line %d", error, file, line);

	if (global_options.option.syslog)
		syslog(LOG_CRIT, "%s", text);

	abort();
}

void ioerror(const char *txt)
{				
	log_error(LOG_ERR, get_last_error(), txt);
}

void sockerror(const char *txt)
{				
	log_error(LOG_ERR, get_last_socket_error(), txt);
}

void log_error(int level, int error, const char *txt)
{				
	s_log(level, "%s: %s (%d)", txt, s_strerror(error), error);
}

char *s_strerror(int errnum)
{
	return strerror(errnum);
}



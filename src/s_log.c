
#include "s_server.h"


static int logLevel = LOGGING_DEFAULT;
static int logSyslog = 0;
AtomPtr logFile = NULL;
static FILE *logF;

#define STR(x) XSTR(x)
#define XSTR(x) #x

static void initSyslog(void);


void preinitLog()
{
	CONFIG_VARIABLE_SETTABLE(logLevel, CONFIG_HEX, configIntSetter,
				 "Logging level (max = " STR(LOGGING_MAX) ").");
	CONFIG_VARIABLE(logFile, CONFIG_ATOM,
			"Log file (stderr if empty and logSyslog is unset).");

	logF = stderr;
}

int loggingToStderr(void)
{
	return (logF == stderr);
}

void initLog(void)
{
	if (daemonise && logFile == NULL && !logSyslog)
		logFile = internAtom("./s_server.log");

	if (logFile != NULL && logFile->length > 0) {
		FILE *f;
		f = fopen(logFile->string, "a");
		if (f == NULL) {
			do_log_error(L_ERROR, errno,
				     "Couldn't open log file %s",
				     logFile->string);
			exit(1);
		}
		setvbuf(f, NULL, _IOLBF, 0);
		logF = f;
	}

	if (logSyslog) {
		initSyslog();

		if (logFile == NULL) {
			logF = NULL;
		}
	}
}

static void initSyslog()
{
	return;
}



void flushLog()
{
	if (logF)
		fflush(logF);
}

void reopenLog()
{
	if (logFile) {
		FILE *f;
		f = fopen(logFile->string, "a");
		if (f == NULL) {
			do_log_error(L_ERROR, errno,
				     "Couldn't reopen log file %s",
				     logFile->string);
			exit(1);
		}
		setvbuf(f, NULL, _IOLBF, 0);
		fclose(logF);
		logF = f;
	}

	if (logSyslog) {
		initSyslog();
	}
}

void really_do_log(int type, const char *f, ...)
{
	va_list args;

	va_start(args, f);
	if (type & LOGGING_MAX & logLevel)
		really_do_log_v(type, f, args);
	va_end(args);
}

void really_do_log_v(int type, const char *f, va_list args)
{
	if (type & LOGGING_MAX & logLevel) {
		if (logF)
			vfprintf(logF, f, args);
	}
}

void really_do_log_error(int type, int e, const char *f, ...)
{
	va_list args;
	va_start(args, f);
	if (type & LOGGING_MAX & logLevel)
		really_do_log_error_v(type, e, f, args);
	va_end(args);
}

void really_do_log_error_v(int type, int e, const char *f, va_list args)
{
	if ((type & LOGGING_MAX & logLevel) != 0) {
		char *es = pstrerror(e);
		if (es == NULL)
			es = "Unknown error";

		if (logF) {
			vfprintf(logF, f, args);
			fprintf(logF, ": %s\n", es);
		}
	}
}

void really_do_log_n(int type, const char *s, int n)
{
	if ((type & LOGGING_MAX & logLevel) != 0) {
		if (logF) {
			fwrite(s, n, 1, logF);
		}
	}
}

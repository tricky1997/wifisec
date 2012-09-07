
#include "common.h"
#include "prototypes.h"

static int init_prng(GLOBAL_OPTIONS *);
static int add_rand_file(GLOBAL_OPTIONS *, const char *);

int cli_index, opt_index;	

int ssl_init(void)
{				
	SSL_load_error_strings();
	SSL_library_init();
	cli_index = SSL_get_ex_new_index(0, "cli index", NULL, NULL, NULL);
	opt_index = SSL_CTX_get_ex_new_index(0, "opt index", NULL, NULL, NULL);
	if (cli_index < 0 || opt_index < 0)
		return 1;
	ENGINE_load_builtin_engines();
	return 0;
}

int ssl_configure(GLOBAL_OPTIONS * global)
{				
	if (init_prng(global))
		 return 1;
	s_log(LOG_DEBUG, "PRNG seeded successfully");
	return 0;		
}

static int init_prng(GLOBAL_OPTIONS * global)
{
	int totbytes = 0;
	char filename[256];
	int bytes;

	bytes = 0;		

	filename[0] = '\0';

	if (global->rand_file) {
		totbytes += add_rand_file(global, global->rand_file);
		if (RAND_status())
			return 0;	
	}

	
	RAND_file_name(filename, 256);
	if (filename[0]) {
		totbytes += add_rand_file(global, filename);
		if (RAND_status())
			return 0;	
	}
#ifdef RANDOM_FILE
	totbytes += add_rand_file(global, RANDOM_FILE);
	if (RAND_status())
		return 0;	
#endif

	if (global->egd_sock) {
		if ((bytes = RAND_egd(global->egd_sock)) == -1) {
			s_log(LOG_WARNING, "EGD Socket %s failed",
			      global->egd_sock);
			bytes = 0;
		} else {
			totbytes += bytes;
			s_log(LOG_DEBUG,
			      "Snagged %d random bytes from EGD Socket %s",
			      bytes, global->egd_sock);
		}
	}
	
	totbytes += add_rand_file(global, "/dev/urandom");
	if (RAND_status())
		return 0;	

	
	s_log(LOG_ERR, "PRNG seeded with %d bytes total", totbytes);
	s_log(LOG_ERR, "PRNG was not seeded with enough random bytes");
	return 1;		
}

static int add_rand_file(GLOBAL_OPTIONS * global, const char *filename)
{
	int readbytes;
	int writebytes;
	struct stat sb;

	if (stat(filename, &sb))
		return 0;	
	if ((readbytes = RAND_load_file(filename, global->random_bytes)))
		 s_log(LOG_DEBUG, "Snagged %d random bytes from %s",
		       readbytes, filename);
	else
		s_log(LOG_INFO, "Unable to retrieve any random data from %s",
		      filename);
	
	if (global->option.rand_write && (sb.st_mode & S_IFREG)) {
		writebytes = RAND_write_file(filename);
		if (writebytes == -1)
			s_log(LOG_WARNING,
			      "Failed to write strong random data to %s - "
			      "may be a permissions or seeding problem",
			      filename);
		else
			s_log(LOG_DEBUG, "Wrote %d new random bytes to %s",
			      writebytes, filename);
	}
	return readbytes;
}



#include "common.h"
#include "prototypes.h"

#ifndef va_copy
#ifdef __va_copy
#define va_copy(dst, src) __va_copy((dst), (src))
#else 
#define va_copy(dst, src) memcpy(&(dst), &(src), sizeof(va_list))
#endif 
#endif 

static u8 canary[10];		
static volatile int canary_initialized = 0;

typedef struct alloc_list_struct ALLOC_LIST;

typedef struct {
	ALLOC_LIST *head;
	size_t bytes, blocks;
} ALLOC_TLS;

struct alloc_list_struct {
	ALLOC_LIST *prev, *next;
	ALLOC_TLS *tls;
	size_t size;
	int valid_canary;
	unsigned int magic;
	
} __attribute__ ((aligned(16)));

static void set_alloc_tls(ALLOC_TLS *);
static ALLOC_TLS *get_alloc_tls();
static ALLOC_LIST *get_alloc_list_ptr(void *, char *, int);

char *str_dup(const char *str)
{
	char *retval;

	retval = str_alloc(strlen(str) + 1);
	strcpy(retval, str);
	return retval;
}

char *str_printf(const char *format, ...)
{
	char *txt;
	va_list arglist;

	va_start(arglist, format);
	txt = str_vprintf(format, arglist);
	va_end(arglist);
	return txt;
}

char *str_vprintf(const char *format, va_list start_ap)
{
	int n, size = 32;
	char *p, *np;
	va_list ap;

	p = str_alloc(size);
	for (;;) {
		va_copy(ap, start_ap);
		n = vsnprintf(p, size, format, ap);
		if (n > -1 && n < size)
			return p;
		if (n > -1)	
			size = n + 1;	
		else		
			size *= 2;	
		np = str_realloc(p, size);
		p = np;		
	}
}

static ALLOC_TLS *global_tls = NULL;

static void set_alloc_tls(ALLOC_TLS * tls)
{
	global_tls = tls;
}

static ALLOC_TLS *get_alloc_tls()
{
	return global_tls;
}

void str_canary_init()
{
	if (canary_initialized)	
		return;
	RAND_bytes(canary, sizeof canary);
	canary_initialized = 1;	
}

void str_cleanup()
{
	ALLOC_TLS *alloc_tls;

	alloc_tls = get_alloc_tls();
	if (alloc_tls) {
		while (alloc_tls->head)	
			str_free_debug(alloc_tls->head + 1, __FILE__, __LINE__);
		set_alloc_tls(NULL);
		free(alloc_tls);
	}
}

void str_stats()
{
	ALLOC_TLS *alloc_tls;

	alloc_tls = get_alloc_tls();
	if (!alloc_tls) {
		s_log(LOG_DEBUG, "str_stats: alloc_tls not initialized");
		return;
	}
	if (!alloc_tls->blocks && !alloc_tls->bytes)
		return;		
	s_log(LOG_DEBUG, "str_stats: %lu block(s), "
	      "%lu data byte(s), %lu control byte(s)",
	      (unsigned long int)alloc_tls->blocks,
	      (unsigned long int)alloc_tls->bytes,
	      (unsigned long int)(alloc_tls->blocks *
				  (sizeof(ALLOC_LIST) + sizeof canary)));
}

void *str_alloc_debug(size_t size, char *file, int line)
{
	ALLOC_TLS *alloc_tls;
	ALLOC_LIST *alloc_list;

	alloc_tls = get_alloc_tls();
	if (!alloc_tls) {	
		alloc_tls = calloc(1, sizeof(ALLOC_TLS));
		if (!alloc_tls)
			fatal_debug("Out of memory", file, line);
		alloc_tls->head = NULL;
		alloc_tls->bytes = alloc_tls->blocks = 0;
		set_alloc_tls(alloc_tls);
	}
	alloc_list = calloc(1, sizeof(ALLOC_LIST) + size + sizeof canary);
	if (!alloc_list)
		fatal_debug("Out of memory", file, line);

	alloc_list->prev = NULL;
	alloc_list->next = alloc_tls->head;
	alloc_list->tls = alloc_tls;
	alloc_list->size = size;
	alloc_list->valid_canary = canary_initialized;	
	memcpy((u8 *) (alloc_list + 1) + size, canary, sizeof canary);
	alloc_list->magic = 0xdeadbeef;

	if (alloc_tls->head)
		alloc_tls->head->prev = alloc_list;
	alloc_tls->head = alloc_list;
	alloc_tls->bytes += size;
	alloc_tls->blocks++;

	return alloc_list + 1;
}

void *str_realloc_debug(void *ptr, size_t size, char *file, int line)
{
	ALLOC_LIST *previous_alloc_list, *alloc_list;

	if (!ptr)
		return str_alloc(size);
	previous_alloc_list = get_alloc_list_ptr(ptr, file, line);
	alloc_list = realloc(previous_alloc_list,
			     sizeof(ALLOC_LIST) + size + sizeof canary);
	if (!alloc_list)
		fatal_debug("Out of memory", file, line);
	if (alloc_list->tls) {	
		
		if (alloc_list->tls->head == previous_alloc_list)
			alloc_list->tls->head = alloc_list;
		if (alloc_list->next)
			alloc_list->next->prev = alloc_list;
		if (alloc_list->prev)
			alloc_list->prev->next = alloc_list;
		
		alloc_list->tls->bytes += size - alloc_list->size;
	}
	alloc_list->size = size;
	alloc_list->valid_canary = canary_initialized;	
	memcpy((u8 *) (alloc_list + 1) + size, canary, sizeof canary);
	return alloc_list + 1;
}



void str_detach_debug(void *ptr, char *file, int line)
{
	ALLOC_LIST *alloc_list;

	if (!ptr)		
		return;
	alloc_list = get_alloc_list_ptr(ptr, file, line);
	if (alloc_list->tls) {	
		
		if (alloc_list->tls->head == alloc_list)
			alloc_list->tls->head = alloc_list->next;
		if (alloc_list->next)
			alloc_list->next->prev = alloc_list->prev;
		if (alloc_list->prev)
			alloc_list->prev->next = alloc_list->next;
		
		alloc_list->tls->bytes -= alloc_list->size;
		alloc_list->tls->blocks--;
		
		alloc_list->next = NULL;
		alloc_list->prev = NULL;
		alloc_list->tls = NULL;
	}
}

void str_free_debug(void *ptr, char *file, int line)
{
	ALLOC_LIST *alloc_list;

	if (!ptr)		
		return;
	str_detach_debug(ptr, file, line);
	alloc_list = (ALLOC_LIST *) ptr - 1;
	alloc_list->magic = 0xdefec8ed;	
	free(alloc_list);
}

static ALLOC_LIST *get_alloc_list_ptr(void *ptr, char *file, int line)
{
	ALLOC_LIST *alloc_list;

	alloc_list = (ALLOC_LIST *) ptr - 1;
	if (alloc_list->magic != 0xdeadbeef) {	
		if (alloc_list->magic == 0xdefec8ed)
			fatal_debug("Double free attempt", file, line);
		else
			fatal_debug("Bad magic", file, line);	
	}
	if (alloc_list->tls	
	    && alloc_list->tls != get_alloc_tls())
		fatal_debug("Memory allocated in a different thread", file,
			    line);
	if (alloc_list->valid_canary
	    && memcmp((u8 *) ptr + alloc_list->size, canary, sizeof canary))
		fatal_debug("Dead canary", file, line);	
	return alloc_list;
}



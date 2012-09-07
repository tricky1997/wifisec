#include "common.h"
#include "prototypes.h"

unsigned long wifisec_process_id(void)
{
	return (unsigned long)getpid();
}

unsigned long wifisec_thread_id(void)
{
	return 0L;
}

static void null_handler(int sig)
{
	(void)sig;		
	signal(SIGCHLD, null_handler);
}

int create_client(int ls, int s, CLI * arg, void *(*cli) (void *))
{
	switch (fork()) {
	case -1:		
		if (arg)
			str_free(arg);
		if (s >= 0)
			closesocket(s);
		return -1;
	case 0:		
		if (ls >= 0)
			closesocket(ls);
		signal(SIGCHLD, null_handler);
		cli(arg);
		_exit(0);
	default:		
		if (arg)
			str_free(arg);
		if (s >= 0)
			closesocket(s);
	}
	return 0;
}

#ifdef DEBUG_STACK_SIZE

#define STACK_RESERVE (STACK_SIZE/8)
#define VERIFY_AREA ((STACK_SIZE-STACK_RESERVE)/sizeof(u32))
#define TEST_VALUE 0xdeadbeef


void stack_info(int init)
{				
	u32 table[VERIFY_AREA];
	int i, num;
	static int min_num = VERIFY_AREA;

	if (init) {
		for (i = 0; i < VERIFY_AREA; i++)
			table[i] = TEST_VALUE;
	} else {
		
		for (i = 0; i < VERIFY_AREA; i++)
			if (table[i] != TEST_VALUE)
				break;
		num = i;
		
		for (i = 0; i < VERIFY_AREA; i++)
			if (table[VERIFY_AREA - i - 1] != TEST_VALUE)
				break;
		if (i > num)	
			num = i;
		if (num < 64) {
			s_log(LOG_NOTICE, "STACK_RESERVE is too high");
			return;
		}
		if (num < min_num)
			min_num = num;
		s_log(LOG_NOTICE,
		      "stack_info: size=%d, current=%d (%d%%), maximum=%d (%d%%)",
		      STACK_SIZE,
		      (int)((VERIFY_AREA - num) * sizeof(u32)),
		      (int)((VERIFY_AREA -
			     num) * sizeof(u32) * 100 / STACK_SIZE),
		      (int)((VERIFY_AREA - min_num) * sizeof(u32)),
		      (int)((VERIFY_AREA -
			     min_num) * sizeof(u32) * 100 / STACK_SIZE));
	}
}

#endif 



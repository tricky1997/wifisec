#include "s_server.h"

int daemonise = 1;

#ifdef SOLO
#define servermain main
#endif
int servermain(int argc, char **argv)
{
	FdEventHandlerPtr listener;

	CONFIG_VARIABLE(daemonise, CONFIG_BOOLEAN, "Run as a daemon");

	preinitChunks();
	preinitLog();
	preinitObject();
	preinitDns();
	preinitServer();
	preinitHttp();
	preinitDiskcache();
	preinitLocal();
	preinitForbidden();

	initChunks();
	initLog();
	initObject();
	initEvents();
	initHttp();
	initServer();
	initDiskcache();
	initForbidden();

	if (daemonise)
		do_daemonise(loggingToStderr());

	listener = create_listener(proxyAddress->string,
				   proxyPort, httpAccept, NULL);
	if (!listener) {
		exit(1);
	}

	eventLoop();

	(void)argc;
	(void)argv;
	return 0;
}

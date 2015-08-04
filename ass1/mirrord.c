#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>


#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <unistd.h>
#include <err.h>
#include <string.h>


__dead	 void usage(void);

__dead void
usage(void)
{
    extern char *__progname;
    fprintf(stderr, "usage: %s [-46d] [-a access.log] [-l address] [-p port] directory\n", __progname);
    exit(1);
}

int
main (int argc, char *argv[])
{
    /* IP version and int for getopt */
    int ch, ip, port, portFlag = 0;
    /* char* log, address, dirname, port; */
    char* log, *address, *dirname ;

    // check for the minimum number of command line arguments
    if (argc < 2 || argc > 9)
	usage();

    while ((ch = getopt(argc, argv, "46da:l:p:")) != -1)
    {
	switch(ch)
	{
	case '4':
	    printf("ip4");
	    ip = 4;
	    break;
	case '6':
	    printf("ip6");
	    ip = 6;
	    break;
	case 'd':
	    printf("dont daemonize\n");
	    break;
	case 'a':
	    printf("log: %s\n", optarg);
	    log = optarg;
	    break;
	case 'l':
	    printf("address: %s\n", optarg);
	    address = optarg;
	    break;
	case 'p':
	    printf("port: %s\n", optarg);
	    port = atoi(optarg);
	    portFlag = 1;
	    break;
	default:
	    usage();
	}
    }

    if (!portFlag)
    {
	struct servent * s = getservbyname("http", "tcp");
	printf("no port supplied, finding port: ");
	if (s) {
	    printf("%d\n", s->s_port);
	    port = s->s_port;
	} else {
	    err(1, "Could not find/use port");
	    
	}
    }


    dirname = argv[argc - 1];
    printf("dirname: %s\n", dirname);
    return 0;
}

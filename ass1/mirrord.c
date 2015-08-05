#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <arpa/inet.h>

#include <event.h>

#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <fcntl.h>
#include <unistd.h>
#include <err.h>
#include <string.h>


int 	 start_mirror(FILE *, char*, char*);	
void 	 ack_con(int, short, void *);
int  	 print_to_log(FILE*, char*);
__dead void	usage(void);

__dead void
usage(void)
{
    extern char *__progname;
    fprintf(stderr, "usage: %s [-46d] [-a access.log] [-l address] [-p port] directory\n", __progname);
    exit(1);
}

int
print_to_log(FILE* logfile, char* message)
{
    if (logfile == NULL)
    {
	printf("%s\n", message);
    } else {
	fputs(message, logfile);
    }

    return 0;
} 

void
ack_con(int socket, short revents, void *logfile)
{
    int fd;
    struct sockaddr_storage ss;
    socklen_t socklen = sizeof(ss);
    /* printf("accepted connection from \n"); */
    fd = accept(socket, (struct sockaddr *)&ss, &socklen);
    print_to_log(logfile, "logged yo");
    send(fd, "sup", 3, 0);

    close(fd);
}

int
start_mirror(FILE* logfile, char* hostname, char* port)
{
    struct addrinfo hints, *res;
    struct event event;
    int error;
    int s;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = PF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    error = getaddrinfo(hostname, port, &hints, &res);
    if (error)
	errx(1, "%s", gai_strerror(error));

    s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);

    bind(s, res->ai_addr, res->ai_addrlen);

    listen(s, 1);

    event_init();

    event_set(&event, s, EV_READ | EV_PERSIST, ack_con, logfile);
    event_add(&event, NULL);

    event_dispatch();
    
    
    freeaddrinfo(res);
    return 0;
}

int
main (int argc, char *argv[])
{
    /* IP version and int for getopt */
    int ch, ip, daemon = 1, portFlag = 0;
    /* char* log, address, dirname, port; */
    char* log, *address = NULL, *dirname, *port =NULL;
    FILE* logfile = NULL;
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
	    daemon = 0;
	    break;
	case 'a':
	    printf("log: %s\n", optarg);
	    log = optarg;
	    logfile = fopen(log, "a");
	    fputs("mirrord started.\n", logfile);
	    break;
	case 'l':
	    printf("address: %s\n", optarg);
	    address = optarg;
	    break;
	case 'p':
	    printf("port: %s\n", optarg);
	    port = optarg;
	    portFlag = 0;
	    break;
	default:
	    usage();
	}
    }

    /* if (!portFlag) */
    /* { */
    /* 	struct servent * s = getservbyname("http", "tcp"); */
    /* 	printf("no port supplied, finding port: "); */
    /* 	if (s) { */
    /* 	    printf("%d\n", s->s_port); */
    /* 	    port = s->s_port; */
    /* 	} else { */
    /* 	    err(1, "Could not find port\n"); */
    /* 	} */
    /* } */

    if (daemon) {
	/* daemonize the process */
	/* int status, i; */
	pid_t pid, sid;
	if ((pid = fork()) == 0) {
	    
	    umask(0);
	    
	    sid = setsid();
	    close(STDOUT_FILENO);
	    close(STDIN_FILENO);
	    close(STDERR_FILENO);
	    start_mirror(logfile, address, port);
	    
	} else {
	    exit(0);
	    
	}
    } else {
	printf("don't daemonize");
	/* don't daemonize */
	start_mirror(NULL, address, port);
    }

    
    dirname = argv[argc - 1];
    printf("dirname: %s\n", dirname);
    return 0;
}

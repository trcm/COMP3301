#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <arpa/inet.h>

#include <event.h>

#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <err.h>
#include <string.h>

/* #include "http-parser/http_parser.h" */
#include "http_parser.h"
#include "mirrord.h"

#define MAX_REQUESTS 1024

/* global http_parser_settings for all connections */
static http_parser_settings settings;

request *requests[MAX_REQUESTS];
int requestNum;


__dead void
usage(void)
{
	extern char    *__progname;
	fprintf(stderr, "usage: %s [-46d] [-a access.log] [-l address] [-p port] directory\n", __progname);
	exit(1);
}

int
print_to_log(FILE *logfile, char *message)
{
	if (logfile == NULL) {
		fprintf(stdout, message);
		fflush(stdout);
	} else {
		fprintf(logfile, "%s\n", message);
		fflush(logfile);
	}

	return 0;
}

void
ack_con(int sock, short revents, void *logfile)
{
	int 		fd, recvLen;
	struct sockaddr_storage ss;
	socklen_t 	socklen = sizeof(ss);
	
	fd = accept(sock, (struct sockaddr *) & ss, &socklen);
	printf("%d\n", fd);
	// init http_parser
	http_parser * hp = malloc(sizeof(http_parser));
	http_parser_init(hp, HTTP_REQUEST);


	hp->data = &fd;
	/* printf("%d\n", hp->data); */
	char * req = malloc(sizeof(char) * 1024);

	/* do { */
	do{
		recvLen = recv(fd, req, 50, 0);
		http_parser_execute(hp, &settings, req, recvLen);
	} while (recvLen > 0);

	http_parser_execute(hp, &settings, req, recvLen);
	requestNum++;
	close(fd);
}

int
start_mirror(FILE *logfile, char *hostname, char *port)
{
	struct addrinfo hints, *res;
	struct event 	event;
	int 		error;
	int 		s, optval = 1;
	printf("Starting mirrord...\n");
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;
	error = getaddrinfo(hostname, port, &hints, &res);
	if (error)
		errx(1, "%s", gai_strerror(error));

	s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	setsockopt(s, SOL_SOCKET, SO_REUSEPORT, &optval, sizeof(optval));
	bind(s, res->ai_addr, res->ai_addrlen);
	listen(s, 5);


	requests = malloc(sizeof(request) * MAX_REQUESTS);

	event_init();

	event_set(&event, s, EV_READ | EV_PERSIST, ack_con, logfile);
	event_add(&event, NULL);

	event_dispatch();

	freeaddrinfo(res);
	return 0;
}

int
on_complete(http_parser *parser)
{
	printf("Message recieved %d\n", parser->method);
	switch (parser->method)
	{
	case 1:
		
		print_to_log(NULL, "remote arrd [rfc822date] \"GET request_url\" response_code data_bytes\n");
		break;
	case 2:
		
		print_to_log(NULL, "remote arrd [rfc822date] \"HEAD request_url\" response_code data_bytes\n");
		break;
	}
	char * res = "HTTP/1.1 200 OK\n" \
		"Content-Type: text/html\n" \
		"Content-Length: 4\n" \
		"Connection: close\n" \
		"Server: mirrord/s4333060\n" \
		"\r\n"
		"sup\n";
	int * fd = (int *)parser->data;
	

	int sendLen = 0;
	/* do { */
		sendLen = send(*fd, res, strlen(res), MSG_NOSIGNAL);
	/* } while (sendLen > 0); */

	close(*fd);
	return 0;
}

int
on_url(http_parser *parser, const char *at, size_t length)
{
	char url[length + 1];
	strncat(url, at, length);
	printf("GOT URL %s\n", url);
	strncpy(requests[requestNum]->url, url, sizeof(url));
	fflush(stdout);
	return 0;
}	


int
main(int argc, char *argv[])
{
	/* IP version and int for getopt */
	int 		ch       , ip, daemonize = 1, portFlag = 0;
	char           *log, *address = NULL, *dirname, *port = NULL;
	FILE           *logfile = NULL;

	/* initialize requestNum global */
	requestNum = 0;
	
	settings.on_headers_complete = on_complete;
	settings.on_url = on_url;

	/* minimum number of command line arguments */
	if (argc < 2 || argc > 9)
		usage();

	while ((ch = getopt(argc, argv, "46da:l:p:")) != -1) {
		switch (ch) {
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
			daemonize = 0;
			break;
		case 'a':
			printf("log: %s\n", optarg);
			log = optarg;
			logfile = fopen(log, "a+");
			/* fputs("mirrord started.\n", logfile); */
			fprintf(logfile, "%s", "mirrord started.\n");
			fflush(logfile);
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
	/* struct servent * s = getservbyname("http", "tcp"); */
	/* printf("no port supplied, finding port: "); */
	/* if (s) { */
	/* printf("%d\n", s->s_port); */
	/* port = s->s_port; */
	/* } else { */
	/* err(1, "Could not find port\n"); */
	/* } */
	/* } */

	dirname = argv[argc - 1];
	printf("dirname: %s\n", dirname);

	if (daemonize) {
		/* daemonize the process */
		daemon(0, 0);
		start_mirror(logfile, address, port);

	} else {
		/* don't daemonize */
		start_mirror(NULL, address, port);
	}


	return 0;
}

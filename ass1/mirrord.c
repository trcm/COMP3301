#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <netinet/in.h>

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
#define CHUNK 1024

/* global http_parser_settings for all connections */
static http_parser_settings settings;
/* static char* logfile; */

request requests[MAX_REQUESTS];
int requestNum;
int logFlag;
FILE * logptr;

__dead void
usage(void)
{
	extern char    *__progname;
	fprintf(stderr, "usage: %s [-46d] [-a access.log] [-l address] [-p port] directory\n", __progname);
	exit(1);
}

int
print_to_log(char *message)
{
	if (logptr == NULL && logFlag) {
		fprintf(stdout, message);
		fflush(stdout);
	} else if (logptr) {
		fprintf(logptr, "%s", message);
		fflush(logptr);
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
	// init http_parser
	http_parser * hp = malloc(sizeof(http_parser));
	http_parser_init(hp, HTTP_REQUEST);

	
	struct sockaddr_in *s = (struct sockaddr_in *) &ss;
	char *address = inet_ntoa(s->sin_addr);
	
	strncat(requests[requestNum].remote_addr, "\0", 1);
	strncat(requests[requestNum].remote_addr, address, strlen(address));
	
	
	hp->data = &fd;
	/* printf("%d\n", hp->data); */
	char * req = malloc(sizeof(char) * 1024);
	requests[requestNum].headerNum = 0;

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


	/* requests = malloc(sizeof(request) * MAX_REQUESTS); */

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

	switch (parser->method)
	{
	case 1:
		strncpy(requests[requestNum].method, "GET", 3);
		break;
	case 2:
		strncpy(requests[requestNum].method, "HEAD", 4);
		break;
	default:
		/* strncpy(requests[requestNum].method, "HEAD", 4); */
		/* method not supported */
		break;
	}
	/* } while (sendLen > 0); */
	int f = retrieve_file(requests[requestNum].url);
	int * fd = (int *)parser->data;
	if (f > 0) {
		struct stat st;
		fstat(f, &st);
		char *res = malloc(sizeof(char)*1024);

		/* create time buffers for headers and log */
		time_t curr;
		struct tm *modtime;
		struct tm *currtime;
		modtime = gmtime(&st.st_mtime);
		time(&curr);
		currtime = gmtime(&curr);
		char buff[30];
		char cbuff[30];
		strftime(buff, 30, "%a, %d %b %Y %T GMT", modtime);
		strftime(cbuff, 30, "%a, %d %b %Y %T GMT", currtime);

		/* create response header */
		sprintf(res,  
			"HTTP/1.1 200 OK\n"	    \
			"Date: %s\n" \
			"Last-modified: %s\n" \
			"Content-Length: %jd\n" \
			"Connection: close\n" \
			"Server: mirrord/s4333060\n" \
			"\r\n", cbuff, buff, st.st_size);
		int sendLen = 0;
		/* send response header */
		sendLen = send(*fd, res, strlen(res), MSG_NOSIGNAL);

		/* start reading file  */
		void *fData = malloc(sizeof(char)*CHUNK);
		size_t nBytes;
		do {
			/* read chunk from file */
			nBytes = read(f, fData, CHUNK);
			/* send chunk */
			send(*fd, fData, nBytes, MSG_NOSIGNAL);
		} while (nBytes > 0);
		
		/* int i, hNum = requests[requestNum].headerNum; */
		/* /\* get host name for log *\/ */
		/* char fullHost[30]; */
		/* for (i = 0; i < hNum; i++) */
		/* { */
		/* 	if (strcmp(requests[requestNum].headerFields[i], "Host") == 0) */
		/* 	{ */
		/* 		strcpy(fullHost, requests[requestNum].headerValues[i]); */
		/* 		break; */
		/* 	} */
		/* 	fflush(stdout); */
		/* } */

		/* /\* get hostname from the host header field - REFACTOR *\/ */
		/* char hostname[30]; */
		/* uint j; */
		/* for (j = 0; j < strlen(fullHost); j++) */
		/* { */
		/* 	if (fullHost[j] == ':') */
		/* 	{ */
		/* 		hostname[j] = '\0'; */
		/* 		break; */
		/* 	} else { */
		/* 		hostname[j] = fullHost[j]; */
				
		/* 	} */
			
		/* } */
		/* fflush(stdout); */

		char *entry = create_log_entry(requests[requestNum].remote_addr, cbuff, requests[requestNum].method,
					       requests[requestNum].url, 200, st.st_size);
		print_to_log(entry);

		free(fData);
		free(res);
	} else {
		/* send 404 header */
		char *res = "HTTP/1.0 404 NOT FOUND\n"	    \
			"Connection: close\n" \
			"Server: mirrord/s4333060\n" \
			"\r\n";

		/* create time buffers for headers and log */
		time_t curr;
		struct tm *currtime;
		time(&curr);
		currtime = gmtime(&curr);
		char cbuff[30];
		strftime(cbuff, 30, "%a, %d %b %Y %T GMT", currtime);

		fflush(stdout);

		char *entry = create_log_entry(requests[requestNum].remote_addr, cbuff, requests[requestNum].method,
					       requests[requestNum].url, 404, 0);
		print_to_log(entry);
		send(*fd, res, strlen(res), MSG_NOSIGNAL);
	}

	
	close(*fd);
	return 0;
}

int
on_url(http_parser *parser, const char *at, size_t length)
{
	strncpy(requests[requestNum].url, at+1, length-1);
	requests[requestNum].url[length] = '\0'; 
	/* printf("\n\n%s\t-%d\n\n", requests[requestNum].url, requestNum); */
	fflush(stdout);
	return 0;
}	

int
on_header_field(http_parser *parser, const char *at, size_t length)
{
	requests[requestNum].headerNum++;
	char field[1024];
	strncpy(field, at, length);
	field[length] = '\0';
	strncpy(requests[requestNum].headerFields[requests[requestNum].headerNum], field,
		strlen(field));
	return 0;
}

int
on_header_value(http_parser *parser, const char *at, size_t length)
{
	int hNum =  requests[requestNum].headerNum;
	char field[1024];
	strncpy(field, at, length);
	field[length] = '\0';
	strncat(requests[requestNum].headerValues[hNum], field,
		strlen(field));
	return 0;
}

int
retrieve_file(char* filepath)
{
	char *path = getcwd(NULL, 0);

	/* printf("Trying to retrieve %s from %s\n", filepath, path); */
	int fd = open(filepath, O_RDONLY);

	free(path);
	return fd;
}

char*
create_log_entry(char *hostname, char *currentTime, char *method, char *url,
		 int status, int nBytes)
{
	char *entry = malloc(sizeof(char)*CHUNK);
	
	/* Create the new log entry for a http request/response  */
	ssize_t totalSize = strlen(hostname) + strlen(currentTime) +
		strlen(method) + strlen(url) + sizeof(status) * 3+ sizeof(nBytes)* 1024;
	snprintf(entry, totalSize, "%s [%s GMT] \"%s %s\" %d %d\n",
		 hostname, currentTime, method, url, status, nBytes);
	return entry;
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
	logFlag = 0;
	logptr = NULL;

	/* Setup http_parser settings callbacks */
	settings.on_headers_complete = on_complete;
	settings.on_header_field = on_header_field;
	settings.on_header_value = on_header_value;
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
			logFlag = 1;
			daemonize = 0;
			break;
		case 'a':
			printf("log: %s\n", optarg);
			log = optarg;
			logfile = fopen(log, "a+");
			/* fputs("mirrord started.\n", logfile); */
			fprintf(logfile, "%s", "mirrord started.\n");
			logptr = logfile;
			logFlag = 1;
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
	if(chdir(dirname) == -1) {
		err(1, "Could not change to directory");
	}
	printf("dirname: %s\n", dirname);

	if (daemonize) {
		/* daemonize the process */
		daemon(1, 0);
		start_mirror(logfile, address, port);

	} else {
		/* don't daemonize */
		start_mirror(NULL, address, port);
	}


	return 0;
}

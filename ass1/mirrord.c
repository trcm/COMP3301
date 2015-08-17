#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/queue.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include <err.h>
#include <errno.h>
#include <event.h>
#include <fcntl.h>
#include <netdb.h>
#include <semaphore.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "http_parser.h"
#include "mirrord.h"

#define MAX_REQUESTS 1024
#define CHUNK 1024

/* Array to hold information about requests */
struct request       **requests;
/* Counter for requests */
int requestNum;
/* Flags for logging */
int logFlag;
/* Semaphore for use when parsing http requests */
sem_t reqSem;
/* Pointer to the mirrord logfile */
FILE *logptr;
TAILQ_HEAD(listhead, request) head;

/* Simple usage function to be printed if invalid command line arguments are supplied */
__dead void
usage(void)
{
	extern char    *__progname;
	fprintf(stderr, "usage: %s [-46d] [-a access.log] [-l address] [-p port] directory\n", __progname);
	exit(1);
}

/* Output the given message to the mirrord logfile */
int
print_to_log(char *message)
{
	if (logFlag) {
		/* Process hasnot been daemonized, output to stdout. */
		fprintf(stdout, message);
		fflush(stdout);
	} else if (logptr) {
		/* Process has been daemonized, output to the logfile. */

		fprintf(logptr, "%s", message);
		fflush(logptr);
	}
	return 0;
}

/* Accept new connections on the socket */
void
ack_con(int sock, short revents, void *logfile)
{
	int fd, on;
	struct sockaddr_storage ss;
	socklen_t socklen = sizeof(ss);

	on = 1;

	fd = accept(sock, (struct sockaddr *) & ss, &socklen);
	if (fd == -1) {
		switch (errno) {
		case ECONNABORTED:
			/* Connection aborted */
			return;
		default:
			err(1, "An error occured while accepting the connection");
		}

	}

	/* Set the file descriptor to be non-blocking */
	if (ioctl(fd, FIONBIO, &on) == -1)
		err(1, "Failed to set nonblocking fd");

	/* Get the address of the incoming connection */
	struct sockaddr_in *s = (struct sockaddr_in *) & ss;
	char *address = inet_ntoa(s->sin_addr);

	/* Initialize a conn struct for the new connection */
	struct conn *c;
	c = malloc(sizeof(*c));
	c->ev = evbuffer_new();
	c->parser = malloc(sizeof(struct http_parser));

	strncpy(c->remote_addr, address, strlen(address) + 1);
	c->remote_addr[strlen(c->remote_addr)] = '\0';

	event_set(&c->rd_ev, fd, EV_READ | EV_PERSIST, handle_read, c);
	event_set(&c->wr_ev, fd, EV_WRITE, handle_send, c);

	event_add(&c->rd_ev, NULL);
}

/* Handles any read event that will happen on a connections file descriptor */
void
handle_read(int fd, short revents, void *conn)
{
	struct conn *c = conn;
	/* String to hold the request from the client */
	char *req;
	http_parser_settings *settings;
	int peek;
	ssize_t recvLen, parsed;
	char *res, *cbuff, *entry;
	req = malloc(sizeof(char) * 4096);
	res = malloc(sizeof(char) * 100);

	/* Setup settings for the http parser */
	settings = malloc(sizeof(http_parser_settings));
	http_parser_settings_init(settings);
	
	settings->on_url = on_url;
	settings->on_body = on_body;
	http_parser_init(c->parser, HTTP_REQUEST);

	/* Critical section of code  */
	/* Grab the semaphore and assign an incomming connection a particular request number. */
		
	/* sem_wait(&reqSem); */

	struct request * n = malloc(sizeof(struct request));
	TAILQ_INSERT_TAIL(&head, n, requestsQueue);
	requestNum++;
	/* c->reqNum = requestNum; */
	/* c->parser->data = &requestNum; */
	c->parser->data = n;
	/* sem_post(&reqSem); */

	/* Check to see if the connection is still alive */
	peek = recv(fd, req, 50, MSG_PEEK);
	if (peek > 0) {
		recvLen = recv(fd, req, 4096, 0);
		parsed = http_parser_execute(c->parser, settings, req, recvLen);

		/* 
		 * ensure that the data parsed is the same as the data recieved.
		 * Also check to make sure the parser->http_errno was not set, and
		 * if the request is in valid by having a body.
		 */
/* || n->body) { */
		if (recvLen != parsed || c->parser->http_errno) { 
			//TODO send 400 bad request
			// TODO check error number then 400
			cbuff = get_current_time();

			asprintf(&res,
				 "HTTP/1.0 400 Bad request\n" \
				 "Date: %s\n" \
				 "Connection: close\n" \
				 "Server: mirrord/s4333060\n" \
				 "\r\n", cbuff);

			send(fd, res, strlen(res), MSG_NOSIGNAL);
			// TODO get the method
			/* printf("%s\n", http_method_str(c->parser->method)); */
			const char *method = http_method_str(c->parser->method);
			entry = create_log_entry(c->remote_addr,
			   cbuff, method, n->url, 400, 0);
			print_to_log(entry);
			/* printf("%d errno", c->parser->http_errno); */
			/* printf("%s\n", http_errno_name(c->parser->http_errno)); */
			/* printf("%s\n", http_errno_description(c->parser->http_errno)); */
			free(req);
			free(res);
			close_connection(c);
			return;
		} 
			
	} else {
		/* connection ended before the http request was sent */
		/* send and log response */
		cbuff = get_current_time();
		entry = create_log_entry(c->remote_addr,
						   cbuff, "-", "-", 444, 0);
		print_to_log(entry);
		close_connection(c);
		return;

	}
	free(settings);
	free(req);

	/* Trigger write event */
	event_add(&c->wr_ev, NULL);
}

/* Handles writing the response and well as any files back to the connection */
void
handle_send(int fd, short revents, void *conn)
{

	struct conn *c = conn;
	struct request *r = c->parser->data;
	const char *method;
	char *res, *cbuff;
	int f, sendLen;
	char *entry;
	struct stat st;
	struct tm *modtime;
	char buff[30];

	c = conn;
	res = malloc(sizeof(char) * 1024);
	method = http_method_str(c->parser->method);
	/* printf("%s %d\n", http_method_str(c->parser->method), r->body); */
	/* check the method of the connections request */
	switch (c->parser->method) {
	case 1:
		strncpy(r->method, "GET\0", 4);
		break;
	case 2:
		strncpy(r->method, "HEAD\0", 5);
		break;
	default:
		/* method not supported */
		/* log, send respone and return */
		cbuff = get_current_time();
		asprintf(&res,
			 "HTTP/1.0 405 Method not allowed\n" \
			 "Date: %s\n" \
			 "Connection: close\n" \
			 "Server: mirrord/s4333060\n" \
			 "\r\n", cbuff);
		send(fd, res, strlen(res), MSG_NOSIGNAL);
		entry = create_log_entry(c->remote_addr, cbuff, "-",
					  r->url, 405, 0);
		print_to_log(entry);
		free(entry);
		free(res);
		close_connection(c);
		return;
	}

	/* Try and retrieve the file requested */
	/* f = retrieve_file(requests[c->reqNum]->url); */
	f = retrieve_file(r->url);

	/* There was an error with retrieving the file, send a 500 reponse */
	if (f == -1 && errno != ENOENT) {
		cbuff = get_current_time();
		asprintf(&res,
			 "HTTP/1.0 500 Internal Server Error\n" \
			 "Date: %s\n" \
			 "Connection: close\n" \
			 "Server: mirrord/s4333060\n" \
			 "\r\n", cbuff);
		send(fd, res, strlen(res), MSG_NOSIGNAL);

		//TODO get the parser method
		if (c->parser->method == 1) {
			method = "GET\0";
		} else  {
			method = "HEAD\0";
		}
		entry = create_log_entry(c->remote_addr, cbuff, method,
		    r->url, 500, 0);
		print_to_log(entry);
		free(entry);
		free(res);
		free(entry);
		close_connection(c);
		return;
		/* } else if (f == -2) { */
		/* printf("INVALID SEND 403\n"); */
		/* requestNum++; */
		/* sem_post(&reqSem); */
		/* free(res); */
		/* close_connection(c); */
		/* return; */
	}

	if (c->parser->method == 1) {
		/* GET request */
		if (f > 0) {
			/* File exists and is able to be read */
			fstat(f, &st);

			/* create time buffers for headers and log */
			modtime = localtime(&st.st_mtime);
			strftime(buff, 30, "%a, %d %b %Y %T %Z", modtime);
			cbuff = get_current_time();
			/* create response header */
			asprintf(&res,
				 "HTTP/1.0 200 OK\n" \
				 "Date: %s\n" \
				 "Last-modified: %s\n" \
				 "Content-Length: %jd\n" \
				 "Connection: close\n" \
				 "Server: mirrord/s4333060\n" \
				 "\r\n", cbuff, buff, st.st_size);
			sendLen = 0;
			/* send response header */
			sendLen = send(fd, res, strlen(res), MSG_NOSIGNAL);
			/* entry = create_log_entry(c->remote_addr, cbuff, requests[c->reqNum]->method, */
			/* 	 requests[c->reqNum]->url, 200, st.st_size); */
			entry = create_log_entry(c->remote_addr, cbuff, r->method,
				 r->url, 200, st.st_size);

			/* start reading the file */
			evbuffer_free(c->ev);
			c->ev = evbuffer_new();
			c->totalSent = 0;

			c->fileSize = st.st_size;

			event_del(&c->rd_ev);
			event_set(&c->rd_fev, f, EV_READ | EV_PERSIST, read_file, c);
			event_set(&c->wr_fev, fd, EV_WRITE, send_file, c);

			event_add(&c->rd_fev, NULL);

			print_to_log(entry);
		} else {
			/* send 404 header */
			res = "HTTP/1.0 404 NOT FOUND\n" \
				"Connection: close\n" \
				"Server: mirrord/s4333060\n" \
				"\r\n";

			/* create time buffers for headers and log */
			cbuff = get_current_time();

			fflush(stdout);

			entry = create_log_entry(c->remote_addr, cbuff, r->method,
					  r->url, 404, 0);
			print_to_log(entry);
			send(fd, res, strlen(res), MSG_NOSIGNAL);

			free(entry);
			close_connection(c);
			return;
		}

	} else if (c->parser->method == 2) {
		/* HEAD request */
		if (f > 0) {
			fstat(f, &st);
			/* create time buffers for headers and log */
			modtime = localtime(&st.st_mtime);
			strftime(buff, 30, "%a, %d %b %Y %T %Z", modtime);
			cbuff = get_current_time();
			/* create response header */
			asprintf(&res,
				 "HTTP/1.0 200 OK\n" \
				 "Date: %s\n" \
				 "Last-modified: %s\n" \
				 "Content-Length: %jd\n" \
				 "Connection: close\n" \
				 "Server: mirrord/s4333060\n" \
				 "\r\n", cbuff, buff, st.st_size);
			sendLen = 0;
			/* send response header */
			sendLen = send(fd, res, strlen(res), MSG_NOSIGNAL);

			entry = create_log_entry(c->remote_addr, cbuff, r->method,
					  r->url, 200, 0);
			print_to_log(entry);

			free(entry);
			free(res);
			close_connection(c);
			return;
		} else {
			/* send 404 header */
			res = "HTTP/1.0 404 NOT FOUND\n" \
				"Connection: close\n" \
				"Server: mirrord/s4333060\n" \
				"\r\n";

			/* create time buffers for headers and log */
			cbuff = get_current_time();

			entry = create_log_entry(c->remote_addr, cbuff, r->method,
			    r->url, 404, 0);
			print_to_log(entry);
			send(fd, res, strlen(res), MSG_NOSIGNAL);

			/* free(res); */
			free(entry);
			close_connection(c);
			return;
		}
	}
}

/* Reads data from the desired file into an evbuffer */
void
read_file(int fd, short revents, void *conn)
{
	struct conn *c = conn;
	size_t len = 0;

	/* Buffer is not empty, there is still data to be written */
	if (EVBUFFER_LENGTH(c->ev) > 0)
		return;

	/* File transfer has been completed, shut it down */
	if (c->totalSent == (size_t) c->fileSize) {
		close(fd);
		event_del(&c->rd_fev);
		event_del(&c->wr_fev);
		close_connection(c);
		return;
	}

	/* Read file from descriptor */
	len = evbuffer_read(c->ev, fd, 4096);
	c->totalSent = c->totalSent + len;

	/* Trigger file send event */
	event_add(&c->wr_fev, NULL);
}

/* Send the file to a file descriptor from the evbuffer */
void
send_file(int fd, short revents, void *conn)
{
	struct conn *c = conn;
	int sent;

	while (EVBUFFER_LENGTH(c->ev) > 0) {
		sent = evbuffer_write(c->ev, fd);

		/* Check for a closed connection */
		if (sent == -1 && errno == EPIPE) {
			/* Connection closed, cleanup */
			close(fd);
			event_del(&c->rd_fev);
			event_del(&c->wr_fev);
			close_connection(c);
			return;
		}
	}
}

/* Close down a connection and free resources */
void
close_connection(struct conn * c)
{
	struct request *r = c->parser->data;
	TAILQ_REMOVE(&head, r, requestsQueue);
	free(c->parser->data);
	evbuffer_free(c->ev);
	event_del(&c->rd_ev);
	event_del(&c->wr_ev);
	free(c->parser);
	close(EVENT_FD(&c->rd_ev));
	free(c);
}

/* URL callback, will be triggered when a URL is found by the http_parser */
int
on_url(http_parser * parser, const char *at, size_t length)
{
	/* Request number for the connection */
	/* int *num = parser->data; */
	struct request * c = parser->data;
	strncpy(c->url, at + 1, length - 1);
	c->url[length - 1] = '\0';
	/* strncpy(requests[*num]->url, at + 1, length - 1); */
	/* requests[*num]->url[length - 1] = '\0'; */
	return 0;
}

/* Checks to see if there is a body section of the request */
int
on_body(http_parser * parser, const char *at, size_t length)
{
	/* There should be no body in a GET or HEAD request, so 
	 * set the body flag 
	 */
	struct request * c = parser->data;
	c->body = 1;
	return 0;
}
/* int */
/* on_header_field(http_parser *parser, const char *at, size_t length) */
/* { */
/* requests[requestNum]->headerNum++; */
/* int hNum =  requests[requestNum]->headerNum; */
/* char field[1024]; */
/* strncpy(field, at, length); */
/* field[length] = '\0'; */
/* printf("header %s: ", field); */
/* strncpy(requests[requestNum]->headerFields[hNum], field, */
/* strlen(field)); */
/* return 0; */
/* } */

/* int */
/* on_header_value(http_parser *parser, const char *at, size_t length) */
/* { */
/* int hNum =  requests[requestNum]->headerNum; */
/* char field[1024]; */
/* strncpy(field, at, length); */
/* field[length] = '\0'; */
/* printf("%s\n", field); */
/* strncat(requests[requestNum]->headerValues[hNum], field, */
/* strlen(field)); */
/* return 0; */
/* } */

/* Attempt to retrieve the file that the connection indicated */
int
retrieve_file(char *filepath)
{
	int fd ;
	char *path, *absPath;
	struct stat st;
	char *token, *tok, *t1, *t2;

	/* attempt to open the file */
	fd = open(filepath, O_RDONLY);
	/* Get the path for the webroot directory */
	path = getcwd(NULL, 0);
	/* get the absolute path for the requested file */
	absPath = realpath(filepath, NULL);
	
	/* Check if the file is a symlink */
	lstat(filepath, &st);
	if (S_ISLNK(st.st_mode)) {
		return fd;
	}

	if (absPath != NULL) {
		/* Tokenize and loop over the parts of the directories */
		token = strtok_r(path, "/", &t1);
		tok = strtok_r(absPath, "/", &t2);
		while (token != NULL && tok != NULL) {
			if (strcmp(token, tok) != 0) {
				/* 
				 * If the tokens don't match the file path is 
				 * forbidden. 
				 */
				close(fd);
				return -2;
				break;
			}
			token = strtok_r(NULL, "/", &t1);
			tok = strtok_r(NULL, "/", &t2);
		}
		/* Filepath is valid */
	}
	free(absPath);
	free(path);
	return fd;
}

/* Create the log entry from the given parameters */
char*
create_log_entry(char *hostname, char *currentTime, const char *method, char *url,
    int status, int nBytes)
{
	char *entry = malloc(sizeof(char) * CHUNK);
	ssize_t totalSize;
	/* Create the new log entry for a http request/response  */
	if (url == NULL || strcmp(url, "") == 0)
		url = "-";
	totalSize = strlen(hostname) + strlen(currentTime) +
	strlen(method) + strlen(url) + sizeof(status) * 3 + sizeof(nBytes) * 1024;
	snprintf(entry, totalSize, "%s [%s] \"%s %s\" %d %d\n",
		 hostname, currentTime, method, url, status, nBytes);
	return entry;
}

/* Grab the current time for responses and log entries */
char*
get_current_time(void)
{
	struct tm *currtime;
	time_t curr;
	char *cbuff;
	time(&curr);
	currtime = gmtime(&curr);
	cbuff = malloc(sizeof(char) * 30);
	strftime(cbuff, 30, "%a, %d %b %Y %T %Z", currtime);
	return cbuff;
}

/* Start the socket for mirrord */
int
start_mirror(FILE * logfile, char *hostname, char *port, int ip)
{
	/* struct addrinfo hints, *res, *res0; */
	struct event event[2];
	/* int error; */
	/* int s, optval = 1; */
	/* int on = 1; */
	/* const char *cause = NULL; */
	/* printf("Hostname %s\n", hostname); */
	/* memset(&hints, 0, sizeof(hints)); */
	/* hints.ai_family = ip; */
	/* hints.ai_socktype = SOCK_STREAM; */
	/* hints.ai_flags = AI_PASSIVE; */

	/* s = -1; */
	/* error = getaddrinfo(hostname, port, &hints, &res0); */

	
	/* if (error) */
	/* 	errx(1, "%s", gai_strerror(error)); */
	/* for (res = res0; res; res = res->ai_next) { */
	/* 	s = socket(res->ai_family, res->ai_socktype, */
	/* 		   res->ai_protocol); */
	/* 	if (s == -1) { */
	/* 		cause = "socket"; */
	/* 		continue; */
	/* 	} */

	/* 	break;  /\* okay we got one *\/ */
	/* } */
	
	/* /\* s = socket(res->ai_family, res->ai_socktype, res->ai_protocol); *\/ */

	/* if (s == -1) { */
	/* 	/\* handle socket errors *\/ */
	/* } */
	/* setsockopt(s, SOL_SOCKET, SO_REUSEPORT, &optval, sizeof(optval)); */

	/* if (bind(s, res->ai_addr, res->ai_addrlen) == -1) */
	/* 	err(1, "Failed to bind to port %s", port); */

	/* if (ioctl(s, FIONBIO, &on) == -1) */
	/* 	err(1, "Failed to set nonblocking socket"); */

	/* if (listen(s, 5) == -1) */
	/* 	err(1, "Failed to listen on socket"); */
	event_init();

	struct addrinfo hints, *res, *res0;
	int error;
	int save_errno;
	int s[2];
	int on;
	int nsock;
	const char *cause = NULL;
	int optval = 1;

	on = 1;
	
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = ip;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;
	error = getaddrinfo(hostname, port, &hints, &res0);
	if (error)
		errx(1, "%s", gai_strerror(error));
	nsock = 0;
	for (res = res0; res && nsock < 2; res = res->ai_next) {
		s[nsock] = socket(res->ai_family, res->ai_socktype,
				  res->ai_protocol);
		if (s[nsock] == -1) {
			cause = "socket";
			continue;
		}

		if (bind(s[nsock], res->ai_addr, res->ai_addrlen) == -1) {
			cause = "bind";
			save_errno = errno;
			close(s[nsock]);
			errno = save_errno;
			continue;
		}

		if (ioctl(s[nsock], FIONBIO, &on) == -1)
			err(1, "Failed to set nonblocking socket");

		if (listen(s[nsock], 5)) {
			cause = "Listen";
			continue;
		}

		setsockopt(s[nsock], SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &optval, sizeof(optval));

		event_set(&event[nsock], s[nsock], EV_READ | EV_PERSIST, ack_con, logfile);
		event_add(&event[nsock], NULL);
		nsock++;
		if (ip == AF_INET)
			break;
	}
	if (nsock == 0)
		err(1, "%s", cause);
	/* freeaddrinfo(res0); */


	/* event_set(&event, s, EV_READ | EV_PERSIST, ack_con, logfile); */
	event_dispatch();

	freeaddrinfo(res);
	return 0;
}


int
main(int argc, char *argv[])
{
	int 		ch, ipv, daemonize, portFlag;
	char           *log, *address, *dirname, *port;
	FILE           *logfile = NULL;

	TAILQ_INIT(&head);

	struct request *h = malloc(sizeof(struct request));
	TAILQ_INSERT_HEAD(&head, h, requestsQueue);
	
	/* initialize strings and flags */
	daemonize = 1;
	portFlag = 0;
	requestNum = 0;
	logFlag = 0;

	/* Strings to hold potential parameters from the cmd line arguments */
	log = NULL;
	address = NULL;
	logptr = NULL;
	dirname = NULL;
	port = NULL;

	/* set default ip type */
	ipv = PF_UNSPEC;
	
	/* initialize requests array */
	/* requests = malloc(sizeof(struct request *) * MAX_REQUESTS); */
	/* int 		i; */
	/* for (i = 0; i < MAX_REQUESTS; i++) { */
	/* 	requests[i] = malloc(sizeof(struct request)); */
	/* } */

	/* initialize binary semaphore */
	sem_init(&reqSem, 0, 1);

	/* Handle sigpipe */
	signal(SIGPIPE, SIG_IGN);

	/* minimum number of command line arguments */
	if (argc < 2 || argc > 9)
		usage();

	while ((ch = getopt(argc, argv, "46da:l:p:")) != -1) {
		switch (ch) {
		case '4':
			ipv = PF_INET;
			break;
		case '6':
			ipv = PF_INET6;
			break;
		case 'a':
			log = optarg;
			if (daemonize)
			{
				logfile = fopen(log, "a+");
				/* print a startup message to the logfile */
				fprintf(logfile, "%s", "mirrord started.\n");
				logptr = logfile;
				fflush(logfile);
			}
			break;
		case 'd':
			/* Don't daemonize */
			logFlag = 1;
			daemonize = 0;
			break;
		case 'l':
			address = optarg;
			break;
		case 'p':
			port = optarg;
			portFlag = 1;

			if (atoi(port) == 0) {
				/* port was given as a name, find the port number */
				struct servent *s = getservbyname(port, NULL);
				if (s) {
					printf("%d\n", s->s_port);
					asprintf(&port, "%d", s->s_port);
				} else {
					err(1, "Could not find valid port\n");
				}
			}
			break;
		default:
			usage();
		}
	}

	/* If no port is supplied, find the default http port number */
	if (!portFlag) {
		struct servent *s = getservbyname("http", NULL);
		if (s) {
			asprintf(&port, "%d", s->s_port);
		} else {
			err(1, "Could not find port\n");
		}
	}

	dirname = argv[argc - 1];
	if (chdir(dirname) == -1) {
		usage();
	}
	if (daemonize) {
		/* daemonize the process */
		daemon(1, 0);
		start_mirror(logfile, address, port, ipv);

	} else {
		/* don't daemonize */
		start_mirror(NULL, address, port, ipv);
	}

	return 0;
}

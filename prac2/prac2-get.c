/* 
** CSSE2310/7231 - sample client - code to be commented in class
** Send a request for the top level web page (/) on some webserver and
** print out the response - including HTTP headers.
*/
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <stdlib.h>
#include <err.h>
#include <stdio.h> 
#include <unistd.h>
#include <netdb.h>
#include <string.h>

#define IP4 AF_INET
#define IP6 AF_INET6

struct in_addr* name_to_IP_addr(char*);
/* int connect_to(struct in_addr*, int, int); */
int connect_to(char*, int, int);
void send_HTTP_request(int, char*, char*);
void get_and_output_HTTP_response(int);
__dead void usage(void);


struct in_addr*
name_to_IP_addr(char* hostname)
{
    int error;
    struct addrinfo* addressInfo;

    error = getaddrinfo(hostname, NULL, NULL, &addressInfo);
    if(error) {
	return NULL;
    }
    return &(((struct sockaddr_in*)(addressInfo->ai_addr))->sin_addr);
}

/* int */
/* connect_to(struct in_addr* ipAddress, int sockType, int port) */
int
connect_to(char* hostname, int sockType, int port)
{
    struct addrinfo hints, *res, *res0;
    int error;
    int s;
    const char *cause = NULL;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = PF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    error = getaddrinfo(hostname, "http", &hints, &res0);
    if (error) {
	errx(1, "%s", gai_strerror(error));
	/*NOTREACHED*/
    }
    s = -1;
    for (res = res0; res; res = res->ai_next) {
	s = socket(res->ai_family, res->ai_socktype,
		   res->ai_protocol);
	if (s < 0) {
	    cause = "socket";
	    continue;
	}

	if (connect(s, res->ai_addr, res->ai_addrlen) < 0) {
	    cause = "connect";
	    close(s);
	    s = -1;
	    continue;
	}

	break;  /* okay we got one */
    }
    if (s < 0) {
	err(1, "%s", cause);
	/*NOTREACHED*/
    }
    freeaddrinfo(res0);  struct sockaddr_in socketAddr;
    
    return s;
}

void
send_HTTP_request(int fd, char* file, char* host)
{
    char* requestString;

    /* Allocate enough space for our HTTP request */
    requestString = (char*)malloc(strlen(file) + strlen(host) + 26);

    /* Construct HTTP request:
     * GET / HTTP/1.0
     * Host: hostname
     * <blank line>
     */
    sprintf(requestString, "GET %s HTTP/1.0\r\nHost: %s\r\n\r\n", file, host);

    /* Send our request to server */
    if(write(fd, requestString, strlen(requestString)) < 1) {
	perror("Write error");
	exit(1);
    }
}

void get_and_output_HTTP_response(int fd)
{
    char buffer[1024];
    int numBytesRead;
    int eof = 0;

    // Repeatedly read from network fd until nothing left - write 
    // everything out to stdout
    while(!eof) {
	numBytesRead = read(fd, buffer, 1024);
	if(numBytesRead < 0) {
	    perror("Read error\n");
	    exit(1);
	} else if(numBytesRead == 0) {
	    eof = 1;
	} else {
	    fwrite(buffer, sizeof(char), numBytesRead, stdout);
	}
    }
}

__dead void
usage(void)
{
    extern char *__progname;
    fprintf(stderr, "usage: %s [-46] [-p port] host [url]\n", __progname);
    exit(1);
}
    
int
main(int argc, char* argv[]) {
    int fd, port, bflag, ch, sockType;
    struct in_addr* ipAddress;
    char* hostname;

    if(argc != 6) {
	usage();
    }

 
    bflag = 1; 
    while ((ch = getopt(argc, argv, "46p:")) != -1) { 
	switch (ch) { 
	case '4': 
	    sockType = 4;
	    bflag++;
	    break; 
	case '6': 
	    sockType = 6;
	    bflag++;
	    break; 
	case 'p': 
	    bflag++;
	    printf("port %d %d\n", bflag, atoi(argv[bflag]));
	    port = atoi(argv[bflag]);
	    break; 
	default: 
	    usage();
	} 
    } 
    
    hostname = argv[5];
	   /* Convert hostname to IP addr */
    ipAddress = name_to_IP_addr(hostname);
    if(!ipAddress) {
	err(1, "%s is not a valid hostname\n", hostname);
	/* fprintf(stderr, "%s is not a valid hostname\n", hostname); */
	/* exit(1); */
    }
    
    /* Connect to port 80 on that address */
    fd = connect_to(hostname, sockType, port);
    send_HTTP_request(fd, "/", hostname);
    get_and_output_HTTP_response(fd);
    close(fd);
    return 0;
}

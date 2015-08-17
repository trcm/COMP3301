/* COMP3301 Assignment 1 - S4333060 */

#define MAX_SIZE 2048

struct request {
	char 		method[MAX_SIZE]; 	/* method parsed from the request */
	char 		url[50]; 		/* the url of the requested file */
	int 		body;  			/* Flag which will be checked if a body is present in the request */
	TAILQ_ENTRY   (request) requestsQueue;
};


struct conn {
	struct event 	rd_ev; 			/* read event on descriptor */
	struct event 	wr_ev; 			/* write events on the descriptor */
	struct event 	rd_fev;			/* event for reading from a file */
	struct event 	wr_fev;			/* event for sending file data to the client */
	struct evbuffer *ev;			/* buffer for reading and sending file data */
	struct http_parser *parser;
	char 		remote_addr[30];	/* address of the client */
	off_t 		fileSize;		/* file size of he file to be sent */
	size_t 		totalSent;		/* total amount of data that has been transferred */
};

/* Function prototypes */
int 		on_url    (http_parser *, const char *, size_t);
int 		on_body   (http_parser *, const char *, size_t);
int 		start_mirror(FILE *, char *, char *, int);
void 		ack_con  (int, short, void *);
int 		print_to_log(char *);
int 		on_complete(http_parser *);
int 		retrieve_file(char *);
char           *create_log_entry(char *, char *, const char *, char *, int, int);
char           *get_current_time(void);
void 		handle_read(int, short, void *);
void 		handle_send(int, short, void *);
void 		read_file(int, short, void *);
void 		send_file(int, short, void *);
void 		close_connection(struct conn *);
__dead void 	usage(void);

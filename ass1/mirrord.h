/* COMP3301 Assignment 1 - S4333060 */

#define MAX_SIZE 2048

struct request {
	char method[MAX_SIZE];
	char host[MAX_SIZE];
	char url[50];
	int body;
	TAILQ_ENTRY(request) requestsQueue;
};


struct conn {
	/* events for accessing the socket */
	struct event rd_ev;
	struct event wr_ev;
	/* events for reading and sending the specified file */
	struct event rd_fev;
	struct event wr_fev;

	struct evbuffer *ev;
	struct http_parser *parser;

	char remote_addr[30];
	off_t fileSize;
	size_t totalSent;
	int requestNum;
};

/* function prototypes */
int		 on_url(http_parser*, const char*, size_t);
int		 on_body(http_parser*, const char*, size_t);
int 		 start_mirror(FILE*, char*, char*, int);
void 		 ack_con (int, short, void*);
int 		 print_to_log(char*);
int		 on_complete(http_parser*);
int		 retrieve_file(char*);
char*		 create_log_entry(char*, char*, const char*, char*, int, int);
char*		 get_current_time(void);
void 		 handle_read(int, short, void*);
void 		 handle_send(int, short, void*);
void 		 read_file(int, short, void*);
void 		 send_file(int, short, void*);
void             close_connection(struct conn *);
__dead void 	 usage(void);


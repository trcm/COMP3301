/* COMP3301 Assignment 1 - S4333060 */


typedef struct request {
	char *url;
	int method;
} request;

int		 on_complete(http_parser *parser);
int		 on_url(http_parser *, const char *, size_t);
int 		 start_mirror(FILE *, char *, char *);
void 		 ack_con  (int, short, void *);
int 		 print_to_log(FILE *, char *);
int		 on_complete(http_parser *);
__dead void 	 usage(void);


/* COMP3301 Assignment 1 - S4333060 */

#define MAX_SIZE 2048

typedef struct request {
	char url[MAX_SIZE];
	int method;
} request;

int		 on_complete(http_parser *);
int		 on_url(http_parser *, const char *, size_t);
int 		 start_mirror(FILE *, char *, char *);
void 		 ack_con  (int, short, void *);
int 		 print_to_log(FILE *, char *);
int		 on_complete(http_parser *);
int		 retrieve_file(char*);
int		 on_header_field(http_parser*, const char*, size_t);
__dead void 	 usage(void);


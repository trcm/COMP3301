/* COMP3301 Assignment 1 - S4333060 */

#define MAX_SIZE 2048

typedef struct request {
	char url[MAX_SIZE];
	char host[MAX_SIZE];
	char remote_addr[16];
	char method[MAX_SIZE];
	char headerFields[30][30];
	char headerValues[30][30];
	int headerNum;
} request;

int		 on_complete(http_parser *);
int		 on_url(http_parser *, const char *, size_t);
int 		 start_mirror(FILE *, char *, char *);
void 		 ack_con  (int, short, void *);
int 		 print_to_log(char *);
int		 on_complete(http_parser *);
int		 retrieve_file(char*);
int		 on_header_field(http_parser*, const char*, size_t);
int		 on_header_value(http_parser*, const char*, size_t);
char*		 create_log_entry(char*, char*, char*, char*, int, int);
__dead void 	 usage(void);


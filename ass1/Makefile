# comp3301/comp7308 event driven echo daemon

PROG=mirrord
SRCS=mirrord.c
SRCS+=http_parser.c
MAN=
LDADD=-levent -lpthread
DPADD=${LIBEVENT}
CFLAGS+= -Wall -Werror -g 
CFLAGS+= -Wstrict-prototypes -Wmissing-prototypes  
CFLAGS+= -Wmissing-declarations 
CFLAGS+= -Wshadow -Wpointer-arith 
CFLAGS+= -Wsign-compare 

.include <bsd.prog.mk>


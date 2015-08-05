#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <err.h>

#include <event.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/ioctl.h>
#include <sys/queue.h>

__dead void usage(void);

struct conn {
    struct event		rd_ev;
    struct event		wr_ev;
    struct evbuffer		*buf;
};

void echo_accept(int, short, void *);
void echo_read(int, short, void *);
void echo_write(int, short, void *);
void echo_close(struct conn *);

void
echo_accept(int sock, short revents, void *null)
{
    struct sockaddr_storage ss;
    socklen_t socklen = sizeof(ss);
    struct conn *c;
    int fd;
    int on = 1;

    fd = accept(sock, (struct sockaddr *)&ss, &socklen);
    if (fd == -1) {
	switch (errno) {
	case EINTR:
	case EWOULDBLOCK:
	case ECONNABORTED:
	    /* oh well, wait for another one */
	    return;
	default:
	    err(1, "accept");
	}
    }

    if (ioctl(fd, FIONBIO, &on) == -1)
	err(1, "conn ioctl(FIONBIO)");

    c = malloc(sizeof(*c));
    if (c == NULL) {
	warn("conn alloc");
	close(fd);
	return;
    }

    c->buf = evbuffer_new();
    if (c->buf == NULL) {
	warn("conn buf alloc");
	free(c);
	close(fd);
	return;
    }

    printf("fd %d: accepted\n", fd);

    event_set(&c->rd_ev, fd, EV_READ | EV_PERSIST, echo_read, c);
    event_set(&c->wr_ev, fd, EV_WRITE, echo_write, c);
    event_add(&c->rd_ev, NULL);
    event_add(&c->wr_ev, NULL);
}

void
echo_read(int fd, short revents, void *conn)
{
    int i;
// create buffer
/* struct evbuffer * eBuff = evbuffer_new(); */
    struct conn * c = (struct conn *) conn;
// recieve and echo the message to the user
    char ** data;
    data =  malloc(sizeof(char*) * 1024);
    for (i = 0; i < 1024; i++) {
	data[i] = malloc(sizeof(char) * 1024);
    }
    int dLen = 0;
    do {
	evbuffer_read(c->buf, fd, 1024);
	printf("%s %d\n", c->buf->buffer, dLen);
	if (strcmp(c->buf->buffer, data[dLen]) == 0) {
	    data[dLen] = c->buf->buffer;
	    evbuffer_drain(c->buf, strlen(data[dLen]));
	    dLen++;
	}
    } while (strcmp(c->buf->buffer, "done\n") != 0);

/* evbuffer_read(c->buf, fd, 1024); */
    fprintf(stdout, "fd %d: %s\n", fd, (char *)c->buf->buffer);
/* fflush(stdout); */
    write(fd, "Message recieved\n", 18);
    evbuffer_write(c->buf, fd);
/* evbuffer_write(c->evbuffer, fd); */
// free the buffer
    echo_close(conn);
}



void
echo_write(int fd, short revents, void *conn)
{
    printf("fd %d: wrote echo\n", fd);
}


void
echo_close(struct conn *c)
{
    printf("fd %d: closing\n", EVENT_FD(&c->rd_ev));

    evbuffer_free(c->buf);
    event_del(&c->wr_ev);
    event_del(&c->rd_ev);
    close(EVENT_FD(&c->rd_ev));
    free(c);
}

__dead void
usage(void)
{
    extern char *__progname;
    fprintf(stderr, "usage: %s sock\n", __progname);
    exit(1);
}

int
main(int argc, char *argv[])
{
    struct sockaddr_un sun;
    struct event event;
    int sock;
    int on = 1;

    if (argc != 2)
	usage();

    sun.sun_family = AF_UNIX;
    if (strlcpy(sun.sun_path, argv[1],
		sizeof(sun.sun_path)) >= sizeof(sun.sun_path))
	errx(1, "socket path is too long");

    sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock == -1)
	err(1, "socket");

    if (bind(sock, (struct sockaddr *)&sun, sizeof(sun)) == -1)
	err(1, "bind");

    if (ioctl(sock, FIONBIO, &on) == -1)
	err(1, "listener ioctl(FIONBIO)");

    if (listen(sock, 5) == -1)
	err(1, "listen");

    event_init();

    event_set(&event, sock, EV_READ | EV_PERSIST, echo_accept, NULL);
    event_add(&event, NULL);

    event_dispatch();

    return (0);
}

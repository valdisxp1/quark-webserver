/* See LICENSE file for copyright and license details. */
#include <stddef.h>

#ifdef __linux__
	#include <sys/epoll.h>
#else
	#include <sys/types.h>
	#include <sys/event.h>
	#include <sys/time.h>
#endif

#include "queue.h"
#include "util.h"

int
queue_create(void)
{
	int qfd;

	#ifdef __linux__
		if ((qfd = epoll_create1(0)) < 0) {
			warn("epoll_create1:");
		}
	#else

	#endif

	return qfd;
}

int
queue_add_fd(int qfd, int fd, enum queue_event_type t, int shared,
             const void *data)
{
	#ifdef __linux__
		struct epoll_event e;

		/* set event flag */
		if (shared) {
			/*
			 * if the fd is shared, "exclusive" is the only
			 * way to avoid spurious wakeups and "blocking"
			 * accept()'s.
			 */
			e.events = EPOLLEXCLUSIVE;
		} else {
			/*
			 * if we have the fd for ourselves (i.e. only
			 * within the thread), we want to be
			 * edge-triggered, as our logic makes sure
			 * that the buffers are drained when we return
			 * to epoll_wait()
			 */
			e.events = EPOLLET;
		}

		switch (t) {
		case QUEUE_EVENT_IN:
			e.events |= EPOLLIN;
			break;
		case QUEUE_EVENT_OUT:
			e.events |= EPOLLOUT;
			break;
		}

		/* set data */
		if (data == NULL) {
			/* the data is the fd itself */
			e.data.fd = fd;
		} else {
			/* set data pointer */
			e.data.ptr = (void *)data;
		}

		/* register fd in the interest list */
		if (epoll_ctl(qfd, EPOLL_CTL_ADD, fd, &e) < 0) {
			warn("epoll_ctl:");
			return 1;
		}
	#else

	#endif

	return 0;
}

int
queue_mod_fd(int qfd, int fd, enum queue_event_type t, const void *data)
{
	#ifdef __linux__
		struct epoll_event e;

		/* set event flag */
		e.events = EPOLLET;
		switch (t) {
		case QUEUE_EVENT_IN:
			e.events |= EPOLLIN;
			break;
		case QUEUE_EVENT_OUT:
			e.events |= EPOLLOUT;
			break;
		}

		/* set data */
		if (data == NULL) {
			/* the data is the fd itself */
			e.data.fd = fd;
		} else {
			/* set data pointer */
			e.data.ptr = (void *)data;
		}

		/* register fd in the interest list */
		if (epoll_ctl(qfd, EPOLL_CTL_MOD, fd, &e) < 0) {
			warn("epoll_ctl:");
			return 1;
		}
	#else

	#endif

	return 0;
}

int
queue_rem_fd(int qfd, int fd)
{
	#ifdef __linux__
		struct epoll_event e;

		if (epoll_ctl(qfd, EPOLL_CTL_DEL, fd, &e) < 0) {
			warn("epoll_ctl:");
			return 1;
		}
	#else

	#endif

	return 0;
}

ssize_t
queue_wait(int qfd, queue_event *e, size_t elen)
{
	ssize_t nready;

	#ifdef __linux__
		if ((nready = epoll_wait(qfd, e, elen, -1)) < 0) {
			warn("epoll_wait:");
			return -1;
		}
	#else

	#endif

	return nready;
}

int
queue_event_get_fd(const queue_event *e)
{
	#ifdef __linux__
		return e->data.fd;
	#else

	#endif
}

void *
queue_event_get_ptr(const queue_event *e)
{
	#ifdef __linux__
		return e->data.ptr;
	#else

	#endif
}

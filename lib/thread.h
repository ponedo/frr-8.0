/* Thread management routine header.
 * Copyright (C) 1998 Kunihiro Ishiguro
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef _ZEBRA_THREAD_H
#define _ZEBRA_THREAD_H

#include <stdio.h>
#include <zebra.h>
#include <pthread.h>
#include <poll.h>
#include <sys/epoll.h>
#include "monotime.h"
#include "frratomic.h"
#include "typesafe.h"
#include "xref.h"

#ifdef __cplusplus
extern "C" {
#endif

struct rusage_t {
	struct rusage cpu;
	struct timeval real;
};
#define RUSAGE_T        struct rusage_t

#define GETRUSAGE(X) thread_getrusage(X)

PREDECL_LIST(thread_list);
PREDECL_HEAP(thread_timer_list);

struct frr_epoll_event {
	/* the index of this frr_epoll_event instance in .event_ptrs or 
	 * .new_event_ptrs */
	int index; //index should be -1 for a invalid frr_epoll_event
	struct epoll_event ev;
};

struct fd_handler {
	/* number of pfd that fit in the allocated space of pfds. This is a
	 * constant and is the same for both pfds and copy.
	 */
	nfds_t event_size;

	/* the epoll fd set to monitor for i/o. This should be coordinated with 
	 * the "events" field below */
	int epoll_fd;

	/* Below we define two arrays, namely .events and .new_events. 
	 * The function of two arrays are analogous to .pfds and .copy in old
	 * version fd_handler which uses poll().
	 * 
	 * .events hold existing monitored events that have been registered in
	 * kernel by epoll_ctl() calls. Similar to .copy array in old version, 
	 * .events is updated just before every time fd_poll() is called.
	 * 
	 * .new_events hold event update requests during the interval from last 
	 * fd_poll() call to next fd_poll() call. .new_events functions as a 
	 * holder of new event request, which is similar to .pfds array in old
	 * version
	 * 
	 * Both array are indexed by fd for fast update. However, during 
	 * cancel_arg_helper when canceling a thread, all frr_epoll_events 
	 * are supposed to be traversed, which is inefficient. We define two
	 * compact arrays .event_ptrs and .new_event_ptrs for fast canceling.
	 * Only (new_)event_count number of elements in .(new_)event_ptr are 
	 * valid, and each element refers a valid frr_epoll_event.
	 * 
	 * frr_epoll_event arrays and ptr arrays are mutually referenced. An 
	 * frr_epoll_event reference its corresponding ptr element by its 
	 * .index field. An ptr reference its corresponding frr_epoll_event 
	 * natually since it is a pointer. */

	
	/* the buffer which stores monitored fds and corresponding events, 
	 * indexed by fd */
    struct frr_epoll_event *events;
	/* a compact array of pointers to frr_epoll_event in .events array, 
	 * This array is traversed if needed when doing do_thread_cancel */
    struct frr_epoll_event **event_ptrs;
	/* number of valid frr_epoll_event in .events (number of valid pointers)
	 * in .events_ptrs */
	nfds_t event_count;

	/* the temp buffer which stores requests of adding new fd into 
	 * epoll_fd set, or modifying the events of existing fds. 
	 * Indexed by fd */
	struct frr_epoll_event *new_events;
	/* a compact array of pointers to frr_epoll_event in .new_events array, 
	 * This array is traversed if needed when doing do_thread_cancel */
    struct frr_epoll_event **new_event_ptrs;
	/* number of valid frr_epoll_event in .new_events (number of valid 
	 * pointers in .new_events_ptrs */
	nfds_t new_event_count;
	
	/* the buffer which stores the results of epoll_wait() */
    struct epoll_event *revents;
};

struct xref_threadsched {
	struct xref xref;

	const char *funcname;
	const char *dest;
	uint32_t thread_type;
};

/* Master of the theads. */
struct thread_master {
	char *name;

	FILE *f_debug;

	struct thread **read;
	struct thread **write;
	struct thread_timer_list_head timer;
	struct thread_list_head event, ready, unuse;
	struct list *cancel_req;
	bool canceled;
	pthread_cond_t cancel_cond;
	struct hash *cpu_record;
	int io_pipe[2];
	bool awakened;
	int fd_limit;
	struct fd_handler handler;
	unsigned long alloc;
	long selectpoll_timeout;
	bool spin;
	bool handle_signals;
	pthread_mutex_t mtx;
	pthread_t owner;

	bool ready_run_loop;
	RUSAGE_T last_getrusage;
};

/* Thread itself. */
struct thread {
	uint8_t type;		  /* thread type */
	uint8_t add_type;	  /* thread type */
	struct thread_list_item threaditem;
	struct thread_timer_list_item timeritem;
	struct thread **ref;	  /* external reference (if given) */
	struct thread_master *master; /* pointer to the struct thread_master */
	int (*func)(struct thread *); /* event function */
	void *arg;		      /* event argument */
	union {
		int val;	      /* second argument of the event. */
		int fd;		      /* file descriptor in case of r/w */
		struct timeval sands; /* rest of time sands value. */
	} u;
	struct timeval real;
	struct cpu_thread_history *hist; /* cache pointer to cpu_history */
	unsigned long yield;		 /* yield time in microseconds */
	const struct xref_threadsched *xref;   /* origin location */
	pthread_mutex_t mtx;   /* mutex for thread.c functions */
};

struct cpu_thread_history {
	int (*func)(struct thread *);
	atomic_size_t total_cpu_warn;
	atomic_size_t total_wall_warn;
	atomic_size_t total_calls;
	atomic_size_t total_active;
	struct time_stats {
		atomic_size_t total, max;
	} real;
	struct time_stats cpu;
	atomic_uint_fast32_t types;
	const char *funcname;
};

/* Struct timeval's tv_usec one second value.  */
#define TIMER_SECOND_MICRO 1000000L

/* Thread types. */
#define THREAD_READ           0
#define THREAD_WRITE          1
#define THREAD_TIMER          2
#define THREAD_EVENT          3
#define THREAD_READY          4
#define THREAD_UNUSED         5
#define THREAD_EXECUTE        6

/* Thread yield time.  */
#define THREAD_YIELD_TIME_SLOT     10 * 1000L /* 10ms */

#define THREAD_TIMER_STRLEN 12

/* Macros. */
#define THREAD_ARG(X) ((X)->arg)
#define THREAD_FD(X)  ((X)->u.fd)
#define THREAD_VAL(X) ((X)->u.val)

/*
 * Please consider this macro deprecated, and do not use it in new code.
 */
#define THREAD_OFF(thread)                                             \
	do {                                                           \
		if ((thread))                                          \
			thread_cancel(&(thread));                      \
	} while (0)

/*
 * Macro wrappers to generate xrefs for all thread add calls.  Includes
 * file/line/function info for debugging/tracing.
 */
#include "lib/xref.h"

#define _xref_t_a(addfn, type, m, f, a, v, t)                                  \
	({                                                                     \
		static const struct xref_threadsched _xref                     \
				__attribute__((used)) = {                      \
			.xref = XREF_INIT(XREFT_THREADSCHED, NULL, __func__),  \
			.funcname = #f,                                        \
			.dest = #t,                                            \
			.thread_type = THREAD_ ## type,                        \
		};                                                             \
		XREF_LINK(_xref.xref);                                         \
		_thread_add_ ## addfn(&_xref, m, f, a, v, t);                  \
	})                                                                     \
	/* end */

#define thread_add_read(m,f,a,v,t)       _xref_t_a(read_write, READ,  m,f,a,v,t)
#define thread_add_write(m,f,a,v,t)      _xref_t_a(read_write, WRITE, m,f,a,v,t)
#define thread_add_timer(m,f,a,v,t)      _xref_t_a(timer,      TIMER, m,f,a,v,t)
#define thread_add_timer_msec(m,f,a,v,t) _xref_t_a(timer_msec, TIMER, m,f,a,v,t)
#define thread_add_timer_tv(m,f,a,v,t)   _xref_t_a(timer_tv,   TIMER, m,f,a,v,t)
#define thread_add_event(m,f,a,v,t)      _xref_t_a(event,      EVENT, m,f,a,v,t)

#define thread_execute(m,f,a,v)                                                \
	({                                                                     \
		static const struct xref_threadsched _xref                     \
				__attribute__((used)) = {                      \
			.xref = XREF_INIT(XREFT_THREADSCHED, NULL, __func__),  \
			.funcname = #f,                                        \
			.dest = NULL,                                          \
			.thread_type = THREAD_EXECUTE,                         \
		};                                                             \
		XREF_LINK(_xref.xref);                                         \
		_thread_execute(&_xref, m, f, a, v);                           \
	}) /* end */

/* Prototypes. */
extern struct thread_master *thread_master_create(const char *);
void thread_master_set_name(struct thread_master *master, const char *name);
extern void thread_master_free(struct thread_master *);
extern void thread_master_free_unused(struct thread_master *);

extern struct thread *_thread_add_read_write(
	const struct xref_threadsched *xref, struct thread_master *master,
	int (*fn)(struct thread *), void *arg, int fd, struct thread **tref);

extern struct thread *_thread_add_timer(
	const struct xref_threadsched *xref, struct thread_master *master,
	int (*fn)(struct thread *), void *arg, long t, struct thread **tref);

extern struct thread *_thread_add_timer_msec(
	const struct xref_threadsched *xref, struct thread_master *master,
	int (*fn)(struct thread *), void *arg, long t, struct thread **tref);

extern struct thread *_thread_add_timer_tv(
	const struct xref_threadsched *xref, struct thread_master *master,
	int (*fn)(struct thread *), void *arg, struct timeval *tv,
	struct thread **tref);

extern struct thread *_thread_add_event(
	const struct xref_threadsched *xref, struct thread_master *master,
	int (*fn)(struct thread *), void *arg, int val, struct thread **tref);

extern void _thread_execute(const struct xref_threadsched *xref,
			    struct thread_master *master,
			    int (*fn)(struct thread *), void *arg, int val);

extern void thread_cancel(struct thread **event);
extern void thread_cancel_async(struct thread_master *, struct thread **,
				void *);
/* Cancel ready tasks with an arg matching 'arg' */
extern void thread_cancel_event_ready(struct thread_master *m, void *arg);
/* Cancel all tasks with an arg matching 'arg', including timers and io */
extern void thread_cancel_event(struct thread_master *m, void *arg);
extern struct thread *thread_fetch(struct thread_master *, struct thread *);
extern void thread_call(struct thread *);
extern unsigned long thread_timer_remain_second(struct thread *);
extern struct timeval thread_timer_remain(struct thread *);
extern unsigned long thread_timer_remain_msec(struct thread *);
extern int thread_should_yield(struct thread *);
/* set yield time for thread */
extern void thread_set_yield_time(struct thread *, unsigned long);

/* Internal libfrr exports */
extern void thread_getrusage(RUSAGE_T *);
extern void thread_cmd_init(void);

/* Returns elapsed real (wall clock) time. */
extern unsigned long thread_consumed_time(RUSAGE_T *after, RUSAGE_T *before,
					  unsigned long *cpu_time_elapsed);

/* only for use in logging functions! */
extern pthread_key_t thread_current;
extern char *thread_timer_to_hhmmss(char *buf, int buf_size,
		struct thread *t_timer);

/* Debug signal mask */
void debug_signals(const sigset_t *sigs);

#ifdef __cplusplus
}
#endif

#endif /* _ZEBRA_THREAD_H */

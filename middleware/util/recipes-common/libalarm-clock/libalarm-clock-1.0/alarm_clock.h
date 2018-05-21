/*
* Copyright (c) 2013-2014 Wind River Systems, Inc.
*
* SPDX-License-Identifier: Apache-2.0
*
*/

#ifndef __ALARM_CLOCK_H__
#define __ALARM_CLOCK_H__

/**
*/

// For ppoll
#define _GNU_SOURCE

#include <time.h>
#include <poll.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdbool.h>

#include "alarm_clock_types.h"

extern struct timespec ts_diff(struct timespec end, struct timespec start);
extern struct timespec ts_add(struct timespec t1, struct timespec t2);
extern struct timespec ts_max(struct timespec t1, struct timespec t2);
extern struct timespec ts_min(struct timespec t1, struct timespec t2);

extern void ac_bind_exit_fptr(void (*f)(int status, const char* log));

extern alarm_t* ac_create_alarm(int   first,
                                int   interval,
                                int   recurrence,
                                int (*expire_func)(alarm_t*),
                                int   id,
                                void* util_ptr);

extern void ac_init(alarm_clock_t   *alarm_clock_p, 
                    int            (*expire_func)(alarm_t*),
                    struct timespec  precision);


extern void  ac_init_alarm(alarm_t *wheel_data_p,
                           int      first,
                           int      interval,
                           int      recurrence,
                           int    (*expire_func)(alarm_t*),
                           int      id,
                           void*    util_ptr);

extern int alarm_get_id(alarm_t *p);

extern void alarm_set_id(alarm_t *p,
                         int      id);

extern void* alarm_get_util_ptr(alarm_t *p);

extern void alarm_set_util_ptr(alarm_t *p, 
                               void*    util_ptr);

extern void alarm_set_expire_func(alarm_t  *p,
                                  int     (*expire_func)(alarm_t*));
               
extern void alarm_set_interval(alarm_t *p,
                               long     secs,
                               long     nsecs);

extern void alarm_set_first_timeout(alarm_t *p,
                                    long     secs,
                                    long     nsecs);

extern bool ac_alarm_on_queue(alarm_t *target);

extern void ac_enqueue_alarm(alarm_clock_t *alarm_clock_p,
                             alarm_t       *p);

extern void ac_enqueue_first_alarm(alarm_clock_t *alarm_clock_p,
                                   alarm_t       *p);

extern alarm_t* ac_dequeue_alarm(alarm_t *target);

extern void ac_requeue_alarm(alarm_clock_t *alarm_clock_p,
                             alarm_t       *p);

extern void ac_requeue_first_alarm(alarm_clock_t *alarm_clock_p,
                                   alarm_t       *p);

extern void ac_run_clock(alarm_clock_t *alarm_clock_p);

extern int ac_select(alarm_clock_t  *alarm_clock_p,
                     int             nfds,
                     fd_set         *readfds,
                     fd_set         *writefds,
                     fd_set         *exceptfds,
                     struct timeval *timeout);

extern int ac_pselect(alarm_clock_t         *alarm_clock_p,
                      int                    nfds,
                      fd_set                *readfds,
                      fd_set                *writefds,
                      fd_set                *exceptfds,
                      const struct timespec *timeout_ts,
                      const sigset_t        *sigmask);

extern int ac_poll(alarm_clock_t  *alarm_clock_p,
                   struct pollfd  *fds, 
                   nfds_t          nfds,
                   int             timeout);

extern int ac_ppoll(alarm_clock_t         *alarm_clock_p,
                    struct pollfd         *fds, 
                    nfds_t                 nfds,
                    const struct timespec *timeout_ts,
                    const sigset_t        *sigmask);



#endif /* __ALARM_CLOCK_H__ */

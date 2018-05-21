/*
* Copyright (c) 2013-2014 Wind River Systems, Inc.
*
* SPDX-License-Identifier: Apache-2.0
*
*/

/**
*/

// For ppoll
#define _GNU_SOURCE

#include "alarm_clock_types.h"
#include <cgcs/atomic.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <stdarg.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <poll.h>
#include <resolv.h>
#include <time.h> 
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <syslog.h>
#include <sys/syscall.h>


#define gettid() ((pid_t)syscall(SYS_gettid))


// #define DEBUG_ALARM 1
// #define DEBUG_ALARM2 1

#define PRINT(lvl, s) syslog(LOG_USER | lvl, "%s", s)

#define PRINT_ERR(format, ...) \
    ({ \
    char _buf[512]; \
    char _buf2[1024]; \
    struct timespec _t; \
    struct tm _lt; \
    pid_t _pid; \
    pid_t _tid; \
    _pid = getpid(); \
    _tid = gettid(); \
    clock_gettime(CLOCK_REALTIME, &_t); \
    localtime_r(&_t.tv_sec, &_lt); \
    strftime(_buf, sizeof(_buf), "%T", &_lt); \
    snprintf(_buf2, sizeof(_buf2), "%s.%09ld %s[%d:%d] %s:%d %s: ERROR: " format, _buf, _t.tv_nsec, program_invocation_short_name, _pid, _tid, __FILE__, __LINE__, __FUNCTION__, ##__VA_ARGS__); \
    PRINT(LOG_ERR, _buf2); \
    })


#ifdef DEBUG_ALARM2
 #define PRINT_DEBUG2 PRINT_DEBUG
#else
 #define PRINT_DEBUG2(format, ...)
#endif

#ifdef DEBUG_ALARM
 #define PRINT_DEBUG(format, ...) \
    ({ \
    char _buf[512]; \
    char _buf2[1024]; \
    struct timespec _t; \
    struct tm _lt; \
    pid_t _pid; \
    pid_t _tid; \
    _pid = getpid(); \
    _tid = gettid(); \
    clock_gettime(CLOCK_REALTIME, &_t); \
    localtime_r(&_t.tv_sec, &_lt); \
    strftime(_buf, sizeof(_buf), "%T", &_lt); \
    snprintf(_buf2, sizeof(_buf2), "%s.%09ld %s[%d:%d] %s:%d %s: DEBUG: " format, _buf, _t.tv_nsec, program_invocation_short_name, _pid, _tid, __FILE__, __LINE__, __FUNCTION__, ##__VA_ARGS__); \
    PRINT(LOG_DEBUG, _buf2); \
    })
#else
 #define PRINT_DEBUG(format, ...)
#endif


void (*ac_exit_fptr)(int         status,
                     const char* log) = NULL;


/* =================== FUNCTION PROTOTYPES ===================== */
/*   ----------------------- PRIVATE -------------------------   */
struct timespec ts_diff(struct timespec end, struct timespec start);
struct timespec ts_add(struct timespec t1, struct timespec t2);
struct timespec ts_min(struct timespec t1, struct timespec t2);
struct timespec ts_max(struct timespec t1, struct timespec t2);
int ts_cmp(struct timespec t1, struct timespec t2);

static
void location(const struct timespec *delta, 
              int                   *wheel, 
              int                   *spoke);

static
void enqueue(alarm_t **head,
             alarm_t  *p);

static
alarm_t* dequeue_head(alarm_t **head);

static
void requeue(alarm_clock_t *alarm_clock_p,
             int            wheel,
             int            spoke_delta);

static
void advance(alarm_clock_t *alarm_clock_p);

static
void fire(alarm_clock_t *alarm_clock_p,
          alarm_t       *p);


/*   ----------------------- PUBLIC --------------------------   */

void ac_bind_exit_fptr(void (*f)(int status, const char* log));

void ac_init(alarm_clock_t    *alarm_clock_p, 
             int             (*f)(alarm_t*),
             struct timespec   precision);

bool ac_alarm_on_queue(alarm_t *target);

alarm_t* ac_dequeue_alarm(alarm_t *target);

void ac_enqueue_alarm_int(alarm_clock_t   *alarm_clock_p,
                          alarm_t         *p);

void ac_enqueue_alarm(alarm_clock_t *alarm_clock_p,
                      alarm_t       *p);

void ac_requeue_alarm(alarm_clock_t *alarm_clock_p,
                      alarm_t       *p);

void ac_requeue_first_alarm(alarm_clock_t *alarm_clock_p,
                            alarm_t       *p);

int alarm_get_id(alarm_t *p);

void alarm_set_id(alarm_t *p, 
                  int      id);

void* alarm_get_util_ptr(alarm_t *p);

void alarm_set_util_ptr(alarm_t *p, 
                        void    *util_ptr);

void alarm_set_expire_func(alarm_t  *p,
                           int     (*expire_func)(alarm_t*));

void alarm_set_interval(alarm_t *p, 
                        long     secs,
                        long     nsecs);

void alarm_set_first_timeout(alarm_t *p,
                             long     secs,
                             long     nsecs);



/* ========================= CODE ============================== */
struct timespec ts_diff(struct timespec end, struct timespec start)
    {
    struct timespec temp;
    if ((end.tv_nsec - start.tv_nsec) < 0)
        {
    	temp.tv_sec = (end.tv_sec - start.tv_sec) - 1;
    	temp.tv_nsec = 1000000000 + end.tv_nsec - start.tv_nsec;
        }
    else
        {
    	temp.tv_sec = end.tv_sec - start.tv_sec;
    	temp.tv_nsec = end.tv_nsec - start.tv_nsec;
        }

    if (temp.tv_sec < 0)
        {
    	temp.tv_sec = 0;
    	temp.tv_nsec = 0;
        }

    return temp;
    }

int ts_cmp(struct timespec t1, struct timespec t2)
    {
    if (t1.tv_sec < t2.tv_sec)
       return -1;
    if (t1.tv_sec > t2.tv_sec)
       return 1;
    if (t1.tv_nsec < t2.tv_nsec)
       return -1;
    if (t1.tv_nsec > t2.tv_nsec)
       return 1;
    return 0;
    }

struct timespec ts_add(struct timespec t1, struct timespec t2)
    {
    struct timespec temp;
    temp.tv_sec = t1.tv_sec + t2.tv_sec;
    temp.tv_nsec = t1.tv_nsec + t2.tv_nsec;
    if (temp.tv_nsec >= 1000000000) 
        {
        temp.tv_sec += 1;
        temp.tv_nsec -= 1000000000;
        }
    
    return temp;
    }


struct timespec ts_min(struct timespec t1, struct timespec t2)
    {
    struct timespec temp;
    if ((t1.tv_sec < t2.tv_sec) ||
        ((t1.tv_sec == t2.tv_sec) && (t1.tv_nsec < t2.tv_nsec)))
        {
        temp.tv_sec = t1.tv_sec;
        temp.tv_nsec = t1.tv_nsec;
        }
    else
        {
        temp.tv_sec = t2.tv_sec;
        temp.tv_nsec = t2.tv_nsec;
        }

    return temp;
    }

struct timespec ts_max(struct timespec t1, struct timespec t2)
    {
    struct timespec temp;
    if ((t1.tv_sec > t2.tv_sec) || 
        ((t1.tv_sec == t2.tv_sec) && (t1.tv_nsec > t2.tv_nsec)))
        {
        temp.tv_sec = t1.tv_sec;
        temp.tv_nsec = t1.tv_nsec;
        }
    else 
        {
        temp.tv_sec = t2.tv_sec;
        temp.tv_nsec = t2.tv_nsec;
        }

    return temp;
    }

void ac_bind_exit_fptr(void (*f)(int status, const char* log))
    {
    ac_exit_fptr = f;
    }

void ac_exit(int status, const char* log)
    {
    if (ac_exit_fptr)
        ac_exit_fptr(status, log);
    else
        {
        PRINT_ERR("exiting, status %d, log '%s'\n", status, log);
        exit(status);
        }
    }

void location(const struct timespec *delta, 
              int                   *wheel,
              int                   *spoke)
    {
    int i;
    time_t sec_mask=(SPOKES-1);
    ulong  nsec_mask=(SPOKES-1);
    ulong  val;
    int shift;
    long nsec;

    for(i=WHEELS_PER_TVSEC-1; i>=0; i--)
       {
       shift = SPOKES_POW * i;
       val = (delta->tv_sec & (sec_mask << shift)) >> shift;
       if (val > 0)
           {
           *wheel = i + WHEELS_PER_TVNSEC;
           *spoke = val;
           return;
           }
       }

    nsec = NSEC_SCALE * delta->tv_nsec;
    for(i=WHEELS_PER_TVNSEC-1; i>=0; i--)
       {
       shift = SPOKES_POW * i;
       val = (nsec & (nsec_mask << shift)) >> shift;
       if (val > 0)
           {
           *wheel = i;
           *spoke = val;
           return;
           }
       }
    
    *wheel = 0;
    *spoke = 0;
    return;
    }

bool ac_alarm_on_queue(alarm_t  *p)
    {
    return (p->head ? true : false);
    }

void enqueue(alarm_t **head, 
             alarm_t  *p)
    {
    PRINT_DEBUG("enqueue head=%p, *head=%p, p=%p, p->head=%p, p->next=%p\n", 
                head, *head, p, p->head, p->next);

    if (p->head || p->next)
        { 
        PRINT_ERR("enqueue, is node already on a list? p=%p, head=%p, next=%p\n",
                  p, p->head, p->next);
        ac_exit(-1, __FUNCTION__);
        }
    p->next = *head;
    *head = p;   
    p->head = head;
    }

alarm_t* dequeue_head(alarm_t **head)
    {
    alarm_t* p;

    p = *head;
    if (p)
        {
        *head = p->next;
        p->next = NULL;
        p->head = NULL;
        }
    return p;
    }

alarm_t* ac_dequeue_alarm(alarm_t *target)
    {
    alarm_t **head;
    alarm_t *p;

    head = target->head;
    if (!head)
        {
        if (target->next)
            {
            PRINT_ERR("ac_dequeue_alarm: head was NULL, yet next was %p\n", target->next);
            ac_exit(-1, __FUNCTION__);
            }
        PRINT_ERR("ac_dequeue_alarm: head was NULL\n");
        ac_exit(-1, __FUNCTION__);
        return target;
        }

    p = *head;
    if (p == target)
       return dequeue_head(head);

    while(p->next != *head)
        {
        if (p->next == target)
            {
            p->next = target->next;
            target->next = NULL;
            target->head = NULL;
            return target;
            }

        p = p->next;
        }

    return NULL;
    }

int alarm_get_id(alarm_t *p)
    {
    return p->id;
    }

void alarm_set_id(alarm_t *p, 
                  int      id)
    {
    p->id = id;
    }

void* alarm_get_util_ptr(alarm_t *p)
    {
    return p->util_ptr;
    }

void alarm_set_util_ptr(alarm_t *p,
                        void    *util_ptr)
    {
    p->util_ptr = util_ptr;
    }

void alarm_set_expire_func(alarm_t  *p,
                           int     (*expire_func)(alarm_t*))
    {
    p->expire_func = expire_func;
    }

void alarm_set_interval(alarm_t *p, 
                        long     secs,
                        long     nsecs)
    {
    p->interval.tv_sec = secs;
    p->interval.tv_nsec = nsecs;
    clock_gettime(CLOCK_MONOTONIC, &(p->last_alarm));
    p->next_alarm = ts_add(p->last_alarm, p->first_delay);
    }

void alarm_set_first_timeout(alarm_t *p,
                             long     secs,
                             long     nsecs)
    {
    p->first_delay.tv_sec = secs;
    p->first_delay.tv_nsec = nsecs;
    clock_gettime(CLOCK_MONOTONIC, &(p->last_alarm));
    p->next_alarm = ts_add(p->last_alarm, p->first_delay);
    }

void ac_enqueue_alarm(alarm_clock_t *alarm_clock_p,
                      alarm_t       *p)
    {
    struct timespec now;

    clock_gettime(CLOCK_MONOTONIC, &now);
    p->next_alarm = ts_add(now, p->interval);
    ac_enqueue_alarm_int(alarm_clock_p, p);
    }

void ac_enqueue_first_alarm(alarm_clock_t *alarm_clock_p,
                            alarm_t       *p)
    {
    struct timespec now;

    clock_gettime(CLOCK_MONOTONIC, &now);
    p->next_alarm = ts_add(now, p->first_delay);
    ac_enqueue_alarm_int(alarm_clock_p, p);
    }

void ac_enqueue_alarm_int(alarm_clock_t   *alarm_clock_p,
                          alarm_t         *p)
    {
    struct timespec delta;
    int wheel = 0;
    int spoke = 0;
    int mapped_spoke = 0;

    delta = ts_diff(p->next_alarm, alarm_clock_p->now);
    location(&delta, &wheel, &spoke);
    mapped_spoke = SPOKE_MAP(alarm_clock_p, wheel, spoke);

    PRINT_DEBUG2("enqueue clock=%p, alarm=%p, %d on next:%d.%09d, delta:%d.%09d, w:%d, s:%d->%d \n",
                 alarm_clock_p, p, p->id, (int)p->next_alarm.tv_sec, (int)p->next_alarm.tv_nsec,
                 (int)delta.tv_sec, (int)delta.tv_nsec, wheel, spoke, mapped_spoke);

    enqueue(&(alarm_clock_p->heads[wheel][mapped_spoke]), p);
    }

void ac_requeue_alarm(alarm_clock_t *alarm_clock_p,
                      alarm_t       *p)
    {
    ac_dequeue_alarm(p);
    ac_enqueue_alarm(alarm_clock_p, p);
    }

void ac_requeue_first_alarm(alarm_clock_t *alarm_clock_p,
                            alarm_t       *p)
    {
    ac_dequeue_alarm(p);
    ac_enqueue_first_alarm(alarm_clock_p, p);
    }

void ac_init(alarm_clock_t    *alarm_clock_p, 
             int             (*f)(alarm_t*),
             struct timespec   precision)
    {
    int wheel = 0;
    int spoke = 0;

    for(wheel=0; wheel<(int)WHEELS; wheel++)
        {
        alarm_clock_p->accumulators[wheel]=0;
        alarm_clock_p->zero_index[wheel]=0;
        for(spoke=0; spoke<(int)SPOKES; spoke++)
            alarm_clock_p->heads[wheel][spoke]=NULL;
        }

    clock_gettime(CLOCK_MONOTONIC, &alarm_clock_p->now);
    alarm_clock_p->expire_func = f;
    alarm_clock_p->precision = precision;
    }

void fire(alarm_clock_t *alarm_clock_p,
          alarm_t       *p)
    {
    int rc = -1;
    struct timespec now;

    p->last_alarm = p->next_alarm;

    if (p->recurrence > 0)
        p->recurrence--;

    if (p->expire_func)
        {
        rc = p->expire_func(p);
        }
    else if (alarm_clock_p->expire_func)
        {
        rc = alarm_clock_p->expire_func(p);
        }

    /* Set next alarm time if not already done */
    if (0 == ts_cmp(p->next_alarm, p->last_alarm))
        {
        clock_gettime(CLOCK_MONOTONIC, &now);
        p->next_alarm = ts_add(now, p->interval);
        }

    if ((rc >= 0) || (rc == ALARM_CLOCK_FOREVER))
        p->recurrence = rc;

    if (rc == ALARM_CLOCK_DELETED)
        {
        /* Nothing to do, p was deleted by user */
        }
    else if (p->recurrence != 0) 
        {
        PRINT_DEBUG("fire ac_enqueue_alarm_int, rc=%d\n", rc);
        ac_enqueue_alarm_int(alarm_clock_p, p);
        }
    else 
        {
        /* last firing, delete now */
        if (p->need_free)
            free(p);
        }
    }

void requeue(alarm_clock_t *alarm_clock_p,
             int            wheel,
             int            spoke_delta)
    {
    int spoke;
    int mapped_spoke;
    int rollover_spokes;
    alarm_t* heads[SPOKES];
    alarm_t* p;

    rollover_spokes = SPOKES_ON_WHEEL(wheel);
    PRINT_DEBUG2("requeue w:%d sd:%d sr:%d\n", wheel, spoke_delta, rollover_spokes);

    if (spoke_delta >= rollover_spokes)
       spoke_delta = rollover_spokes-1;

    for(spoke=0; spoke<=spoke_delta; spoke++)
        {
        mapped_spoke = SPOKE_MAP(alarm_clock_p, wheel, spoke);
        heads[spoke] = alarm_clock_p->heads[wheel][mapped_spoke];
        alarm_clock_p->heads[wheel][mapped_spoke] = NULL;
        PRINT_DEBUG("requeue head w:%d s:%d->%d = %p\n", wheel, spoke, mapped_spoke, heads[spoke]);
        } 

    alarm_clock_p->zero_index[wheel] = (alarm_clock_p->zero_index[wheel] + spoke_delta) % rollover_spokes;
    PRINT_DEBUG2("set zero_index w:%d z:%d\n", wheel, alarm_clock_p->zero_index[wheel]);

    for(spoke=0; spoke<=spoke_delta; spoke++)
        {
        while ((p = dequeue_head(&heads[spoke])))
            ac_enqueue_alarm_int(alarm_clock_p, p);
        }
    }


void advance(alarm_clock_t *alarm_clock_p)
    {
    struct timespec now;
    struct timespec delta;
    int wheel = 0;
    int spoke = 0;
    int shift = 0;
    int wheel_delta = 0;
    int spoke_delta = 0;
    int rollover_spokes;
    alarm_t* p;
    long nsec;

    clock_gettime(CLOCK_MONOTONIC, &now);
    delta = ts_diff(now, alarm_clock_p->now);
    location(&delta, &wheel_delta, &spoke_delta);
    alarm_clock_p->now = now;
    nsec = NSEC_SCALE * delta.tv_nsec;

    PRINT_DEBUG("advance now:%d.%09d, delta:%d.%09d, w:%d, s:%d \n", 
                (int)now.tv_sec, (int)now.tv_nsec,
                (int)delta.tv_sec, (int)delta.tv_nsec,
                wheel_delta, spoke_delta);

    for(wheel = 0; wheel < (int)WHEELS; wheel++)
        {
        if (wheel < (int)WHEELS_PER_TVNSEC)
            {
            shift = wheel * SPOKES_POW;
            alarm_clock_p->accumulators[wheel] += (nsec >> shift) & SPOKE_MASK;
            }
        else
            {
            shift = SPOKES_POW * (wheel - WHEELS_PER_TVNSEC);
            alarm_clock_p->accumulators[wheel] += (delta.tv_sec >> shift) & SPOKE_MASK;
            }
        }

    for(wheel = 0; wheel < wheel_delta; wheel++)
        {
        alarm_clock_p->zero_index[wheel] = 0;
        }

    /* enqueue to fire if on a lower wheel */
    for(wheel = 0; wheel < wheel_delta; wheel++)
        {
        if (wheel > 0)
            {
            rollover_spokes = SPOKES_ON_WHEEL(wheel-1);
            if (alarm_clock_p->accumulators[wheel-1] >= rollover_spokes)
                {
                alarm_clock_p->accumulators[wheel]++;
                alarm_clock_p->accumulators[wheel-1] -= rollover_spokes;
                }
            }

        for(spoke=0; spoke<SPOKES; spoke++)
            while ((p = dequeue_head(&(alarm_clock_p->heads[wheel][spoke]))))
                ac_enqueue_alarm_int(alarm_clock_p, p);
        }

    /* enqueue to fire if on a lower spoke of the wheel_delta */
    wheel = wheel_delta;
    if (wheel > 0)
        {
        rollover_spokes = SPOKES_ON_WHEEL(wheel-1);
        if (alarm_clock_p->accumulators[wheel-1] >= rollover_spokes)
            {
            alarm_clock_p->accumulators[wheel]++;
            alarm_clock_p->accumulators[wheel-1] -= rollover_spokes;
            PRINT_DEBUG("advance accumulator rollover, w:%d\n", wheel);
            }
        }

    requeue(alarm_clock_p, wheel, spoke_delta);

    /* if sufficient time has elapsed, relocate entries on higher wheels */
    for(wheel = wheel_delta+1; wheel < (int)WHEELS; wheel++)
        {
        rollover_spokes = SPOKES_ON_WHEEL(wheel-1);
        if (alarm_clock_p->accumulators[wheel-1] >= rollover_spokes)
           {
           alarm_clock_p->accumulators[wheel]++;
           alarm_clock_p->accumulators[wheel-1] -= rollover_spokes;
           PRINT_DEBUG("advance accumulator rollover, w:%d\n", wheel);

           requeue(alarm_clock_p, wheel, 1);
           }
       }
    
    /* if any entries were relocated to 0/0, it's time to fire */
    while ((p = dequeue_head(&(alarm_clock_p->heads[0][0]))))
        fire(alarm_clock_p, p);
        
    }


void  ac_init_alarm_int(alarm_t *p, 
                      int first,
                      int interval,
                      int recurrence,
                      int (*expire_func)(alarm_t*),
                      int id,
                      void* util_ptr,
                      int need_free)
    {
    p->id = id;
    p->util_ptr = util_ptr;
    p->recurrence = recurrence;
    
    p->head=NULL;
    p->next=NULL;
    p->first_delay.tv_sec=first;
    p->first_delay.tv_nsec=0;
    p->interval.tv_sec=interval;
    p->interval.tv_nsec=0;
    clock_gettime(CLOCK_MONOTONIC, &(p->last_alarm));
    p->next_alarm = ts_add(p->last_alarm, p->first_delay);
    p->expire_func = expire_func;
    p->need_free = need_free;
    }

void  ac_init_alarm(alarm_t *p, 
                      int first,
                      int interval,
                      int recurrence,
                      int (*expire_func)(alarm_t*),
                      int id,
                      void* util_ptr)
    {
    ac_init_alarm_int(p, first, interval, recurrence, expire_func, id, util_ptr, false);
    }

alarm_t*  ac_create_alarm(int   first,
                                         int   interval,
                                         int   recurrence,
                                         int (*expire_func)(alarm_t*),
                                         int   id,
                                         void* util_ptr
                                         )
    {
    alarm_t* p;

    p = (alarm_t*)malloc(sizeof(alarm_t));
    ac_init_alarm_int(p, first, interval, recurrence, expire_func, id, util_ptr, true);
    return p;
    }

int wheel_next_firing(alarm_clock_t* alarm_clock_p, struct timespec *delta)
    {
    int wheel;
    int spoke;
    int mapped_spoke;
    int shift;
    alarm_t* head;
    alarm_t* p;
    struct timespec temp_delta;

    for(wheel=0; wheel<(int)WHEELS; wheel++)
        for(spoke=0; spoke<(int)SPOKES; spoke++)
            {
            mapped_spoke = SPOKE_MAP(alarm_clock_p, wheel, spoke);
            head = alarm_clock_p->heads[wheel][mapped_spoke];
            if (head)
                {
                PRINT_DEBUG("wheel_next_firing w:%d s:%d->%d\n", wheel, spoke, mapped_spoke);
                /* compute minimum next firing delta based on next_alarm values in this list */
                p=head;
                *delta = ts_diff(p->next_alarm, alarm_clock_p->now);
                while((p = p->next))
                    {
                    temp_delta = ts_diff(p->next_alarm, alarm_clock_p->now);
                    *delta = ts_min(*delta, temp_delta);
                    }

                /* compute theoretical next firing delta based on wheel and spoke */
                if (wheel < (int)WHEELS_PER_TVNSEC)
                    {
                    shift = SPOKES_POW * wheel;
                    temp_delta.tv_sec = 0;
                    temp_delta.tv_nsec = ((float)((spoke) << shift) / (float)NSEC_SCALE);
                    }
                else
                    {
                    shift = SPOKES_POW * (wheel - WHEELS_PER_TVNSEC);
                    temp_delta.tv_sec = ((spoke) << shift);
                    temp_delta.tv_nsec = 0;
                    }
                
                if (temp_delta.tv_nsec >= 1000000000)
                    {
                    temp_delta.tv_nsec -= 1000000000;
                    temp_delta.tv_sec += 1;
                    }

                /* final next fire delta is max of values computed via list, via wheel&spoke, or via min precision */
                *delta = ts_max(*delta, temp_delta);
                *delta = ts_max(*delta, alarm_clock_p->precision);
                return 1;
                }
            }

    delta->tv_sec = 60;
    delta->tv_nsec = 0;
    return 0;
    }

int ac_pselect(alarm_clock_t         *alarm_clock_p,
               int                    nfds,
               fd_set                *readfds,
               fd_set                *writefds,
               fd_set                *exceptfds,
               const struct timespec *timeout,
               const sigset_t        *sigmask)
    {
    int rc;
    struct timespec delta;
    struct timespec final_timeout;
    int save_errno;

    rc = wheel_next_firing(alarm_clock_p, &delta);

    PRINT_DEBUG("wheel_next_firing %d.%09d\n",
                (int)delta.tv_sec, (int)delta.tv_nsec);

    if (timeout)
        final_timeout = ts_min(delta, *timeout);
    else
        final_timeout = delta;

    PRINT_DEBUG("wheel_next_firing %d.%09d\n",
                (int)final_timeout.tv_sec, (int)final_timeout.tv_nsec);

    rc = pselect(nfds, readfds, writefds, exceptfds, &final_timeout, sigmask);
    save_errno = errno;
    if (rc < 0)
        {
        PRINT_ERR("pselect: rc=%d, nfds=%d, delta=%d.%09d: %s\n", rc, nfds, (int)delta.tv_sec, (int)delta.tv_nsec, strerror(errno));
        }
    advance(alarm_clock_p);
    errno = save_errno;
    return rc;
    }

int ac_select(alarm_clock_t  *alarm_clock_p,
              int             nfds,
              fd_set         *readfds,
              fd_set         *writefds,
              fd_set         *exceptfds,
              struct timeval *timeout)
    {
    struct timespec  timeout_ts;
    struct timespec *tsp = NULL;

    if (timeout)
        {
        tsp = &timeout_ts;
        timeout_ts.tv_sec = timeout->tv_sec;
        timeout_ts.tv_nsec = timeout_ts.tv_nsec * 1000;
        }

    return ac_pselect(alarm_clock_p, nfds, readfds, writefds, exceptfds, tsp, NULL);
    }

int ac_ppoll(alarm_clock_t         *alarm_clock_p,
             struct pollfd         *fds,
             nfds_t                 nfds,
             const struct timespec *timeout_ts,
             const sigset_t        *sigmask)
    {
    int rc;
    struct timespec delta;
    struct timespec final_timeout;
    int save_errno;

    PRINT_DEBUG("ppoll: in\n");
    rc = wheel_next_firing(alarm_clock_p, &delta);
    
    PRINT_DEBUG("wheel_next_firing %d.%09d\n",
                (int)delta.tv_sec, (int)delta.tv_nsec);

    if (timeout_ts)
        final_timeout = ts_min(delta, *timeout_ts);
    else
        final_timeout = delta;

    PRINT_DEBUG("ppoll: fds=%p, nfds=%d, delta=%d.%09d: %s\n", fds, (int)nfds, (int)final_timeout.tv_sec, (int)final_timeout.tv_nsec, strerror(errno));
    rc = ppoll(fds, nfds, &final_timeout, sigmask);
    save_errno = errno;
    if (rc < 0)
        {
        PRINT_ERR("ppoll: rc=%d, nfds=%d, delta=%d.%09d: %s\n", rc, (int)nfds, (int)delta.tv_sec, (int)delta.tv_nsec, strerror(errno));
        }
    PRINT_DEBUG("ppoll: pre-advance\n");
    advance(alarm_clock_p);
    PRINT_DEBUG("ppoll: out\n");
    errno = save_errno;
    return rc;
    }

int ac_poll(alarm_clock_t *alarm_clock_p,
            struct pollfd *fds,
            nfds_t         nfds,
            int            timeout)
    {
    struct timespec  timeout_ts;
    struct timespec *tsp = NULL;

    if (timeout >= 0)
        {
        timeout_ts.tv_sec = timeout/1000;
        timeout_ts.tv_nsec = (timeout % 1000) * 1000000;
        tsp = &timeout_ts;
        }
    return ac_ppoll(alarm_clock_p, fds, nfds, tsp, NULL);
    }

void ac_run_clock(alarm_clock_t* alarm_clock_p)
    {
    int rc;

    while(1)
        {
        rc = ac_select(alarm_clock_p, 0, NULL, NULL, NULL, NULL);
        if (rc < 0)
            {
            PRINT_ERR("ac_select: rc=%d\n", rc);
            }
        }
   }



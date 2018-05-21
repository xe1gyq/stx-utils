/*
* Copyright (c) 2013-2014 Wind River Systems, Inc.
*
* SPDX-License-Identifier: Apache-2.0
*
*/

#ifndef __ALARM_CLOCK_TYPES_H__
#define __ALARM_CLOCK_TYPES_H__

/**
*/

#include <time.h>

#define ALARM_CLOCK_STOP      0
#define ALARM_CLOCK_FOREVER  -1
#define ALARM_CLOCK_CONTINUE -2
#define ALARM_CLOCK_DELETED  -3

typedef struct alarm_s alarm_t;
struct alarm_s
   {
   alarm_t          *next;
   alarm_t         **head; /* ptr to head of queue this node resides on */
   int               recurrence;
   struct timespec   interval;
   struct timespec   first_delay;
   struct timespec   last_alarm;
   struct timespec   next_alarm;
   int               id;
   void             *util_ptr;
   int             (*expire_func)(alarm_t*);
   int               need_free;
   };

#define BITS_PER_BYTE 8
#define SPOKES_POW 4
#define SPOKES (1 << SPOKES_POW)
#define SPOKE_MASK (SPOKES - 1)
#define WHEELS_PER_TVSEC (sizeof(time_t) * BITS_PER_BYTE / SPOKES_POW)
#define WHEELS_PER_TVNSEC 8
#define DISCONTINUITY_WHEEL 7
#define DISCONTINUITY_SPOKES 4   
#define NSEC_SCALE ((float)(DISCONTINUITY_SPOKES * (1 << (SPOKES_POW * DISCONTINUITY_WHEEL))) / 1000000000.0)
#define WHEELS (WHEELS_PER_TVSEC + WHEELS_PER_TVNSEC)

#define SPOKES_ON_WHEEL(wheel) (((wheel)==DISCONTINUITY_WHEEL) ?  DISCONTINUITY_SPOKES : SPOKES)
#define SPOKE_MAP(wheel_ptr, wheel_idx, spoke_idx) (((wheel_ptr)->zero_index[(wheel_idx)] + (spoke_idx)) % SPOKES_ON_WHEEL(wheel_idx))

typedef alarm_t* alarm_p;
typedef struct alarm_clock_s alarm_clock_t;
struct alarm_clock_s
   {
   alarm_p           heads[WHEELS][SPOKES];
   int               accumulators[WHEELS];
   int               zero_index[WHEELS];
   struct timespec   now;
   int             (*expire_func)(alarm_t*);
   struct timespec   precision;
   };

#endif /* __ALARM_CLOCK_TYPES_H__ */

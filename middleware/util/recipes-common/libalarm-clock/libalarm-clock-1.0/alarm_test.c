/*
* Copyright (c) 2013-2014 Wind River Systems, Inc.
*
* SPDX-License-Identifier: Apache-2.0
*
*/

/**
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <resolv.h>
#include <time.h> 
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "alarm_clock.h"


alarm_clock_t alarm_clock;

int expired(alarm_t* p)
    {
    char buf[80];
    time_t t;
    struct tm lt;

    time(&t);
    localtime_r(&t, &lt);
    strftime(buf, sizeof(buf), "%T", &lt);
    printf("%s: %d fired, r:%d\n", buf, p->id, p->recurrence);
    if (p->recurrence==0)
       free(p);

    return ALARM_CLOCK_CONTINUE;
    }

int main()
    {
    struct timespec precision;

    precision.tv_sec = 0;
    precision.tv_nsec = 10000000;   /* 10 millisec */
    ac_init(&alarm_clock, expired, precision);
    ac_enqueue_alarm(&alarm_clock, ac_create_alarm(10,  1, 100, NULL, 1, NULL));
    ac_enqueue_alarm(&alarm_clock, ac_create_alarm(90, 13,  20, NULL, 2, NULL));
    ac_enqueue_alarm(&alarm_clock, ac_create_alarm( 8,  2, 100, NULL, 3, NULL));
    ac_enqueue_alarm(&alarm_clock, ac_create_alarm(70, 23,  10, NULL, 4, NULL));
    ac_enqueue_alarm(&alarm_clock, ac_create_alarm(10,  3, 100, NULL, 5, NULL));
    ac_run_clock(&alarm_clock);
    return 0;
    }


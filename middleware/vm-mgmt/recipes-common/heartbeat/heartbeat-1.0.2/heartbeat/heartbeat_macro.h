/*
* Copyright (c) 2013-2014 Wind River Systems, Inc.
*
* SPDX-License-Identifier: Apache-2.0
*
*/

#ifndef __HEARTBEAT_MACRO_H__
#define __HEARTBEAT_MACRO_H__

/**
*/

#define _GNU_SOURCE
#include <errno.h>
#include <time.h>
#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/syscall.h>

#include "heartbeat_common.h"

#define gettid() ((pid_t)syscall(SYS_gettid))
#define tkill(tid, sig) ((int)syscall(SYS_tkill, (tid), (sig)))

#define DEBUG 0
#define MESSAGE 0
#define INFO 1

#define PRINT(lvl, s) syslog(LOG_USER | lvl, "%s", s)

#define PRINT_INFO(format, ...) \
    ({ \
    char _buf[512]; \
    char _buf2[1024]; \
    struct timespec _t; \
    struct tm _lt; \
    pid_t _pid; \
    pid_t _tid; \
    _pid = getpid(); \
    _tid = gettid(); \
    if (hb_debug_info || INFO) \
       { \
       clock_gettime(CLOCK_REALTIME, &_t); \
       localtime_r(&_t.tv_sec, &_lt); \
       strftime(_buf, sizeof(_buf), "%T", &_lt); \
       snprintf(_buf2, sizeof(_buf2), "%s.%09ld %s[%d:%d](%s) %s:%d %s: INFO: " format, _buf, _t.tv_nsec, program_invocation_short_name, _pid, _tid, hb_get_role_name(hb_role), __FILE__, __LINE__, __FUNCTION__, ##__VA_ARGS__); \
       PRINT(LOG_INFO, _buf2); \
       } \
    })

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
    snprintf(_buf2, sizeof(_buf2), "%s.%09ld %s[%d:%d](%s) %s:%d %s: ERROR: " format, _buf, _t.tv_nsec, program_invocation_short_name, _pid, _tid, hb_get_role_name(hb_role), __FILE__, __LINE__, __FUNCTION__, ##__VA_ARGS__); \
    PRINT(LOG_ERR, _buf2); \
    })

#define PRINT_MESSAGE(format, ...) \
    ({ \
    char _buf[512]; \
    char _buf2[1024]; \
    struct timespec _t; \
    struct tm _lt; \
    pid_t _pid; \
    pid_t _tid; \
    if (hb_debug_message || MESSAGE) \
       { \
       _pid = getpid(); \
       _tid = gettid(); \
       clock_gettime(CLOCK_REALTIME, &_t); \
       localtime_r(&_t.tv_sec, &_lt); \
       strftime(_buf, sizeof(_buf), "%T", &_lt); \
       snprintf(_buf2, sizeof(_buf2), "%s.%09ld %s[%d:%d](%s) %s:%d %s: MESSAGE: " format, _buf, _t.tv_nsec, program_invocation_short_name, _pid, _tid, hb_get_role_name(hb_role), __FILE__, __LINE__, __FUNCTION__, ##__VA_ARGS__); \
       PRINT(LOG_INFO, _buf2); \
       } \
    })

#define PRINT_DEBUG(format, ...) \
    ({ \
    char _buf[512]; \
    char _buf2[1024]; \
    struct timespec _t; \
    struct tm _lt; \
    pid_t _pid; \
    pid_t _tid; \
    if (hb_debug_debug || DEBUG) \
       { \
       _pid = getpid(); \
       _tid = gettid(); \
       clock_gettime(CLOCK_REALTIME, &_t); \
       localtime_r(&_t.tv_sec, &_lt); \
       strftime(_buf, sizeof(_buf), "%T", &_lt); \
       snprintf(_buf2, sizeof(_buf2), "%s.%09ld %s[%d:%d](%s) %s:%d %s: DEBUG: " format, _buf, _t.tv_nsec, program_invocation_short_name, _pid, _tid, hb_get_role_name(hb_role), __FILE__, __LINE__, __FUNCTION__, ##__VA_ARGS__); \
       PRINT(LOG_DEBUG, _buf2); \
       } \
    })

#define PRINT_INFO_NSFD(fd1, fd2, format, ...) \
    ({ \
     setns(fd1); \
     PRINT_INFO(format, ##__VA_ARGS__); \
     setns(fd2); \
    })
#define PRINT_DEBUG_NSFD(fd1, fd2, format, ...)  \
    ({ \
     setns(fd1); \
     PRINT_DEBUG(format, ##__VA_ARGS__); \
     setns(fd2); \
    })
#define PRINT_MESSAGE_NSFD(fd1, fd2, format, ...) \
    ({ \
     setns(fd1); \
     PRINT_MESSAGE(format, ##__VA_ARGS__); \
     setns(fd2); \
    })
#define PRINT_ERR_NSFD(fd1, fd2, format, ...) \
    ({ \
     setns(fd1); \
     PRINT_ERR(format, ##__VA_ARGS__); \
     setns(fd2); \
    })
#define PRINT_INFO_NS(ns, format, ...)    PRINT_INFO_NSFD(syslog_fd, ns->ns_fd, format, ##__VA_ARGS__) 
#define PRINT_DEBUG_NS(ns, format, ...)   PRINT_DEBUG_NSFD(syslog_fd, ns->ns_fd, format, ##__VA_ARGS__) 
#define PRINT_MESSAGE_NS(ns, format, ...) PRINT_MESSAGE_NSFD(syslog_fd, ns->ns_fd, format, ##__VA_ARGS__) 
#define PRINT_ERR_NS(ns, format, ...)     PRINT_ERR_NSFD(syslog_fd, ns->ns_fd, format, ##__VA_ARGS__) 

#endif /* __HEARTBEAT_MACRO_H__ */

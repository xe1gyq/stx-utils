/*
* Copyright (c) 2013-2014 Wind River Systems, Inc.
*
* SPDX-License-Identifier: Apache-2.0
*
*/

/**
*/

// for POLLRDHUP
#define _GNU_SOURCE

#include "heartbeat_types.h"
#include "heartbeat_macro.h"

#include <dirent.h>
#include <errno.h>
#include <execinfo.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <poll.h>
#include <pthread.h>
#include <resolv.h>
#include <sched.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h> 
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/inotify.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>

#define EXTEND_POOLHD 16

const char* hb_fd_type_names[] =
    {
    "unknown",
    "client_sock",
    "client_vio",
    "server_sock",
    "server_vio",    // unconnected
    "server_client_sock",
    "server_client_vio",
    "ns_pipe",
    "inotify",
    };


void hb_pollfd_print(hb_pollfd_data_t *pollfd_data)
    {
    int i;
    struct pollfd *pp;
    hb_fd_data_t  *fp;

    PRINT_INFO("pollfd_data = %p\n", pollfd_data);
    PRINT_INFO("array_high = %d, array_max = %d\n", pollfd_data->array_high, pollfd_data->array_max);
    PRINT_INFO("fd_array = %p\n", pollfd_data->fd_array);
    PRINT_INFO("pollfd_array = %p\n", pollfd_data->pollfd_array);
    for(i=0; i<pollfd_data->array_high; i++)
        {
        pp = &(pollfd_data->pollfd_array[i]);
        fp = &(pollfd_data->fd_array[i]);
        PRINT_INFO("fd_array[%d]: fd_type = %d, idx = %d, ptr = %p\n", i, fp->fd_type, fp->idx, fp->ptr);
        PRINT_INFO("pollfd_array[%d]: fd = %d, events = %x, revents = %x\n", i, pp->fd, pp->events, pp->revents);
        }
    }




const char* hb_get_fd_type_name(hb_fd_type_t fd_type)
    {
    if (fd_type >= hbft_max)
        return "???";

    return hb_fd_type_names[fd_type];
    }

void hb_clear_pollfd_record(struct pollfd *p)
    {
    p->fd = -1;
    p->events = POLLIN | POLLRDHUP;
    p->revents = 0;
    }

void hb_clear_fd_record(hb_fd_data_t *p)
    {
    p->fd_type = hbft_unknown;
    p->idx = -1;
    p->ptr = NULL;
    }

int hb_extend_pollfd_data(hb_pollfd_data_t* pollfd_data)
    {
    int            i;
    int            tmp_max = 0;
    struct pollfd *tmp_pa = NULL;
    hb_fd_data_t  *tmp_fa = NULL;
    struct pollfd *old_pa = NULL;
    hb_fd_data_t  *old_fa = NULL;

    tmp_max = pollfd_data->array_max + EXTEND_POOLHD;
    tmp_pa = (typeof(tmp_pa))malloc(tmp_max * sizeof(*tmp_pa));
    tmp_fa = (typeof(tmp_fa))malloc(tmp_max * sizeof(*tmp_fa));
    if (!tmp_pa || !tmp_fa)
        {
        PRINT_ERR("malloc failure at n=%d records\n", tmp_max);
        if (tmp_pa)
            free(tmp_pa);
        if (tmp_fa)
            free(tmp_fa);
        return -1;
        }

    old_pa = pollfd_data->pollfd_array;
    old_fa = pollfd_data->fd_array;
    memcpy(tmp_pa, old_pa, pollfd_data->array_max * sizeof(*tmp_pa));
    memcpy(tmp_fa, old_fa, pollfd_data->array_max * sizeof(*tmp_fa));
    for(i=pollfd_data->array_max; i<tmp_max; i++)
        {
        hb_clear_pollfd_record(&(tmp_pa[i]));
        hb_clear_fd_record(&(tmp_fa[i]));
        }
    pollfd_data->pollfd_array = tmp_pa;
    pollfd_data->fd_array = tmp_fa;
    pollfd_data->array_max = tmp_max;
    return 0;
    }

int hb_pollfd_find_fd(hb_pollfd_data_t *pollfd_data,
                      int               fd)
    {
    int i;

    if (!pollfd_data)
        return -1;

    for(i=0; i<pollfd_data->array_high; i++)
        if (fd == pollfd_data->pollfd_array[i].fd)
            return i;
    return -1;
    }


int hb_pollfd_remove_fd(hb_pollfd_data_t *pollfd_data,
                        int               fd)
    {
    int i;
    int j;

    if (!pollfd_data || fd<0)
        return -1;

    i = hb_pollfd_find_fd(pollfd_data, fd);
    if (i < 0)
        {
        PRINT_ERR("fd=%d not found\n", fd);
        return -1;
        }

    j = pollfd_data->array_high-1;
    PRINT_INFO("idx=%d, fd=%d, swapped idx=%d\n", i, fd, j);
    // hb_pollfd_print(pollfd_data);
    if (j < 0)
        {
        PRINT_ERR("array_high=%d yet found element at index %d\n", pollfd_data->array_high, i);
        j = i;
        }

    if (i < j)
        {
        pollfd_data->pollfd_array[i] = pollfd_data->pollfd_array[j];
        pollfd_data->fd_array[i] = pollfd_data->fd_array[j];
        }

    hb_clear_pollfd_record(&(pollfd_data->pollfd_array[j]));
    hb_clear_fd_record(&(pollfd_data->fd_array[j]));
    pollfd_data->array_high--;

    // hb_pollfd_print(pollfd_data);
    return i;
    }

int hb_pollfd_modify_fd(hb_pollfd_data_t *pollfd_data,
                        int               fd,
                        hb_fd_type_t      fd_type,
                        int               idx,
                        void             *ptr)
    {
    int i;
    hb_fd_data_t  *fp;

    if (!pollfd_data || fd<0)
        return -1;

    i = hb_pollfd_find_fd(pollfd_data, fd);
    if (i < 0)
        {
        PRINT_ERR("fd=%d not found\n", fd);
        return -1;
        }

    fp = &(pollfd_data->fd_array[i]);
    fp->fd_type = fd_type;
    fp->idx = idx;
    fp->ptr = ptr;

    PRINT_INFO("idx=%d, fd=%d, type=%s, idx=%d, ptr=%p\n", i, fd, hb_get_fd_type_name(fd_type), idx, ptr);
    // hb_pollfd_print(pollfd_data);
    return i;
    }

int hb_pollfd_add(hb_pollfd_data_t *pollfd_data,
                  int               fd, 
                  hb_fd_type_t      fd_type,
                  int               idx,
                  void             *ptr)
    {
    int i;
    int rc = -1;
    struct pollfd *pp;
    hb_fd_data_t  *fp;

    if (!pollfd_data || fd<0 || fd_type>=hbft_max || fd_type<=hbft_unknown)
        {
        PRINT_ERR("Bad arg: data=%p, fd=%d, type=%d, idx=%d, ptr=%p\n", pollfd_data, fd, fd_type, idx, ptr);
        return -1;
        } 

    i = hb_pollfd_find_fd(pollfd_data, fd);
    if (i >= 0)
        {
        PRINT_ERR("fd=%d alread registered in slot %d\n", fd, i);
        return -1;
        }

    if (pollfd_data->array_high >= pollfd_data->array_max)
        {
        rc = hb_extend_pollfd_data(pollfd_data);
        if (rc < 0 || pollfd_data->array_high >= pollfd_data->array_max)
            {
            PRINT_ERR("Failed to extend\n");
            return -1;
            }
        } 

    pp = &(pollfd_data->pollfd_array[pollfd_data->array_high]);
    fp = &(pollfd_data->fd_array[pollfd_data->array_high]);
    fp->fd_type = fd_type;
    fp->idx = idx;
    fp->ptr = ptr;
    pp->fd = fd;
    pp->events = POLLIN | POLLRDHUP;
    pp->revents = 0;
    rc = pollfd_data->array_high;
    pollfd_data->array_high++;

    PRINT_INFO("idx=%d, fd=%d, type=%s, idx=%d, ptr=%p\n", rc, fd, hb_get_fd_type_name(fd_type), idx, ptr);
    // hb_pollfd_print(pollfd_data);
    return rc;
    }

void hb_init_pollfd_data(hb_pollfd_data_t* pollfd_data)
    {
    pollfd_data->array_high = 0;
    pollfd_data->array_max = 0;
    pollfd_data->pollfd_array = NULL;
    pollfd_data->fd_array = NULL;
    }


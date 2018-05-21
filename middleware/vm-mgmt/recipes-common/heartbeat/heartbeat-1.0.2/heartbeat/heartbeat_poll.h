/*
* Copyright (c) 2013-2014 Wind River Systems, Inc.
*
* SPDX-License-Identifier: Apache-2.0
*
*/

#ifndef __HEARTBEAT_POLL_H__
#define __HEARTBEAT_POLL_H__

/**
*/

#include "heartbeat_types.h"



extern int hb_pollfd_find_fd(hb_pollfd_data_t *pollfd_data,
                             int               fd);

extern int hb_pollfd_remove_fd(hb_pollfd_data_t *pollfd_data,
                               int               fd);

extern int hb_pollfd_add(hb_pollfd_data_t *pollfd_data,
                         int               fd,
                         hb_fd_type_t      fd_type,
                         int               idx,
                         void             *ptr);

extern int hb_pollfd_modify_fd(hb_pollfd_data_t *pollfd_data,
                               int               fd,
                               hb_fd_type_t      fd_type,
                               int               idx,
                               void             *ptr);

extern void hb_init_pollfd_data(hb_pollfd_data_t* pollfd_data);

extern const char* hb_get_fd_type_name(hb_fd_type_t fd_type);


#endif /* __HEARTBEAT_POLL_H__ */

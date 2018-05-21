/*
* Copyright (c) 2013-2014 Wind River Systems, Inc.
*
* SPDX-License-Identifier: Apache-2.0
*
*/

#ifndef __HEARTBEAT_VIRTIO_H__
#define __HEARTBEAT_VIRTIO_H__

#include "heartbeat_types.h"

#include <stdbool.h>

extern vio_data_t vio_data;

extern int vio_server_init(ns_data_t *ns);

extern void vio_inotify_event(ns_data_t *ns);

extern vio_record_t* vio_ptr_find_by_fd(int fd);

extern int vio_find_by_fd(int fd);

extern void vio_disconnect(vio_record_t *vio, ns_data_t *ns);

extern void vio_full_disconnect(vio_record_t *vio, ns_data_t *ns);

extern void vio_reconnect(vio_record_t *vio, ns_data_t *ns);

extern void vio_scan(ns_data_t *ns);

#endif /* __HEARTBEAT_VIRTIO_H__ */

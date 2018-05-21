/*
* Copyright (c) 2013-2014 Wind River Systems, Inc.
*
* SPDX-License-Identifier: Apache-2.0
*
*/

#ifndef __HEARTBEAT_VIRTIO_COMMON_H__
#define __HEARTBEAT_VIRTIO_COMMON_H__

/**
*/

#include "heartbeat_types.h"

#include <stdbool.h>


extern vio_data_t vio_data;



extern int vio_client_init(hb_client_t *client);



#endif /* __HEARTBEAT_VIRTIO_COMMON_H__ */

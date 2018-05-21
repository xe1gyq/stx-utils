/*
* Copyright (c) 2013-2014 Wind River Systems, Inc.
*
* SPDX-License-Identifier: Apache-2.0
*
*/

#ifndef __HEARTBEAT_UTIL_H__
#define __HEARTBEAT_UTIL_H__

/**
*/
#include "heartbeat_message.h"
#include "heartbeat_types.h"

extern hb_server_client_t* find_server_client_from_hostname(ns_data_t* ns, const char* host_name);

#endif  /* __HEARTBEAT_UTIL_H__ */

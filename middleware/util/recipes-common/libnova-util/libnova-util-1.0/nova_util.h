/*
* Copyright (c) 2013-2014 Wind River Systems, Inc.
*
* SPDX-License-Identifier: Apache-2.0
*
*/

#ifndef __NOVA_UTIL_H__
#define __NOVA_UTIL_H__

/**
*/

#include "nova_util_types.h"


extern char* nova_find_id_from_name(const char* target);

extern char* nova_find_id_from_instance_name(const char* target);

extern char* nova_find_id_from_ip_addr(const char* target);

extern char* nova_find_dhcp_host_from_id(const char* instance_id);

extern char* nova_find_vm_host_from_id(const char* instance_id);

extern char* nova_find_network_id_from_instance_id(const char* instance_id);

extern int nova_set_timeout(char *instance_id, nova_timer_t id, int timeout_ms);

extern char* get_nova_timer_name(nova_timer_t id);

extern nova_timer_t get_nova_timer_id(const char* timer_name);

extern int nova_cmd_issue(const char  *cmd,
                          int        (*alt_system)(const char* cmd));

#endif /* __NOVA_UTIL_H__ */


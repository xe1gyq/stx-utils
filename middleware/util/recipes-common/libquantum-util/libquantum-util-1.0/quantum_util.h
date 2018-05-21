/*
* Copyright (c) 2013-2014 Wind River Systems, Inc.
*
* SPDX-License-Identifier: Apache-2.0
*
*/

#ifndef __QUANTUM_UTIL_H__
#define __QUANTUM_UTIL_H__

/**
*/

extern int get_os_env(void);

extern int get_os_passwd(char *passwd_buf, int passwd_buf_size);

extern char* quantum_find_dhcp_host_from_net(const char* network_name);

extern char* quantum_find_id_from_name(const char* network_name);


#endif /* __QUANTUM_UTIL_H__ */

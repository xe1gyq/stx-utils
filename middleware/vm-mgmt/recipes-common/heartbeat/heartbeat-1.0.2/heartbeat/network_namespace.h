/*
* Copyright (c) 2013-2014 Wind River Systems, Inc.
*
* SPDX-License-Identifier: Apache-2.0
*
*/

#ifndef __network_namespace_h__
#define __network_namespace_h__

/**
*/


#include "heartbeat_message.h"
#include "heartbeat_types.h"

extern hb_server_client_t* find_scp_from_abstract_name(heartbeat_inst_id_t id_type, const char* id);

extern hb_server_client_t* find_scp_from_instance_id(const char* id);

extern hb_server_client_t* find_server_client_from_instance_name(ns_data_t* ns, const char* instance_name);

extern hb_server_client_t* find_server_client_from_instance_id(ns_data_t* ns, const char* instance_id);

extern hb_server_client_t* find_server_client_from_name(ns_data_t* ns, const char* name);

extern ns_data_t* ns_find_ns_name(const char* ns_name);

extern ns_data_t* ns_add(const char *ns_name);

extern void ns_insert(ns_data_t *new_ns);

extern int ns_delete(const char *ns_name);

extern ns_traverse_return_t ns_traverse(
                                        ns_traverse_func_return_t (*f)(ns_data_t *ptr,
                                                                       void      *arg),
                                        void                       *arg);

extern char* ns_find_ns_name_from_quantum_network_id(const char* network_id);

extern int ns_check(const char *name_space);

extern void discover_namespaces();


#endif /* __network_namespace_h__ */

/*
* Copyright (c) 2013-2014 Wind River Systems, Inc.
*
* SPDX-License-Identifier: Apache-2.0
*
*/

#ifndef __HEARTBEAT_ROLE_H__
#define __HEARTBEAT_ROLE_H__

/**
*/
#include "heartbeat_message.h"
#include "heartbeat_types.h"

extern void set_msg_host_info(heartbeat_message_t *message);
extern void issue_nova_cmd(const char* cmd, ns_data_t *ns);
extern void handle_nova_cmd(ns_data_t           *ns,
                            heartbeat_message_t *message);
extern void handle_timeouts_event(ns_data_t           *ns, 
                                  heartbeat_message_t *message);
extern void set_instance_id_from_instance_name_via_proxy(hb_server_client_t *scp, const char* inst_name);
extern void discover_namespaces_thread_start();
extern void discover_vio_thread_start();


extern void* set_instance_id_from_instance_name_via_proxy_helper(void* arg);
extern void set_instance_id_from_addr_via_proxy(hb_server_client_t *scp, const char* remote_addr_str);
extern void hb_handle_hbca_instance_reboot(hb_server_client_t *scp);
extern void hb_handle_hbca_instance_stop(hb_server_client_t *scp);
extern void hb_handle_hbca_instance_delete(hb_server_client_t *scp);
extern void hb_handle_hbm_nova_cmd(ns_data_t *ns, heartbeat_message_t *message, hb_fd_type_t fdt);
extern void hb_handle_hbm_timeouts(ns_data_t *ns, heartbeat_message_t *message);


extern int handle_shutdown_request_proxied_control(ns_data_t           *ns,
                                                   heartbeat_message_t *message,
                                                   hb_server_client_t  *scp,
                                                   int                  reply_sock,
                                                   heartbeat_message_t *response
                                                   );

extern int handle_shutdown_request_proxied_compute(ns_data_t           *ns,
                                                   heartbeat_message_t *message,
                                                   hb_server_client_t  *scp,
                                                   int                  reply_sock,
                                                   heartbeat_message_t *response
                                                   );

extern void hb_early_init(void);

#endif  /* __HEARTBEAT_ROLE_H__ */


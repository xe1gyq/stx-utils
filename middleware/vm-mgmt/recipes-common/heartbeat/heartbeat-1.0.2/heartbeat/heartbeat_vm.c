/*
* Copyright (c) 2013-2014 Wind River Systems, Inc.
*
* SPDX-License-Identifier: Apache-2.0
*
*/

/**
*/
#include "heartbeat_macro.h"
#include "heartbeat_message.h"
#include "heartbeat_types.h"
#include "heartbeat_common.h"
#include "heartbeat_virtio.h"
#include "heartbeat_poll.h"


#include <ctype.h>
#include <errno.h>
#include <execinfo.h>
#include <fcntl.h>
#include <netdb.h>
#include <pthread.h>
#include <resolv.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h> 
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>




void issue_nova_cmd(const char* cmd, ns_data_t *ns)
    {
    cmd=cmd;
    ns=ns;
    }

void handle_nova_cmd(ns_data_t           *ns,
                     heartbeat_message_t *message)
    {
    ns=ns;
    message=message;
    }


void handle_timeouts_event(ns_data_t           *ns, 
                          heartbeat_message_t *message)
    {
    ns=ns;
    message=message;
    }


void set_instance_id_from_instance_name_via_proxy(hb_server_client_t *scp, const char* inst_name)
    {
    scp=scp;
    inst_name=inst_name;
    }

void set_instance_id_from_addr_via_proxy(hb_server_client_t *scp, const char* remote_addr_str)
    {
    scp=scp;
    remote_addr_str=remote_addr_str;
    }

    

void* discover_namespaces_thread(void* arg)
    {
    arg=arg;
    return NULL;
    }

void discover_namespaces_thread_start()
    {
    }

void* discover_vio_thread(void* arg)
    {
    arg=arg;
    return NULL;
    }

void discover_vio_thread_start()
    {
    }



void set_msg_host_info(heartbeat_message_t *message)
    {
    message=message;
    }


void hb_handle_hbca_instance_reboot(hb_server_client_t *scp)
    {
    PRINT_ERR("corrective action: Openstack Reboot for '%s' not supported directly from VM\n", scp->name);
    }

void hb_handle_hbca_instance_stop(hb_server_client_t *scp)
    {
    PRINT_ERR("corrective action: Openstack Stop for '%s' not supported directly from VM\n", scp->name);
    }

void hb_handle_hbca_instance_delete(hb_server_client_t *scp)
    {
    PRINT_ERR("corrective action: Openstack Delete for '%s' not supported directly from VM\n", scp->name);
    }

void hb_handle_hbm_nova_cmd(ns_data_t *ns, heartbeat_message_t *message, hb_fd_type_t fdt)
    {
    ns=ns;
    message=message;
    fdt=fdt;
    PRINT_ERR("hbm_nova_cmd message recieved by VM\n");
    }

void hb_handle_hbm_timeouts(ns_data_t *ns, heartbeat_message_t *message)
    {
    ns=ns;
    message=message;
    PRINT_ERR("hbm_timeouts message recieved by VM\n");
    }

int handle_shutdown_request_proxied_control(ns_data_t           *ns,
                                            heartbeat_message_t *message,
                                            hb_server_client_t  *scp,
                                            int                  reply_sock,
                                            heartbeat_message_t *response
                                            )
    {
    ns=ns;
    message=message;
    scp=scp;
    reply_sock=reply_sock;
    response=response;

    PRINT_ERR("hb_role == hbr_control for VM.");
    return 0;
    }

int handle_shutdown_request_proxied_compute(ns_data_t           *ns,
                                            heartbeat_message_t *message,
                                            hb_server_client_t  *scp,
                                            int                  reply_sock,
                                            heartbeat_message_t *response
                                            )
    {
    ns=ns;
    message=message;
    scp=scp;
    reply_sock=reply_sock;
    response=response;

    PRINT_ERR("hb_role == hbr_compute for VM.");
    return 0;
    }

void hb_early_init()
    {
    }

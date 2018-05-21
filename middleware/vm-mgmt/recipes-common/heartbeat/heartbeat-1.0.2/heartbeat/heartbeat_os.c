/*
* Copyright (c) 2013-2014 Wind River Systems, Inc.
*
* SPDX-License-Identifier: Apache-2.0
*
*/

/**
*/
#include "heartbeat_macro.h"
#include <cgcs/alarm_clock.h>
#include "heartbeat_message.h"
#include "heartbeat_types.h"
#include "heartbeat_common.h"
#include "heartbeat_virtio.h"
#include "heartbeat_poll.h"
#include "heartbeat_util.h"
#include "network_namespace.h"

#include <cgcs/nova_util.h>

#include <cgcs/trap_handler.h>
#include <cgcs/atomic.h>

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



extern ns_data_t   server_ns;

extern int hb_system(const char* cmd);
extern void init_pipe_message(heartbeat_message_t *response,
                              heartbeat_message_type_t  mtype);
extern void handle_pipe_disconnect(ns_data_t *ns);
extern int expired_waiting_shutdown_response(alarm_t* p);
extern ssize_t hb_sc_write(hb_server_client_t* scp, heartbeat_message_t *message, size_t size);
extern void handle_shutdown_response(ns_data_t           *ns,
                                     heartbeat_message_t *message,
                                     hb_server_client_t  *scp);
extern void handle_network_namespace_event(ns_data_t           *ns,
                                           heartbeat_message_t *message);



void send_nova_cmd(const char* cmd, ns_data_t *ns)
    {
    heartbeat_message_t      message;
    hb_client_t             *client;

    if (hb_role == hbr_control)
        {
        PRINT_ERR("Can't forward to a higher authority than 'control'\n");
        return;
        }

    if (0 == strcmp(ns->ns_name, HB_NS_DEFAULT_NAME))
        {
        client = ns->client;
        if (!client)
            {
            PRINT_ERR("Null client for ns %p (%s)\n", ns, ns->ns_name);
            return;
            }
        init_message_header(&message, client, hbm_nova_cmd);
        strncpy(message.body.nova_cmd_body.nova_cmd, cmd, sizeof(message.body.nova_cmd_body.nova_cmd));
        hb_client_write(client, &message, sizeof(message));
        }
    else
        {
        client = server_ns.client;
        if (!client)
            {
            PRINT_ERR("Null client for ns %p (%s)\n", ns, ns->ns_name);
            return;
            }
        init_pipe_message(&message, hbm_nova_cmd);
        strncpy(message.body.nova_cmd_body.nova_cmd, cmd, sizeof(message.body.nova_cmd_body.nova_cmd));
        hb_write(server_ns.pipe_fd[WRITE_PIPE], &message, sizeof(message));
        }

    }

void issue_nova_cmd(const char* cmd, ns_data_t *ns)
    {
    if (((hb_role == hbr_control) || (hb_role == hbr_compute)) && (0 == strcmp(ns->ns_name, HB_NS_DEFAULT_NAME)))
        {
        PRINT_INFO("Running command: %s\n", cmd);
        nova_cmd_issue(cmd, hb_system);
        }
    else
        send_nova_cmd(cmd, ns);
    }

void handle_nova_cmd(ns_data_t           *ns,
                     heartbeat_message_t *message)
    {
    issue_nova_cmd(message->body.nova_cmd_body.nova_cmd, ns);
    }



#define NOVA_TIMEOUT_SECS_MAX 3600

void set_instance_timeout(nova_timer_t tmr, int timeout_secs, int timeout_nsecs, char *instance_id)
    {
    int timeout_ms;
    int rc;

    timeout_ms = timeout_secs*1000 + timeout_nsecs/1000000;
    if ((timeout_ms >= 0) && (timeout_secs <= NOVA_TIMEOUT_SECS_MAX))
        {
        rc = nova_set_timeout(instance_id, tmr, timeout_ms);

        PRINT_DEBUG("set %s timeout for %s to %d ms", get_nova_timer_name(tmr), instance_id, timeout_ms);
        if (rc < 0)
            PRINT_ERR("failed to set %s timeout for %s", get_nova_timer_name(tmr), instance_id);
        }
    else
        PRINT_ERR("%s timeout out of bounds %d.%09d for %s", get_nova_timer_name(tmr), timeout_secs, timeout_nsecs, instance_id);
    }


void* set_timeouts_helper(void* arg)
    {
    heartbeat_message_t *message = arg;
    char *instance_id;
    
    PRINT_DEBUG("set_timeouts_helper\n");
    instance_id = message->body.timeouts_body.instance_id;

    set_instance_timeout(nt_first_hb, ntohl(message->body.timeouts_body.first_hb_secs),
                         ntohl(message->body.timeouts_body.first_hb_nsecs), instance_id);
    set_instance_timeout(nt_hb_interval, ntohl(message->body.timeouts_body.hb_interval_secs),
                         ntohl(message->body.timeouts_body.hb_interval_nsecs), instance_id);
    set_instance_timeout(nt_vote, ntohl(message->body.timeouts_body.vote_secs),
                         ntohl(message->body.timeouts_body.vote_nsecs), instance_id);
    set_instance_timeout(nt_shutdown_notice, ntohl(message->body.timeouts_body.shutdown_notice_secs),
                         ntohl(message->body.timeouts_body.shutdown_notice_nsecs), instance_id);
    set_instance_timeout(nt_suspend_notice, ntohl(message->body.timeouts_body.suspend_notice_secs),
                         ntohl(message->body.timeouts_body.suspend_notice_nsecs), instance_id);
    set_instance_timeout(nt_resume_notice, ntohl(message->body.timeouts_body.resume_notice_secs),
                         ntohl(message->body.timeouts_body.resume_notice_nsecs), instance_id);
    set_instance_timeout(nt_downscale_notice, ntohl(message->body.timeouts_body.downscale_notice_secs),
                         ntohl(message->body.timeouts_body.downscale_notice_nsecs), instance_id);
    set_instance_timeout(nt_restart, ntohl(message->body.timeouts_body.restart_secs),
                         ntohl(message->body.timeouts_body.restart_nsecs), instance_id);

    PRINT_DEBUG("free %p\n", message);
    free(message);
    return NULL;
    }

void handle_timeouts_event(ns_data_t           *ns, 
                          heartbeat_message_t *message)
    {
    hb_role_t src_role;
    heartbeat_message_t *message2;
    pthread_attr_t attr;
    pthread_t thread;
    int rc;

    PRINT_DEBUG("handle_timeouts_event\n");
    if (!((hb_role == hbr_control) || (hb_role == hbr_compute)))
        {
        PRINT_ERR("Recieved hbm_timeouts message when role is '%s'\n", hb_get_role_name(hb_role));
        return;
        }

    src_role = ntohs(message->body.timeouts_body.role);
    if (src_role != hbr_vm)
        {
        PRINT_ERR("Recieved hbm_timeouts message from entity reporting it's role as '%s'\n", hb_get_role_name(src_role));
        return;
        }

    if (strcmp(ns->ns_name, HB_NS_DEFAULT_NAME))
        {
        /* Forward to default namespace */
        hb_write(server_ns.pipe_fd[WRITE_PIPE], message, sizeof(*message));
        return;
        }

    message2 = (heartbeat_message_t*)malloc(sizeof(*message2));
    PRINT_DEBUG("malloc %p\n", message2);
    if (!message2)
        {
        PRINT_ERR("Failed to set timeouts for %s: malloc failure", message->body.timeouts_body.name);
        return;
        }
    
    *message2 = *message;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    rc = pthread_create(&thread, &attr, set_timeouts_helper, message2);
    if (rc < 0)
        {
        PRINT_ERR("Failed to set timeouts for %s: ptread_create: %s\n", message->body.timeouts_body.name, strerror(errno));
        PRINT_DEBUG("free %p\n", message2);
        free(message2);
        }
    pthread_attr_destroy(&attr);
    return;
    }


typedef struct
    {
    hb_server_client_t *scp;
    char                target[32];
    } set_instance_id_via_proxy_t;

void* set_instance_id_from_addr_via_proxy_helper(void* arg)
    {
    set_instance_id_via_proxy_t *data = arg;
    char* instance_id;
   
    setns(server_ns.ns_fd, CLONE_NEWNET);
    instance_id = nova_find_id_from_ip_addr(data->target);
    if (instance_id)
        {
        strncpy(data->scp->instance_id, instance_id, sizeof(data->scp->instance_id));
        free(instance_id);
        }
    else
        {
        PRINT_ERR("Failed to lookup instance_id for %s: nova\n", data->target);
        }

    PRINT_DEBUG("free %p\n", data);
    free(data);
    return NULL;
    }

void* set_instance_id_from_instance_name_via_proxy_helper(void* arg)
    {
    set_instance_id_via_proxy_t *data = arg;
    char* instance_id;

    setns(server_ns.ns_fd, CLONE_NEWNET);
    instance_id = nova_find_id_from_instance_name(data->target);
    if (instance_id)
        {
        strncpy(data->scp->instance_id, instance_id, sizeof(data->scp->instance_id));
        free(instance_id);
        }
    else
        {
        PRINT_ERR("Failed to lookup instance_id for %s: nova\n", data->target);
        }

    PRINT_DEBUG("free %p\n", data);
    free(data);
    return NULL;
    }


void set_instance_id_from_instance_name_via_proxy(hb_server_client_t *scp, const char* inst_name)
    {
    set_instance_id_via_proxy_t *data;
    pthread_attr_t attr;
    pthread_t thread;
    int rc;

    data = (set_instance_id_via_proxy_t*)malloc(sizeof(set_instance_id_via_proxy_t));
    PRINT_DEBUG("malloc %p\n", data);
    if (!data)
        {
        PRINT_ERR("Failed to lookup instance_id for %s, malloc: %s\n", inst_name, strerror(errno));
        }
    strncpy(data->target, inst_name, sizeof(data->target));
    data->scp = scp;
    
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    rc = pthread_create(&thread, &attr, set_instance_id_from_instance_name_via_proxy_helper, data);
    if (rc < 0)
        {
        PRINT_ERR("Failed to lookup instance_id for %s: pthread_create: %s\n", inst_name, strerror(errno));
        PRINT_DEBUG("free %p\n", data);
        free(data);
        }
    pthread_attr_destroy(&attr);
    }

void set_instance_id_from_addr_via_proxy(hb_server_client_t *scp, const char* remote_addr_str)
    {
    set_instance_id_via_proxy_t *data;
    pthread_attr_t attr;
    pthread_t thread;
    int rc;

    data = (set_instance_id_via_proxy_t*)malloc(sizeof(set_instance_id_via_proxy_t));
    PRINT_DEBUG("malloc %p\n", data);
    if (!data)
        {
        PRINT_ERR("Failed to lookup instance_id for %s, malloc: %s\n", remote_addr_str, strerror(errno));
        }
    strncpy(data->target, remote_addr_str, sizeof(data->target));
    data->scp = scp;
    
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    rc = pthread_create(&thread, &attr, set_instance_id_from_addr_via_proxy_helper, data);
    if (rc < 0)
        {
        PRINT_ERR("Failed to lookup instance_id for %s: pthread_create: %s\n", remote_addr_str, strerror(errno));
        PRINT_DEBUG("free %p\n", data);
        free(data);
        }
    pthread_attr_destroy(&attr);
    }

    

void* discover_namespaces_thread(void* arg)
    {
    arg=arg;

    while(1)
        {
        sleep(30);
        discover_namespaces();
        }

    return NULL;
    }

void discover_namespaces_thread_start()
    {
    pthread_t thread;
    pthread_attr_t attr;

    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    pthread_create(&thread, &attr, discover_namespaces_thread, NULL);
    pthread_attr_destroy(&attr);
    }

void* discover_vio_thread(void* arg)
    {
    arg=arg;

    while(1)
        {
        sleep(5);
        vio_scan(&server_ns);
        }

    return NULL;
    }

void discover_vio_thread_start()
    {
    pthread_t thread;
    pthread_attr_t attr;

    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    pthread_create(&thread, &attr, discover_vio_thread, NULL);
    pthread_attr_destroy(&attr);
    }



void set_msg_canonical_instance_id(heartbeat_message_t *message)
    {
    char* tmp_instance_id = NULL;

    PRINT_DEBUG("in %d %s", ntohs(message->body.shutdown_request_body.inst_id_type), message->body.shutdown_request_body.instance_id);
    switch(ntohs(message->body.shutdown_request_body.inst_id_type))
        {
        case hii_inst_id:
            // Already in prefered form
            break;
        case hii_inst_name:
            tmp_instance_id = nova_find_id_from_instance_name(message->body.shutdown_request_body.instance_id);
            if (tmp_instance_id)
                {
                strncpy(message->body.shutdown_request_body.instance_id, tmp_instance_id, sizeof(message->body.shutdown_request_body.instance_id));
                message->body.shutdown_request_body.inst_id_type = htons(hii_inst_id);
                free(tmp_instance_id);
                }
            break;
        case hii_name:
            tmp_instance_id = nova_find_id_from_name(message->body.shutdown_request_body.instance_id);
            if (tmp_instance_id)
                {
                strncpy(message->body.shutdown_request_body.instance_id, tmp_instance_id, sizeof(message->body.shutdown_request_body.instance_id));
                message->body.shutdown_request_body.inst_id_type = htons(hii_inst_id);
                free(tmp_instance_id);
                }
            break;
        default:
            PRINT_ERR("Unknown inst_id_type %d", ntohs(message->body.shutdown_request_body.inst_id_type));
            break;
        }
    PRINT_DEBUG("out %d %s", ntohs(message->body.shutdown_request_body.inst_id_type), message->body.shutdown_request_body.instance_id);
    }

void set_msg_host_info(heartbeat_message_t *message)
    {
    char* dhcp_host = NULL;
    char* vm_host = NULL;

    if ((message->body.shutdown_request_body.vm_hostname[0] == '\0')
         || (message->body.shutdown_request_body.network_hostname[0] == '\0'))
        {
        set_msg_canonical_instance_id(message);
        }
        
    if (message->body.shutdown_request_body.vm_hostname[0] == '\0')
        {
 
        vm_host = nova_find_vm_host_from_id(message->body.shutdown_request_body.instance_id);
        PRINT_INFO("vm_host=%s\n", vm_host);
        if (vm_host)
            {
            strncpy(message->body.shutdown_request_body.vm_hostname,
                    vm_host,
                    sizeof(message->body.shutdown_request_body.vm_hostname));
            free(vm_host);
            }
        }

    if (message->body.shutdown_request_body.network_hostname[0] == '\0')
        {
        dhcp_host = nova_find_dhcp_host_from_id(message->body.shutdown_request_body.instance_id);
        PRINT_INFO("dhcp_host=%s\n", dhcp_host);
        if (dhcp_host)
            {
            strncpy(message->body.shutdown_request_body.network_hostname,
                    dhcp_host,
                    sizeof(message->body.shutdown_request_body.network_hostname));
            free(dhcp_host);
            }
        }
    }


void hb_handle_hbca_instance_reboot(hb_server_client_t *scp)
    {
    char command[64+HB_INSTANCE_ID_SIZE+2*HB_NAME_SIZE+HB_LOG_MSG_SIZE+HB_SCRIPT_SIZE];

    snprintf(command, sizeof(command), "nova reboot --soft %s &", scp->instance_id);
    PRINT_INFO("corrective action being taken against '%s': %s\n", scp->name, command);
    issue_nova_cmd(command, scp->ns);
    }

void hb_handle_hbca_instance_stop(hb_server_client_t *scp)
    {
    char command[64+HB_INSTANCE_ID_SIZE+2*HB_NAME_SIZE+HB_LOG_MSG_SIZE+HB_SCRIPT_SIZE];

    snprintf(command, sizeof(command), "nova stop --soft %s &", scp->instance_id);
    PRINT_INFO("corrective action being taken against '%s': %s\n", scp->name, command);
    issue_nova_cmd(command, scp->ns);
    }

void hb_handle_hbca_instance_delete(hb_server_client_t *scp)
    {
    char command[64+HB_INSTANCE_ID_SIZE+2*HB_NAME_SIZE+HB_LOG_MSG_SIZE+HB_SCRIPT_SIZE];

    snprintf(command, sizeof(command), "nova delete %s &", scp->instance_id);
    PRINT_INFO("corrective action being taken against '%s': %s\n", scp->name, command);
    issue_nova_cmd(command, scp->ns);
    }

void hb_handle_hbm_nova_cmd(ns_data_t *ns, heartbeat_message_t *message, hb_fd_type_t fdt)
    {
    if (fdt == hbft_ns_pipe)
        {
        if (0 == strcmp(ns->ns_name, HB_NS_DEFAULT_NAME))
            {
            PRINT_INFO("hbm_nova_cmd message recieved by pipe '%s'\n", ns->ns_name);
            handle_nova_cmd(ns, message);
            }
        else
            {
            PRINT_ERR("hbm_nova_cmd message recieved by pipe '%s'\n", ns->ns_name);
            }
        }
    else
        {
        PRINT_ERR("hbm_nova_cmd message recieved by pipe '%s'\n", ns->ns_name);
        }
    }

void hb_handle_hbm_timeouts(ns_data_t *ns, heartbeat_message_t *message)
    {
    PRINT_INFO("hbm_timeouts message recieved by pipe '%s'\n", ns->ns_name);
    handle_timeouts_event(ns, message);
    }

typedef struct
    {
    const char* instance_id;
    ns_data_t* ns;
    } find_ns_from_instance_id_t;

ns_traverse_func_return_t find_ns_from_instance_id_helper(ns_data_t *ns, void *arg)
    {
    find_ns_from_instance_id_t *data = arg;
    hb_server_client_t *scp;

    scp = find_server_client_from_instance_id(ns, data->instance_id);
    if (scp)
        {
        data->ns = ns;
        return ns_traverse_stop;
        }

    return ns_traverse_continue;
    }

ns_data_t* find_ns_from_instance_id(const char* instance_id)
    {
    ns_traverse_return_t trc;
    find_ns_from_instance_id_t data;

    if (!instance_id)
        return NULL;
    data.instance_id = instance_id;
    data.ns = NULL;
    trc = ns_traverse(find_ns_from_instance_id_helper, &data);
    return ((trc == ns_traverse_stopped) ? data.ns : NULL);
    }


int handle_shutdown_request_proxied_control(ns_data_t           *ns,
                                            heartbeat_message_t *message,
                                            hb_server_client_t  *scp,
                                            int                  reply_sock,
                                            heartbeat_message_t *response
                                            )
    {
    hb_server_client_t  *dest_scp;
    int response_ready = 0;
    heartbeat_event_t            event_type;
    heartbeat_delayed_message_t *delayed;
    long secs;
    long nsecs;

    event_type = ntohs(message->body.shutdown_request_body.event_type);

    set_msg_host_info(message);
    PRINT_INFO("for instance_id '%s', vm_hostname '%s', network_hostname '%s'\n", 
               message->body.shutdown_request_body.instance_id,
               message->body.shutdown_request_body.vm_hostname,
               message->body.shutdown_request_body.network_hostname);
    dest_scp = find_server_client_from_hostname(ns, message->body.shutdown_request_body.vm_hostname);
    PRINT_INFO("%p = find_server_client_from_hostname(%s, %s)\n", dest_scp, ns->ns_name, message->body.shutdown_request_body.vm_hostname);
    if (!dest_scp)
        {
        dest_scp = find_server_client_from_hostname(ns, message->body.shutdown_request_body.network_hostname);
        PRINT_INFO("%p = find_server_client_from_hostname(%s, %s)\n", dest_scp, ns->ns_name, message->body.shutdown_request_body.network_hostname);
        if (!dest_scp)
            {
            response->body.shutdown_response_body.event_vote = htons((uint16_t)hbev_not_found_error);
            snprintf(response->body.shutdown_response_body.err_msg, 
                     sizeof(response->body.shutdown_response_body.err_msg),
                     "Heartbeat server couldn't locate recipient '%s'", 
                     message->body.shutdown_request_body.instance_id);

            response_ready = 1;
            return response_ready;
            }
        }
   
    if (dest_scp->delayed_response != NULL)
        {
        PRINT_ERR("Busy, can't handle shutdown_request at this time\n");
        response->body.shutdown_response_body.event_vote = htons((uint16_t)hbev_busy_error);
        snprintf(response->body.shutdown_response_body.err_msg, 
                 sizeof(response->body.shutdown_response_body.err_msg),
                 "Heartbeat server is busy and can't handle a '%s' request at this time", 
                 hb_get_event_name(event_type));
        response_ready = 1;
        return response_ready;
        }

    delayed = (heartbeat_delayed_message_t*)malloc(sizeof(heartbeat_delayed_message_t));
    PRINT_DEBUG("malloc delayed %p\n", delayed);
    memset(delayed, 0, sizeof(*delayed));
    delayed->sock = reply_sock;
    delayed->outstanding = 1;
    delayed->ns = ns;
    delayed->scp = dest_scp;
    delayed->reply_scp = scp;
    delayed->for_me = 0;
    delayed->for_my_client = 0;
    delayed->need_client_state_cleanup = 0;
    delayed->vote = hbev_waiting;
    delayed->notification_type = ntohs(message->body.shutdown_request_body.notification_type);
    delayed->event_type = ntohs(message->body.shutdown_request_body.event_type);
    
    memcpy(&(delayed->response), response, sizeof(delayed->response));
    dest_scp->delayed_response = delayed;
    PRINT_DEBUG("set delayed=%p for server_client=%p\n", delayed, dest_scp); 

    dest_scp->heartbeat_challenge = rand();
    message->header.heartbeat_id = htonl(dest_scp->heartbeat_id);
    message->body.shutdown_request_body.heartbeat_challenge = htonl(dest_scp->heartbeat_challenge);

    secs = ntohl(message->body.shutdown_request_body.timeout_secs);
    nsecs = ntohl(message->body.shutdown_request_body.timeout_nsecs);
    hb_fix_shutdown_to(dest_scp, NULL, 
                       ntohs(message->body.shutdown_request_body.event_type), 
                       ntohs(message->body.shutdown_request_body.notification_type), 
                       &secs, &nsecs);
    hb_set_first_timeout_scp(dest_scp, secs, nsecs);
    if ((dest_scp->state != hbs_server_nova_paused) && (dest_scp->state != hbs_server_migrating))
        {
        dest_scp->save_state = dest_scp->state;
        PRINT_DEBUG("saving state %d (%s)\n", dest_scp->state, hb_get_state_name(dest_scp->state));
        }

    dest_scp->state = hbs_client_waiting_shutdown_response;
    hb_set_expire_func_scp(dest_scp, expired_waiting_shutdown_response);
    hb_requeue_first_ns_scp(ns, dest_scp);
    hb_sc_write(dest_scp, message, sizeof(*message));

    return response_ready;
    }


int handle_shutdown_request_proxied_compute(ns_data_t           *ns,
                                            heartbeat_message_t *message,
                                            hb_server_client_t  *scp,
                                            int                  reply_sock,
                                            heartbeat_message_t *response
                                            )
    {
    hb_server_client_t          *dest_scp;
    ns_data_t                   *dest_ns;
    char*                        ns_name;
    char*                        network_id;
    int response_ready = 0;
    heartbeat_event_t            event_type;
    heartbeat_delayed_message_t *delayed;
    long secs;
    long nsecs;

    event_type = ntohs(message->body.shutdown_request_body.event_type);

    network_id = NULL;
    ns_name = NULL;
    dest_ns = NULL;
   
    dest_scp = find_scp_from_abstract_name(ntohs(message->body.shutdown_request_body.inst_id_type), message->body.shutdown_request_body.instance_id);
    if (dest_scp)
        {
        dest_ns = dest_scp->ns;
        ns_name = (char*)dest_ns->ns_name;
        }
    else
        {
        set_msg_canonical_instance_id(message);

        set_msg_host_info(message);
        PRINT_INFO("for instance_id '%s', vm_hostname '%s', network_hostname '%s'\n", 
                   message->body.shutdown_request_body.instance_id,
                   message->body.shutdown_request_body.vm_hostname,
                   message->body.shutdown_request_body.network_hostname);
        network_id = nova_find_network_id_from_instance_id(message->body.shutdown_request_body.instance_id);
        PRINT_INFO("%p = nova_find_network_id_from_instance_id(%p)\n", network_id, message->body.shutdown_request_body.instance_id);
        PRINT_INFO("%p = nova_find_network_id_from_instance_id(%s)\n", network_id, message->body.shutdown_request_body.instance_id);
        PRINT_INFO("%s = nova_find_network_id_from_instance_id(%s)\n", network_id, message->body.shutdown_request_body.instance_id);
        if (network_id)
            ns_name = ns_find_ns_name_from_quantum_network_id(network_id);
        PRINT_INFO("%s = ns_find_ns_name_from_quantum_network_id(%s)\n", ns_name, network_id);
        if (network_id)
           free(network_id);
  
        if (ns_name)
            dest_ns = ns_find_ns_name(ns_name);
        PRINT_INFO("%p (%s) = ns_find_ns_name(%s)\n", dest_ns, dest_ns ? dest_ns->ns_name : "", ns_name);
        if (ns_name)
            free(ns_name);
        if (!dest_ns)
            dest_ns = find_ns_from_instance_id(message->body.shutdown_request_body.instance_id);
        PRINT_INFO("%p (%s) = find_ns_from_instance_id(%s)\n", dest_ns, dest_ns ? dest_ns->ns_name : "", message->body.shutdown_request_body.instance_id);
        if (!dest_ns)
            {
            response->body.shutdown_response_body.event_vote = htons((uint16_t)hbev_not_found_error);
            snprintf(response->body.shutdown_response_body.err_msg, 
                     sizeof(response->body.shutdown_response_body.err_msg),
                     "Heartbeat server couldn't locate recipient '%s'", 
                     message->body.shutdown_request_body.instance_id);
            response_ready = 1;
            return response_ready;
            }

        dest_scp = find_server_client_from_instance_id(dest_ns, message->body.shutdown_request_body.instance_id);
        PRINT_INFO("%p = find_server_client_from_instance_id(%s, %s)\n", dest_scp, dest_ns->ns_name, message->body.shutdown_request_body.instance_id);
        }
 
    PRINT_INFO("scp = %s, dest_scp = %s, ns = %s, dest_ns = %s, instance_id = %s)\n", 
               scp ? scp->name : "???", 
               dest_scp ? dest_scp->name : "???", 
               ns ? ns->ns_name : "???", 
               dest_ns ? dest_ns->ns_name : "???", 
               message->body.shutdown_request_body.instance_id);

    if (!dest_scp || !dest_ns)
        {
        response->body.shutdown_response_body.event_vote = htons((uint16_t)hbev_not_found_error);
        snprintf(response->body.shutdown_response_body.err_msg, 
                 sizeof(response->body.shutdown_response_body.err_msg),
                 "Heartbeat server couldn't locate recipient '%s'", 
                 message->body.shutdown_request_body.instance_id);
        response_ready = 1;
        return response_ready;
        }
    if (ns == dest_ns)
        {
        if (dest_scp->delayed_response != NULL)
            {
            PRINT_ERR("Busy, can't handle shutdown_request at this time\n");
            response->body.shutdown_response_body.event_vote = htons((uint16_t)hbev_busy_error);
            snprintf(response->body.shutdown_response_body.err_msg, 
                     sizeof(response->body.shutdown_response_body.err_msg),
                     "Heartbeat server is busy and can't handle a '%s' request at this time", 
                     hb_get_event_name(event_type));
            response_ready = 1;
            return response_ready;
            }

        delayed = (heartbeat_delayed_message_t*)malloc(sizeof(heartbeat_delayed_message_t));
        PRINT_DEBUG("malloc delayed %p\n", delayed);
        memset(delayed, 0, sizeof(*delayed));
        delayed->sock = reply_sock;
        delayed->outstanding = 1;
        delayed->ns = ns;
        delayed->scp = dest_scp;
        delayed->reply_scp = scp;
        delayed->for_me = 0;
        delayed->for_my_client = 1;
        delayed->need_client_state_cleanup = 0;
        delayed->vote = hbev_waiting;
        delayed->notification_type = ntohs(message->body.shutdown_request_body.notification_type);
        delayed->event_type = ntohs(message->body.shutdown_request_body.event_type);
        memcpy(&(delayed->response), response, sizeof(delayed->response));
        dest_scp->delayed_response = delayed;
        PRINT_DEBUG("set delayed=%p for server_client=%p (%s)\n", delayed, dest_scp, dest_scp->name); 

        dest_scp->heartbeat_challenge = rand();
        message->header.heartbeat_id = htonl(dest_scp->heartbeat_id);
        message->body.shutdown_request_body.heartbeat_challenge = htonl(dest_scp->heartbeat_challenge);

        secs = ntohl(message->body.shutdown_request_body.timeout_secs);
        nsecs = ntohl(message->body.shutdown_request_body.timeout_nsecs);
        hb_fix_shutdown_to(dest_scp, NULL, 
                           ntohs(message->body.shutdown_request_body.event_type), 
                           ntohs(message->body.shutdown_request_body.notification_type), 
                           &secs, &nsecs);
        hb_set_first_timeout_scp(dest_scp, secs, nsecs);
        if ((dest_scp->state != hbs_server_nova_paused) && (dest_scp->state != hbs_server_migrating))
            {
            dest_scp->save_state = dest_scp->state;
            PRINT_DEBUG("saving state %d (%s)\n", dest_scp->state, hb_get_state_name(dest_scp->state));
            dest_scp->state = hbs_client_waiting_shutdown_response;
            hb_set_expire_func_scp(dest_scp, expired_waiting_shutdown_response);
            hb_requeue_first_ns_scp(ns, dest_scp);
            }
        else
            {
            dest_scp->state = hbs_client_waiting_shutdown_response;
            hb_set_expire_func_scp(dest_scp, expired_waiting_shutdown_response);
            if (ac_alarm_on_queue(&(dest_scp->alarm)))
                hb_requeue_first_ns_scp(ns, dest_scp);
            else
                hb_enqueue_first_ns_scp(ns, dest_scp);
            }

        hb_sc_write(dest_scp, message, sizeof(*message));
        }
    else
        {
        PRINT_DEBUG("Forward to namespace %s from namespace %s\n", dest_ns->ns_name, ns->ns_name);
        if (dest_ns->delayed_response != NULL)
            {
            PRINT_ERR("Busy, can't handle shutdown_request at this time\n");
            response->body.shutdown_response_body.event_vote = htons((uint16_t)hbev_busy_error);
            snprintf(response->body.shutdown_response_body.err_msg, 
                     sizeof(response->body.shutdown_response_body.err_msg),
                     "Heartbeat server is busy and can't handle a '%s' request at this time", 
                     hb_get_event_name(event_type));
            response_ready = 1;
            return response_ready;
            }

        delayed = (heartbeat_delayed_message_t*)malloc(sizeof(heartbeat_delayed_message_t));
        PRINT_DEBUG("malloc delayed %p\n", delayed);
        memset(delayed, 0, sizeof(*delayed));
        delayed->sock = reply_sock;
        delayed->outstanding = 1;
        delayed->ns = ns;
        delayed->scp = NULL;
        delayed->reply_scp = scp;
        delayed->for_me = 0;
        delayed->for_my_client = 0;
        delayed->need_client_state_cleanup = 0;
        delayed->vote = hbev_waiting;
        delayed->notification_type = ntohs(message->body.shutdown_request_body.notification_type);
        delayed->event_type = ntohs(message->body.shutdown_request_body.event_type);
        memcpy(&(delayed->response), response, sizeof(delayed->response));
        ns->delayed_response = delayed;
        PRINT_DEBUG("set delayed=%p for ns=%p (%s)\n", delayed, dest_ns, dest_ns->ns_name); 

        hb_write(dest_ns->pipe_fd[WRITE_PIPE], message, sizeof(*message));
        }

    return response_ready;
    }

void hb_early_init()
    {
    init_trap_handler();
    }

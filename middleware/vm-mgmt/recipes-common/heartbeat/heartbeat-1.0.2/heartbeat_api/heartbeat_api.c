/*
* Copyright (c) 2013-2014 Wind River Systems, Inc.
*
* SPDX-License-Identifier: Apache-2.0
*
*/

/**
*/
#include "heartbeat_macro.h"
#include "heartbeat_common.h"
#include "heartbeat_message.h"
#include "heartbeat_types.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <resolv.h>
#include <time.h>
#include <stdarg.h>
#include <limits.h>
#include <stdbool.h>
#include <netdb.h>
#include <poll.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

hb_client_t client;
ns_data_t   client_ns;

char hb_default_addr[] = "127.0.0.1";
int hb_default_port = HB_DEFAULT_CLIENT_PORT;

int default_corrective_var = 0;
char default_corrective_script[] = "";
char default_corrective_action_str[] = "log";

int hb_discard_message();

int hb_init_client(char *name, 
                   char *instance_id, 
                   char *instance_name, 
                   int   first,
                   int   interval,
                   int   vote_ms,
                   int   shutdown_ms,
                   int   suspend_ms,
                   int   resume_ms,
                   int   downscale_ms,
                   int   restart_ms);

void hb_suspend(int timeout);

int hb_set_server_addr(const char* addr);

int hb_set_server_hostname(const char* hostname);

int hb_set_server_port(int port);

void hb_set_health_check(heartbeat_health_t  (*health_check_func)(void *health_check_arg,
                                                                  char *err_msg_buff,
                                                                  int   err_msg_buff_size),
                         void  *health_check_arg);

void hb_set_event_handler(heartbeat_event_vote_t (*event_handler_func)(heartbeat_event_t         event_type,
                                                                       heartbeat_notification_t  notification_type,
                                                                       void                     *event_handler_arg,
                                                                       char                     *err_msg_buff,
                                                                       int                       err_msg_buff_size),
                          void *event_handler_arg);

int hb_set_corrective_action(int                            idx, 
                             heartbeat_corrective_action_t  corrective_action,
                             int                            corrective_var,
                             const char                    *script);


int hb_discard_message()
    {
    int rc;
    heartbeat_message_t message;

    PRINT_DEBUG("hb_discard_message\n");
    rc = read(client.sock, &message, sizeof(message));
    if (rc <= 0)
        {
        /* Connection closed, close this end
           and free up entry in server.connections */
        PRINT_ERR("\nClient Connection lost: FD=%d\n", client.sock);
    
        handle_client_disconnect(&client, 0);
        return HB_RC_IO_ERR;
        }
    
    if (rc < (int)sizeof(message))
        {
        /* Connection closed, close this end
           and free up entry in server.connections */
        PRINT_ERR("\nShort message: FD=%d\n", client.sock);

        /* TODO client side corrective action */
        return HB_RC_MESSAGING_ERR;
        }

    /* message processing*/
    if (strncmp(message.header.magic, HB_MAGIC, sizeof(HB_MAGIC)) != 0)
        {
        PRINT_ERR("\nBad Magic: %c%c%c%c\n", message.header.magic[0], message.header.magic[1], message.header.magic[2], message.header.magic[3]);

        /* TODO corrective action? close socket? ignore for now */
        return HB_RC_MESSAGING_ERR;
        }

    PRINT_MESSAGE("hb_discard_message: recv fd=%d, type=%s, ns=%s\n", client.sock, hb_get_message_type_name(ntohs(message.header.mtype)), client.ns->ns_name);

    return HB_RC_OK;
    }

int hb_handle_message()
    {
    return handle_client_connection(&client);
    }

int hb_get_socket()
    {
    return client.sock;
    }

static
void hb_init_default()
    {
    int rc;

    PRINT_INFO("hb_init_default\n");
    memset(&client, 0, sizeof(client));
    client.ns = &client_ns;
    client.sock = -1;
    client.port = hb_default_port;
    rc = hb_set_server_addr(hb_default_addr);
    if (rc != HB_RC_OK)
        PRINT_ERR("hb_set_server_addr failed with rc = %d\n", rc);
    strncpy(client.name, "heartbeat_api", sizeof(client.name));
    client.corrective_action = corrective_action_str_to_idx(default_corrective_action_str);
    client.corrective_action_var = default_corrective_var;
    strncpy(client.corrective_action_script, default_corrective_script, sizeof(client.corrective_action_script));
    client.health_check_func = NULL;
    client.health_check_arg = NULL;
    client.event_handler_func = NULL;
    client.event_handler_arg = NULL;
    }

int hb_set_server_hostname(const char* hostname)
    {
    struct hostent *my_hostent;
    struct in_addr *my_in_addr;
    char *my_addr_str;

    PRINT_INFO("hb_set_server_hostname: %s\n", hostname);
    if (hostname == NULL)
        return HB_RC_INVALID_ARG;

    if (strlen(hostname) >= sizeof(client.remote_hostname)-1)
        return HB_RC_OVERFLOW;

    if (client.sock >= 0)
        return HB_RC_ALREADY_CONNECTED;

    my_hostent = gethostbyname(hostname);
    if (!my_hostent)
        return HB_RC_INVALID_ARG;

    my_in_addr = (struct in_addr*) my_hostent->h_addr_list[0];
    if (my_in_addr->s_addr == INADDR_NONE)
        return HB_RC_INVALID_ARG;

    my_addr_str = inet_ntoa( *my_in_addr );

    client.address.sin_addr.s_addr = my_in_addr->s_addr;

    strncpy(client.remote_addr, my_addr_str, sizeof(client.remote_addr));
    strncpy(client.remote_hostname, hostname, sizeof(client.remote_hostname));
    PRINT_INFO("hb_set_server_hostname: my_in_addr=%x, remote_addr=%s, remote_hostname=%s\n", my_in_addr->s_addr, client.remote_addr, client.remote_hostname);
    return HB_RC_OK;
    }

int hb_set_server_addr(const char* addr)
    {
    struct hostent *my_hostent;
    in_addr_t my_in_addr;

    PRINT_INFO("hb_set_server_addr: %s\n", addr);
    if (addr == NULL)
        return HB_RC_INVALID_ARG;

    if (strlen(addr) >= sizeof(client.remote_addr)-1)
        return HB_RC_OVERFLOW;

    if (client.sock >= 0)
        return HB_RC_ALREADY_CONNECTED;

    my_in_addr = inet_addr(addr);
    if (my_in_addr == INADDR_NONE)
        return HB_RC_INVALID_ARG;

    my_hostent = gethostbyaddr(&my_in_addr, sizeof(in_addr_t), AF_INET);
    if (!my_hostent)
        return HB_RC_INVALID_ARG;

    client.address.sin_addr.s_addr = my_in_addr;
    strncpy(client.remote_addr, addr, sizeof(client.remote_addr));
    strncpy(client.remote_hostname, my_hostent->h_name, sizeof(client.remote_hostname));
    PRINT_INFO("hb_set_server_addr: my_in_addr=%x, remote_addr=%s, remote_hostname=%s\n", my_in_addr, client.remote_addr, client.remote_hostname);
    return HB_RC_OK;
    }

int hb_set_server_port(int port)
    {
    if ((port <= 0) || (port > USHRT_MAX))
        return HB_RC_INVALID_ARG;

    if (client.sock >= 0)
        return HB_RC_ALREADY_CONNECTED;

    client.port = port;
    return HB_RC_OK;
    }

void hb_set_health_check(heartbeat_health_t  (*health_check_func)(void *health_check_arg,
                                                                  char *err_msg_buff,
                                                                  int   err_msg_buff_size),
                         void  *health_check_arg)
    {
    client.health_check_func = health_check_func;
    client.health_check_arg = health_check_arg;
    }

void hb_set_event_handler(heartbeat_event_vote_t (*event_handler_func)(heartbeat_event_t         event_type,
                                                                       heartbeat_notification_t  notification_type,
                                                                       void                     *event_handler_arg,
                                                                       char                     *err_msg_buff,
                                                                       int                       err_msg_buff_size),
                          void  *event_handler_arg)
    {
    client.event_handler_func = event_handler_func;
    client.event_handler_arg = event_handler_arg;
    }

int hb_set_corrective_action(int                            idx, 
                             heartbeat_corrective_action_t  corrective_action,
                             int                            corrective_var,
                             const char                    *script)
    {
    if ((idx < 0) || (idx >= HB_MAX_ACTIONS))
        return HB_RC_INVALID_ARG;

    if (corrective_action >= hbca_corrective_action_max)
        return HB_RC_INVALID_ARG;

    if (corrective_action == hbca_script)
        {
        if (script == NULL)
            return HB_RC_INVALID_ARG;

        if (strlen(script) >= sizeof(client.corrective_action_script)-1)
            return HB_RC_OVERFLOW;
        }
    else
        {
        if (script != NULL)
            return HB_RC_INVALID_ARG;
        }

    if (client.sock >= 0)
        return HB_RC_ALREADY_CONNECTED;

    client.corrective_action = corrective_action;
    client.corrective_action_var = corrective_var;
    if (corrective_action == hbca_script)
        strncpy(client.corrective_action_script, script, sizeof(client.corrective_action_script));
    else
        strncpy(client.corrective_action_script, default_corrective_script, sizeof(client.corrective_action_script));
    return HB_RC_OK;
    }


static
int hb_wait_response(const char      *who,
                     struct timespec  timeout,
                     hb_state_t       expected_state,
                     hb_state_t       wait_state)
    {
    int num_socks;  /* Number of sockets ready for reading */
    int highsock = 0;
    fd_set ready_read_socks;

   retry:
    highsock = client.sock;
    FD_ZERO(&ready_read_socks);
    FD_SET(client.sock, &ready_read_socks);

    num_socks = pselect(highsock+1,
                        &ready_read_socks,
                        (fd_set *) 0,
                        (fd_set *) 0,
                        &timeout,
                        NULL);

    if (num_socks < 0)
        {
        if (errno == EINTR)
            goto retry;
        PRINT_ERR("%s failed: pselect: %s", strerror(errno), who);
        return HB_RC_OS_ERR;
        }

    if (num_socks == 0)
        {
        /* Nothing ready to read */
        PRINT_ERR("%s failed: No response from heartbeat server\n", who);
        return HB_RC_TIMEOUT_ERR;
        }
    else
        {
        if (FD_ISSET(client.sock, &ready_read_socks))
            {
            PRINT_INFO("client.state '%s'\n", hb_get_state_name(client.state));
            handle_client_connection(&client);

            if (client.state != expected_state)
                { 
                if (client.state != wait_state)
                    {
                    PRINT_ERR("%s failed: Invalid response from heartbeat server, in state '%s' when expecting '%s'\n",
                              who, hb_get_state_name(client.state), hb_get_state_name(expected_state));
                    return HB_RC_STATE_ERR;
                    }
                goto retry;
                }
            }
        else
            {
            PRINT_ERR("%s failed: No response from heartbeat server\n", who);
            return HB_RC_IO_ERR;
            }
        }

    return HB_RC_OK;
    }

__attribute__((constructor))
static
void hb_api_init()
    {
    client_ns.next = NULL;
    client_ns.ns_name = HB_NS_DEFAULT_NAME;
    client_ns.thread = 0;
    client_ns.ns_fd = -1;
    init_ns(&client_ns, &client);

    hb_init_default();
    }

int hb_init_client(char *name,
                   char *instance_id,
                   char *instance_name,
                   int   first_ms,
                   int   interval_ms,
                   int   vote_ms,
                   int   shutdown_ms,
                   int   suspend_ms,
                   int   resume_ms,
                   int   downscale_ms,
                   int   restart_ms)
    {
    int rc;

    strncpy(client.name, name ? name : "client", sizeof(client.name));
    strncpy(client.instance_id, instance_id ? instance_id : "???", sizeof(client.instance_id));
    strncpy(client.instance_name, instance_name ? instance_name : "???", sizeof(client.instance_name));

    client.first_hb.tv_sec = first_ms/1000;
    client.first_hb.tv_nsec = (first_ms%1000)*1000000;
    client.hb_interval.tv_sec = interval_ms/1000;
    client.hb_interval.tv_nsec = (interval_ms%1000)*1000000;

    client.vote_to.tv_sec = vote_ms/1000;
    client.vote_to.tv_nsec = (vote_ms%1000)*1000000;
    client.shutdown_notice_to.tv_sec = shutdown_ms/1000;
    client.shutdown_notice_to.tv_nsec = (shutdown_ms%1000)*1000000;
    client.suspend_notice_to.tv_sec = suspend_ms/1000;
    client.suspend_notice_to.tv_nsec = (suspend_ms%1000)*1000000;
    client.resume_notice_to.tv_sec = resume_ms/1000;
    client.resume_notice_to.tv_nsec = (resume_ms%1000)*1000000;
    client.downscale_notice_to.tv_sec = downscale_ms/1000;
    client.downscale_notice_to.tv_nsec = (downscale_ms%1000)*1000000;
    client.restart_to.tv_sec = restart_ms/1000;
    client.restart_to.tv_nsec = (restart_ms%1000)*1000000;

    rc = init_client(&client, false);
    if (rc < 0)
       return rc;

    return hb_wait_response("hb_init_client", client.first_hb, hbs_client_waiting_challenge, hbs_client_waiting_init_ack);
    }

int hb_freeze(int timeout_ms)
    {
    heartbeat_message_t message;
    uint32_t            resp;
    int                 rc;

    init_message_header(&message, &client, hbm_pause);

    resp = compute_response(client.heartbeat_algorithm,
                            client.heartbeat_secret,
                            client.heartbeat_challenge);
    message.body.pause_body.heartbeat_response  = htonl(resp);

    message.body.pause_body.pause_secs = htonl(timeout_ms/1000);
    message.body.pause_body.pause_nsecs = htonl((timeout_ms % 1000) * 1000000);

    client.state = hbs_client_waiting_pause_ack;
    rc = hb_client_write(&client, &message, sizeof(message));
    if (rc < 0)
       {
       PRINT_ERR("hb_freeze write: %s", strerror(errno));
       return HB_RC_IO_ERR;
       }

    return hb_wait_response("hb_freeze", client.hb_interval, hbs_client_paused, hbs_client_waiting_pause_ack);
    }

int hb_thaw()
    {
    heartbeat_message_t message;
    uint32_t            resp;
    int                 rc;

    init_message_header(&message, &client, hbm_resume);

    resp = compute_response(client.heartbeat_algorithm,
                            client.heartbeat_secret,
                            client.heartbeat_challenge);
    message.body.resume_body.heartbeat_response = htonl(resp);

    client.state = hbs_client_waiting_resume_ack;

    rc = hb_client_write(&client, &message, sizeof(message));
    if (rc < 0)
       {
       PRINT_ERR("hb_thaw write: %s", strerror(errno));
       return HB_RC_IO_ERR;
       }


    return hb_wait_response("hb_thaw", client.hb_interval, hbs_client_waiting_challenge, hbs_client_waiting_resume_ack);
    }

int hb_exit(const char* log)
    {
    heartbeat_message_t message;
    uint32_t            resp;
    int                 rc;

    init_message_header(&message, &client, hbm_exit);

    resp = compute_response(client.heartbeat_algorithm,
                            client.heartbeat_secret,
                            client.heartbeat_challenge);
    message.body.exit_body.heartbeat_response = htonl(resp);
    strncpy(message.body.exit_body.log_msg, log, sizeof(message.body.exit_body.log_msg));
    client.state = hbs_client_exiting;

    rc = hb_client_write(&client, &message, sizeof(message));
    if (rc < 0)
       {
       PRINT_ERR("hb_shutdown: %s", strerror(errno));
       return HB_RC_IO_ERR;
       }

    printf("%s\n", log);
    return HB_RC_OK;
    }


int hb_shutdown_request(
                        heartbeat_event_t         event_type, 
                        heartbeat_notification_t  notification_type, 
                        const char               *instance_id,
                        const char               *instance_name,
                        const char               *name,
                        int                       timeout_ms)
    {
    heartbeat_message_t message;
    int                 rc;
    struct timespec     timeout;

    if (!instance_id && !instance_name && !name)
       {
       PRINT_ERR("hbm_shutdown_request: Must provide one of instance_id, instance_name, name");
       return HB_RC_INVALID_ARG;
       }
    if ((timeout_ms <= 0) && (timeout_ms != HB_DEFAULT_VM_TIMEOUT_MS))
       {
       PRINT_ERR("hbm_shutdown_request: timeout must be positive");
       return HB_RC_INVALID_ARG;
       }
    if (event_type <= hbet_unknown || event_type >= hbet_max)
       {
       PRINT_ERR("hbm_shutdown_request: invalid event_type %d", event_type);
       return HB_RC_INVALID_ARG;
       }
    if (notification_type <= hbnt_unknown || notification_type >= hbnt_max)
       {
       PRINT_ERR("hbm_shutdown_request: invalid notification_type %d", notification_type);
       return HB_RC_INVALID_ARG;
       }

    init_message_header(&message, &client, hbm_shutdown_request);

    timeout.tv_sec = timeout_ms/1000;
    timeout.tv_nsec = (timeout_ms % 1000) * 1000000;
    message.body.shutdown_request_body.timeout_secs = htonl(timeout.tv_sec);
    message.body.shutdown_request_body.timeout_nsecs = htonl(timeout.tv_nsec);
    message.body.shutdown_request_body.notification_type = htons(notification_type);
    message.body.shutdown_request_body.event_type = htons(event_type);

    if (instance_id)
       {
       strncpy(message.body.shutdown_request_body.instance_id, instance_id, sizeof(message.body.shutdown_request_body.instance_id));
       message.body.shutdown_request_body.inst_id_type = htons(hii_inst_id);
       }
    else if (instance_name)
       {
       strncpy(message.body.shutdown_request_body.instance_id, instance_name, sizeof(message.body.shutdown_request_body.instance_id));
       message.body.shutdown_request_body.inst_id_type = htons(hii_inst_name);
       }
    else if (name)
       {
       strncpy(message.body.shutdown_request_body.instance_id, name, sizeof(message.body.shutdown_request_body.instance_id));
       message.body.shutdown_request_body.inst_id_type = htons(hii_name);
       }
    else
       {
       PRINT_ERR("hbm_shutdown_request: Must provide one of instance_id, instance_name, name");
       return HB_RC_INVALID_ARG;
       }

    message.body.shutdown_request_body.heartbeat_challenge = rand();
    message.body.shutdown_request_body.network_hostname[0] = '\0';
    message.body.shutdown_request_body.vm_hostname[0] = '\0';

    client.state = hbs_client_waiting_shutdown_response;
    rc = hb_client_write(&client, &message, sizeof(message));
    if (rc < 0)
       {
       PRINT_ERR("hbm_shutdown_request write: %s", strerror(errno));
       return HB_RC_IO_ERR;
       }

    return hb_wait_response("hbm_shutdown_request", timeout, hbs_client_shutdown_response_recieved, hbs_client_waiting_shutdown_response);
    }

int hb_ns_notify(const char    *ns_name, 
                 const char    *ns_host_name,
                 hb_ns_event_t  event)
    {
    heartbeat_message_t message;
    int                 rc;

    init_message_header(&message, &client, hbm_network_namespace);

    message.body.network_namespace_body.ns_event = htons(event);
    strncpy(message.body.network_namespace_body.ns_name, ns_name, sizeof(message.body.network_namespace_body.ns_name));

    if (ns_host_name)
        strncpy(message.body.network_namespace_body.network_hostname, ns_host_name, sizeof(message.body.network_namespace_body.network_hostname));
    else
        message.body.network_namespace_body.network_hostname[0]='\0';

    rc = hb_client_write(&client, &message, sizeof(message));
    if (rc < 0)
       {
       PRINT_ERR("hbm_network_namespace write: %s", strerror(errno));
       return HB_RC_IO_ERR;
       }

    return HB_RC_OK;
    }

int hb_ns_create_notify(const char *ns_name, 
                        const char *ns_host_name)
    {
    return hb_ns_notify(ns_name, ns_host_name, hb_ns_create);
    }

int hb_ns_destroy_notify(const char *ns_name,
                         const char *ns_host_name)
    {
    return hb_ns_notify(ns_name, ns_host_name, hb_ns_destroy);
    }

int hb_select(int nfds, fd_set *readfds, fd_set *writefds,
              fd_set *exceptfds, struct timeval *timeout)
    {
    int sock;
    int rc;

    sock = client.sock;
    if (sock < 0)
        {
        errno = EINVAL;
        return -1;
        }

    if (sock >= nfds)
        nfds = sock+1;
  retry:
    FD_SET(sock, readfds);
    rc = select(nfds, readfds, writefds, exceptfds, timeout);
    if ((rc < 0) && (errno == EINTR))
        {
        goto retry;
        }
    if ((rc > 0) && FD_ISSET(sock, readfds))
        {
        hb_handle_message();
        FD_CLR(sock, readfds);
        rc--;
        }
    return rc;
    }

int hb_pselect(int nfds, fd_set *readfds, fd_set *writefds,
               fd_set *exceptfds, const struct timespec *timeout,
               const sigset_t *sigmask)
    {
    int sig;
    int sock;
    int rc;
    sigset_t sm;
    sigset_t *new_sigmask = (sigset_t *)sigmask;

    sock = client.sock;
    if (sock >= nfds)
        nfds = sock+1;

    FD_SET(sock, readfds);

    sig = hb_get_signum();
    if (sigmask && sig)
        {
        sm = *sigmask;
        new_sigmask = &sm;
        sigdelset(new_sigmask, sig);
        }

  retry:
    rc = pselect(nfds, readfds, writefds, exceptfds, timeout, sigmask);
    if ((rc < 0) && (errno == EINTR))
        {
        goto retry;
        }

    if ((rc > 0) && FD_ISSET(sock, readfds))
        {
        hb_handle_message();
        FD_CLR(sock, readfds);
        rc--;
        }

    return rc;
    }

int hb_poll(struct pollfd *fds, nfds_t nfds, int timeout)
    {
    int i;
    int rc;
    int sock;
    struct pollfd *new_fds = NULL;
    int new_nfds = nfds;

    sock = client.sock;
    for(i=0; i<(int)nfds; i++)
        {
        if (fds[i].fd == sock)
            {
            fds[i].events |= POLLIN;
            new_fds = fds;
            break;
            }
        }

    if (!new_fds)
        {
        new_fds = malloc((nfds+1)*sizeof(struct pollfd));
        memcpy(new_fds, fds, nfds*sizeof(struct pollfd));
        i = nfds;
        new_fds[i].fd = sock;
        new_fds[i].events |= POLLIN;
        new_nfds = nfds+1;
        }
    
  retry:
    rc = poll(new_fds, new_nfds, timeout); 
    if ((rc < 0) && (errno == EINTR))
        {
        goto retry;
        }

    if ((rc > 0) && new_fds[i].revents)
        {
        hb_handle_message();
        new_fds[i].revents = 0;
        if (new_fds != fds)
            memcpy(fds, new_fds, nfds*sizeof(struct pollfd));
        }

    return rc;
    }

int hb_ppoll(struct pollfd *fds, nfds_t nfds,
               const struct timespec *timeout_ts, const sigset_t *sigmask)
    {
    int i;
    int rc;
    int sock;
    int sig;
    struct pollfd *new_fds = NULL;
    int new_nfds = nfds;
    sigset_t sm;
    sigset_t *new_sigmask = (sigset_t *)sigmask;
    
    sock = client.sock;
    for(i=0; i<(int)nfds; i++)
        {
        if (fds[i].fd == sock)
            {
            fds[i].events |= POLLIN;
            new_fds = fds;
            break;
            }
        }   
        
    if (!new_fds)
        {
        new_fds = malloc((nfds+1)*sizeof(struct pollfd));
        memcpy(new_fds, fds, nfds*sizeof(struct pollfd));
        i = nfds;
        new_fds[i].fd = sock;
        new_fds[i].events |= POLLIN;
        new_nfds = nfds+1;
        }
        
    sig = hb_get_signum();
    if (sigmask && sig)
        {
        sm = *sigmask;
        new_sigmask = &sm;
        sigdelset(new_sigmask, sig);
        }

  retry:
    rc = ppoll(new_fds, new_nfds, timeout_ts, new_sigmask);
    if ((rc < 0) && (errno == EINTR))
        {
        goto retry;
        }
        
    if ((rc > 0) && new_fds[i].revents)
        {
        hb_handle_message();
        new_fds[i].revents = 0;
        if (new_fds != fds)
            memcpy(fds, new_fds, nfds*sizeof(struct pollfd));
        }   
        
    return rc;
    }
